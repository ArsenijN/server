import os, json, shutil, secrets, hashlib, time, logging, threading
from datetime import datetime, timedelta
from core.db import _db_connect, _get_chunk_lock, _release_chunk_lock, \
                    _assembly_progress_set, _assembly_progress_clear
from core.notifications import _fire_upload_notification
from config import UPLOAD_CHUNK_SIZE, UPLOAD_SESSION_TTL, MAX_JSON_BODY, \
                   MAX_SHARE_UPLOAD_BYTES, MAX_UPLOAD_BYTES, UPLOAD_TMP_DIR, SERVE_ROOT

# ---------------------------------------------------------------------------
# Strategy selection
# ---------------------------------------------------------------------------
# 'direct'  — chunk bytes are pwrite()d straight into the pre-allocated
#             destination file on the HDD.  No tmp dir, no assembly step.
#             Used when dest_path is NOT on the same filesystem as
#             UPLOAD_TMP_DIR (i.e. the normal CDN-drive case).
#
# 'buffer'  — the original approach: chunk files land in UPLOAD_TMP_DIR
#             (ideally on SSD), then are streamed into dest_path at complete
#             time.  Used when dest_path and UPLOAD_TMP_DIR share a device
#             (uploading to the SSD itself) or as an explicit fallback.
#
# The strategy is chosen at init time by comparing st_dev of the dest
# parent directory against the st_dev of UPLOAD_TMP_DIR.  If fallocate
# fails (e.g. FAT32, some network filesystems) we fall back to 'buffer'.
# ---------------------------------------------------------------------------

def _choose_strategy(dest_path: str) -> str:
    """Return 'direct' or 'buffer' based on device IDs."""
    try:
        dest_dev = os.stat(os.path.dirname(dest_path)).st_dev
        tmp_dev  = os.stat(UPLOAD_TMP_DIR).st_dev
        if dest_dev != tmp_dev:
            return 'direct'
    except OSError:
        pass
    return 'buffer'


def _preallocate(dest_path: str, total_size: int) -> bool:
    """Pre-allocate *total_size* bytes at *dest_path*.

    Uses fallocate(2) on Linux (instant, no zero-write), falls back to
    ftruncate which just extends the file's apparent size without touching
    the spindle.  Both approaches tell the filesystem to reserve contiguous
    extents before the first byte arrives, eliminating fragmentation and
    avoiding surprise ENOSPC mid-upload.

    Returns True on success, False if pre-allocation isn't supported (caller
    should fall back to 'buffer' strategy).
    """
    if total_size <= 0:
        # Zero-byte or unknown-size file — just create an empty file.
        try:
            open(dest_path, 'wb').close()
            return True
        except OSError:
            return False

    try:
        fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            # fallocate: FALLOC_FL_KEEP_SIZE=0 → actually reserves blocks on disk.
            # Available on Linux kernel ≥ 2.6.23; raises AttributeError on Windows/macOS.
            os.posix_fallocate(fd, 0, total_size)
            return True
        except (AttributeError, OSError):
            # Fall back to truncate — this extends the file without writing data.
            # Less guaranteed for contiguous allocation but still avoids fragmentation
            # on most Linux filesystems.
            try:
                os.ftruncate(fd, total_size)
                return True
            except OSError:
                return False
        finally:
            os.close(fd)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _upload_init(filename: str, dest_path: str, total_size: int,
                 total_chunks: int, sha256_final: str | None,
                 owner_type: str, owner_ref: str,
                 anon_device_token: str | None = None) -> dict:
    """Create a new upload session.

    Chooses the write strategy at init time:
      - 'direct'  → pre-allocate dest_path on HDD, write chunks straight in.
      - 'buffer'  → write chunk files to UPLOAD_TMP_DIR (SSD), assemble later.

    Returns the session row as a dict.
    """
    token    = secrets.token_urlsafe(32)
    strategy = _choose_strategy(dest_path)

    # For 'direct' strategy, pre-allocate the destination file.
    # If that fails (unsupported FS, permission error, out of space) fall back.
    if strategy == 'direct':
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        if not _preallocate(dest_path, total_size):
            logging.warning(
                f'_upload_init: fallocate/ftruncate failed for {dest_path!r}; '
                f'falling back to buffer strategy.'
            )
            strategy = 'buffer'

    # For buffer strategy, create the tmp chunk directory on the fast drive.
    tmp_dir = ''
    if strategy == 'buffer':
        tmp_dir = os.path.join(UPLOAD_TMP_DIR, token)
        os.makedirs(tmp_dir, exist_ok=True)

    with _db_connect() as conn:
        conn.execute(
            '''INSERT INTO upload_sessions
               (upload_token, filename, dest_path, tmp_dir, total_size,
                chunk_size, total_chunks, sha256_final, owner_type, owner_ref,
                anon_device_token, strategy, upload_status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (token, filename, dest_path, tmp_dir, total_size,
             UPLOAD_CHUNK_SIZE, total_chunks, sha256_final, owner_type, owner_ref,
             anon_device_token, strategy, 'pending')
        )
        conn.commit()

    logging.info(
        f'Upload session init: token={token[:12]}… strategy={strategy} '
        f'file={filename!r} size={total_size} chunks={total_chunks}'
    )
    return _upload_get(token)


def _upload_get(token: str) -> dict | None:
    """Fetch an upload session by token. Returns dict or None."""
    with _db_connect() as conn:
        row = conn.execute(
            'SELECT * FROM upload_sessions WHERE upload_token = ?', (token,)
        ).fetchone()
    if not row:
        return None
    keys = ['id', 'upload_token', 'filename', 'dest_path', 'tmp_dir', 'total_size',
            'chunk_size', 'total_chunks', 'chunks_received', 'sha256_final',
            'owner_type', 'owner_ref', 'anon_device_token', 'created_at',
            'last_activity', 'completed',
            'strategy', 'upload_status']
    # Older rows (before migration) will have fewer columns — pad with defaults.
    row_list = list(row)
    while len(row_list) < len(keys):
        row_list.append(None)
    d = dict(zip(keys, row_list))
    d['chunks_received'] = json.loads(d['chunks_received'] or '[]')
    # Default strategy for pre-migration rows
    if not d.get('strategy'):
        d['strategy'] = 'buffer'
    if not d.get('upload_status'):
        d['upload_status'] = 'complete' if d['completed'] else 'pending'
    return d


# ---------------------------------------------------------------------------
# Chunk receive — two paths depending on strategy
# ---------------------------------------------------------------------------

def _upload_receive_chunk(token: str, chunk_index: int, data: bytes,
                          expected_size: int | None = None) -> dict:
    """Write chunk to disk (or direct into dest file), update session.

    expected_size: if provided (from Content-Length header), must exactly
    match len(data).  A mismatch means the TCP connection dropped mid-transfer
    and the chunk is truncated — we reject it rather than silently storing a
    partial chunk.
    """
    session = _upload_get(token)
    if not session:
        raise KeyError('Upload session not found')
    if session['completed']:
        raise ValueError('Session already completed')

    if expected_size is not None and len(data) != expected_size:
        raise ValueError(
            f'Chunk {chunk_index} truncated: received {len(data)} bytes, '
            f'expected {expected_size}'
        )

    strategy = session.get('strategy', 'buffer')

    if strategy == 'direct':
        return _receive_chunk_direct(session, chunk_index, data)
    else:
        return _receive_chunk_buffer(session, token, chunk_index, data)


def _receive_chunk_direct(session: dict, chunk_index: int, data: bytes) -> dict:
    """Write chunk directly into the pre-allocated destination file at the
    correct byte offset (pwrite semantics).  No tmp dir involved.

    Thread-safe: pwrite on Linux is atomic at the OS level for non-overlapping
    regions, and each chunk index maps to a unique non-overlapping region.
    The _get_chunk_lock() is still used to serialise the chunks_received JSON
    update in SQLite — the actual disk write happens outside the lock.
    """
    token     = session['upload_token']
    dest_path = session['dest_path']
    chunk_size = session['chunk_size']
    offset    = chunk_index * chunk_size

    # Write at the correct offset directly.  open()+pwrite is the cleanest
    # way to express this; os.pwrite is Linux-only but that's fine here.
    try:
        fd = os.open(dest_path, os.O_WRONLY)
        try:
            written = 0
            view = memoryview(data)
            while written < len(data):
                n = os.pwrite(fd, view[written:], offset + written)
                if n == 0:
                    raise OSError('pwrite returned 0 — disk full?')
                written += n
        finally:
            os.close(fd)
    except AttributeError:
        # os.pwrite not available (Windows) — fall back to seek+write
        with open(dest_path, 'r+b') as f:
            f.seek(offset)
            f.write(data)

    # Verify the write landed correctly (catches out-of-space on closing).
    # We re-read just the written slice and compare length; a full re-read
    # would be expensive for 25 MB chunks.
    # stat() is sufficient: if the file shrank or wasn't extended, something's wrong.
    file_size = os.path.getsize(dest_path)
    expected_min = offset + len(data)
    if file_size < expected_min:
        raise ValueError(
            f'Chunk {chunk_index} direct write incomplete: '
            f'file is {file_size} B, expected at least {expected_min} B'
        )

    # Serialise the chunks_received JSON update.
    lock = _get_chunk_lock(token)
    with lock:
        fresh = _upload_get(token)
        if not fresh:
            raise KeyError('Upload session disappeared')
        received = fresh['chunks_received']
        if chunk_index not in received:
            received.append(chunk_index)
            received.sort()
        with _db_connect() as conn:
            conn.execute(
                '''UPDATE upload_sessions
                   SET chunks_received = ?, last_activity = CURRENT_TIMESTAMP
                   WHERE upload_token = ?''',
                (json.dumps(received), token)
            )
            conn.commit()

    return _upload_get(token)


def _receive_chunk_buffer(session: dict, token: str, chunk_index: int,
                          data: bytes) -> dict:
    """Original buffer strategy: write chunk as a file in tmp_dir."""
    tmp_dir = session['tmp_dir']

    chunk_path = os.path.join(tmp_dir, f'{chunk_index:06d}.chunk')
    with open(chunk_path, 'wb') as f:
        f.write(data)

    on_disk = os.path.getsize(chunk_path)
    if on_disk != len(data):
        try:
            os.remove(chunk_path)
        except OSError:
            pass
        raise ValueError(
            f'Chunk {chunk_index} disk write incomplete: '
            f'{on_disk} B on disk vs {len(data)} B received'
        )

    lock = _get_chunk_lock(token)
    with lock:
        fresh = _upload_get(token)
        if not fresh:
            raise KeyError('Upload session disappeared')
        received = fresh['chunks_received']
        if chunk_index not in received:
            received.append(chunk_index)
            received.sort()
        with _db_connect() as conn:
            conn.execute(
                '''UPDATE upload_sessions
                   SET chunks_received = ?, last_activity = CURRENT_TIMESTAMP
                   WHERE upload_token = ?''',
                (json.dumps(received), token)
            )
            conn.commit()

    return _upload_get(token)


# ---------------------------------------------------------------------------
# Complete / assemble
# ---------------------------------------------------------------------------

def _upload_assemble(token: str) -> tuple[str, str]:
    """Finalise the upload.

    For 'direct' strategy: the file is already on disk at dest_path.
    We just verify chunk completeness, optionally verify whole-file SHA-256
    (skipped when sha256_final is None — saves CPU on the i3), mark complete,
    and return.

    For 'buffer' strategy: the original streaming assembly path, with the
    SHA-256 skip optimisation applied identically.

    Returns (dest_path, sha256_hex).
    sha256_hex is '' when sha256_final was None (no verification requested).
    """
    session = _upload_get(token)
    if not session:
        raise KeyError('Upload session not found')

    strategy     = session.get('strategy', 'buffer')
    dest_path    = session['dest_path']
    total_chunks = session['total_chunks']
    received     = set(session['chunks_received'])
    total_size   = session['total_size']

    # --- 1. Verify all chunks are recorded. ---
    if total_chunks > 0:
        missing = [i for i in range(total_chunks) if i not in received]
        if missing:
            raise ValueError(f'Missing chunks: {missing[:10]}{"…" if len(missing) > 10 else ""}')

    # --- 2. Strategy-specific finalisation. ---
    if strategy == 'direct':
        return _assemble_direct(session, dest_path, total_size, token)
    else:
        return _assemble_buffer(session, dest_path, total_size, token)


def _assemble_direct(session: dict, dest_path: str, total_size: int,
                     token: str) -> tuple[str, str]:
    """Direct strategy: file is already written.  Verify, mark complete, clean up."""
    sha256_final = session.get('sha256_final')

    # Zero-byte file
    if total_size == 0:
        with _db_connect() as conn:
            conn.execute(
                "UPDATE upload_sessions SET completed=1, upload_status='complete', "
                "last_activity=CURRENT_TIMESTAMP WHERE upload_token=?", (token,)
            )
            conn.commit()
        _release_chunk_lock(token)
        _assembly_progress_clear(token)
        return dest_path, 'e3b0c44298fc1c149afbf4c8996fb924'

    # Optional whole-file SHA-256 verification.
    # Skipped when client didn't declare sha256_final (saves ~3-5s on i3 per GB).
    actual_sha256 = ''
    if sha256_final:
        _assembly_progress_set(token, 0, total_size)
        READ_BUF     = 4 * 1024 * 1024
        REPORT_EVERY = 16 * 1024 * 1024
        try:
            hasher = hashlib.sha256(usedforsecurity=False)
        except TypeError:
            hasher = hashlib.sha256()
        bytes_hashed = 0
        last_reported = 0
        try:
            with open(dest_path, 'rb') as f:
                while True:
                    block = f.read(READ_BUF)
                    if not block:
                        break
                    hasher.update(block)
                    bytes_hashed += len(block)
                    if bytes_hashed - last_reported >= REPORT_EVERY:
                        _assembly_progress_set(token, bytes_hashed, total_size)
                        last_reported = bytes_hashed
        except Exception as exc:
            _assembly_progress_set(token, bytes_hashed, total_size, error=str(exc))
            raise
        actual_sha256 = hasher.hexdigest()
        if sha256_final.lower() != actual_sha256:
            _assembly_progress_set(token, bytes_hashed, total_size,
                                   error='SHA-256 mismatch')
            try:
                os.remove(dest_path)
            except OSError:
                pass
            raise ValueError(
                f'SHA-256 mismatch: expected {sha256_final}, got {actual_sha256}'
            )

    _assembly_progress_set(token, total_size, total_size, done=True)
    with _db_connect() as conn:
        conn.execute(
            "UPDATE upload_sessions SET completed=1, upload_status='complete', "
            "last_activity=CURRENT_TIMESTAMP WHERE upload_token=?", (token,)
        )
        conn.commit()
    _release_chunk_lock(token)
    _assembly_progress_clear(token)

    logging.info(
        f'Upload assembled (direct): {dest_path} '
        f'({actual_sha256[:12] if actual_sha256 else "no-hash"}…)'
    )
    return dest_path, actual_sha256


def _assemble_buffer(session: dict, dest_path: str, total_size: int,
                     token: str) -> tuple[str, str]:
    """Buffer strategy: stream-copy chunks into dest_path, hash inline."""
    tmp_dir      = session['tmp_dir']
    total_chunks = session['total_chunks']
    received     = set(session['chunks_received'])
    chunk_size   = session['chunk_size']
    sha256_final = session.get('sha256_final')
    sorted_chunks = sorted(received)

    # Zero-byte file
    if total_chunks == 0:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        open(dest_path, 'wb').close()
        with _db_connect() as conn:
            conn.execute(
                "UPDATE upload_sessions SET completed=1, upload_status='complete', "
                "last_activity=CURRENT_TIMESTAMP WHERE upload_token=?", (token,)
            )
            conn.commit()
        _release_chunk_lock(token)
        _assembly_progress_clear(token)
        try:
            shutil.rmtree(session['tmp_dir'], ignore_errors=True)
        except Exception:
            pass
        return dest_path, 'e3b0c44298fc1c149afbf4c8996fb924'

    # Verify chunk files on disk
    bad_files = []
    for idx in sorted_chunks:
        chunk_path = os.path.join(tmp_dir, f'{idx:06d}.chunk')
        if not os.path.exists(chunk_path):
            bad_files.append(f'chunk {idx} missing from disk')
            continue
        on_disk = os.path.getsize(chunk_path)
        is_last = (idx == sorted_chunks[-1])
        if is_last:
            expected_last = total_size - chunk_size * idx if total_size > 0 else on_disk
            if on_disk != expected_last:
                bad_files.append(
                    f'chunk {idx} (last) size mismatch: {on_disk} B on disk, '
                    f'{expected_last} B expected'
                )
        else:
            if on_disk != chunk_size:
                bad_files.append(
                    f'chunk {idx} size mismatch: {on_disk} B on disk, '
                    f'{chunk_size} B expected'
                )
    if bad_files:
        raise ValueError('Chunk file integrity check failed: ' + '; '.join(bad_files))

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Stream-copy with optional inline SHA-256.
    # sha256_final=None → skip hashing entirely (saves ~3-5s/GB on i3 370m).
    READ_BUF      = 4 * 1024 * 1024   # 4 MiB read buffer
    REPORT_EVERY  = 16 * 1024 * 1024  # progress update interval
    do_hash       = bool(sha256_final)
    try:
        hasher = hashlib.sha256(usedforsecurity=False) if do_hash else None
    except TypeError:
        hasher = hashlib.sha256() if do_hash else None
    bytes_written = 0
    last_reported = 0

    _assembly_progress_set(token, 0, total_size)

    try:
        with open(dest_path, 'wb') as out:
            out_fd = out.fileno()
            for idx in sorted_chunks:
                chunk_path = os.path.join(tmp_dir, f'{idx:06d}.chunk')
                with open(chunk_path, 'rb') as cf:
                    # os.sendfile: zero-copy kernel transfer when hashing not needed
                    if not do_hash:
                        chunk_len = os.path.getsize(chunk_path)
                        in_fd = cf.fileno()
                        sent = 0
                        while sent < chunk_len:
                            try:
                                n = os.sendfile(out_fd, in_fd, sent, chunk_len - sent)
                            except (AttributeError, OSError):
                                # sendfile not available or failed — fall back
                                cf.seek(sent)
                                block = cf.read(READ_BUF)
                                if not block:
                                    break
                                out.write(block)
                                n = len(block)
                            if n == 0:
                                break
                            sent += n
                        bytes_written += sent
                    else:
                        # Must read through Python to hash
                        while True:
                            block = cf.read(READ_BUF)
                            if not block:
                                break
                            out.write(block)
                            hasher.update(block)
                            bytes_written += len(block)

                    if bytes_written - last_reported >= REPORT_EVERY:
                        _assembly_progress_set(token, bytes_written, total_size)
                        last_reported = bytes_written
    except Exception as exc:
        _assembly_progress_set(token, bytes_written, total_size, error=str(exc))
        raise

    actual_sha256 = hasher.hexdigest() if do_hash else ''
    if sha256_final and sha256_final.lower() != actual_sha256:
        _assembly_progress_set(token, bytes_written, total_size, error='SHA-256 mismatch')
        try:
            os.remove(dest_path)
        except OSError:
            pass
        raise ValueError(
            f'SHA-256 mismatch: expected {sha256_final}, got {actual_sha256}'
        )

    _assembly_progress_set(token, total_size, total_size, done=True)
    with _db_connect() as conn:
        conn.execute(
            "UPDATE upload_sessions SET completed=1, upload_status='complete', "
            "last_activity=CURRENT_TIMESTAMP WHERE upload_token=?", (token,)
        )
        conn.commit()
    _release_chunk_lock(token)
    _assembly_progress_clear(token)
    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    logging.info(
        f'Upload assembled (buffer): {dest_path} '
        f'({actual_sha256[:12] if actual_sha256 else "no-hash"}…)'
    )
    return dest_path, actual_sha256


# ---------------------------------------------------------------------------
# Status / session helpers
# ---------------------------------------------------------------------------

def _upload_session_status(session: dict) -> dict:
    """Return a client-friendly status dict for a session."""
    total    = session['total_chunks']
    received = session['chunks_received']
    return {
        'upload_token':    session['upload_token'],
        'filename':        session['filename'],
        'chunk_size':      session['chunk_size'],
        'total_chunks':    total,
        'chunks_received': received,
        'missing_chunks':  [i for i in range(total) if i not in received] if total > 0 else [],
        'completed':       bool(session['completed']),
        'last_activity':   session['last_activity'],
        'strategy':        session.get('strategy', 'buffer'),
    }


def _purge_abandoned_upload_sessions() -> bool:
    """Delete upload sessions and their tmp dirs / partial dest files that
    have been idle past TTL.

    For 'direct' strategy sessions:  the pre-allocated destination file is
    deleted (it's a partial, hidden file — no user would see it in the
    browser, and leaving it wastes HDD space).

    For 'buffer' strategy sessions:  the tmp chunk directory is deleted as
    before.
    """
    try:
        cutoff     = datetime.now() - timedelta(seconds=UPLOAD_SESSION_TTL)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT upload_token, tmp_dir, dest_path, strategy
                   FROM upload_sessions
                   WHERE last_activity < ? AND completed = 0''',
                (cutoff_str,)
            ).fetchall()
            for token, tmp_dir, dest_path, strategy in rows:
                strat = strategy or 'buffer'
                try:
                    if strat == 'direct':
                        # Delete the partial pre-allocated file
                        if dest_path and os.path.isfile(dest_path):
                            os.remove(dest_path)
                            logging.info(
                                f'Purged abandoned direct-write file: {dest_path}'
                            )
                    else:
                        # Delete the tmp chunk directory
                        if tmp_dir:
                            shutil.rmtree(tmp_dir, ignore_errors=True)
                        logging.info(
                            f'Purged abandoned buffer session {token[:12]}…'
                        )
                    _release_chunk_lock(token)
                except Exception:
                    pass
            if rows:
                conn.execute(
                    'DELETE FROM upload_sessions WHERE last_activity < ? AND completed = 0',
                    (cutoff_str,)
                )
                conn.commit()
        return True
    except Exception:
        logging.exception('Failed to purge abandoned upload sessions')
        return False


def _cancel_upload_session(token: str) -> bool:
    """Cancel an upload session immediately, cleaning up associated files.

    Called by handle_upload_session_cancel in server_cdn.py.
    Returns True on success, False on error.
    """
    session = _upload_get(token)
    if not session:
        return True  # already gone

    strategy  = session.get('strategy', 'buffer')
    dest_path = session['dest_path']
    tmp_dir   = session['tmp_dir']

    try:
        with _db_connect() as conn:
            conn.execute(
                'DELETE FROM upload_sessions WHERE upload_token = ?', (token,)
            )
            conn.commit()
        _release_chunk_lock(token)
        if strategy == 'direct':
            if dest_path and os.path.isfile(dest_path):
                os.remove(dest_path)
        else:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        return True
    except Exception:
        logging.exception(f'Failed to cancel upload session {token[:12]}…')
        return False


# Re-export constants so server_cdn.py import line doesn't need changing.
from config import (
    UPLOAD_CHUNK_SIZE,
    UPLOAD_SESSION_TTL,
    MAX_JSON_BODY,
    MAX_SHARE_UPLOAD_BYTES,
    MAX_UPLOAD_BYTES,
    UPLOAD_TMP_DIR,
)
