import os, json, shutil, secrets, hashlib as time, logging, threading, hashlib
from datetime import datetime, timedelta
from core.db import _db_connect, _get_chunk_lock, _release_chunk_lock, \
                    _assembly_progress_set, _assembly_progress_clear
from core.notifications import _fire_upload_notification
from config import UPLOAD_CHUNK_SIZE, UPLOAD_SESSION_TTL, MAX_JSON_BODY, MAX_SHARE_UPLOAD_BYTES, MAX_UPLOAD_BYTES, UPLOAD_TMP_DIR

def _upload_init(filename: str, dest_path: str, total_size: int,
                 total_chunks: int, sha256_final: str | None,
                 owner_type: str, owner_ref: str,
                 anon_device_token: str | None = None) -> dict:
    """Create a new upload session. Returns the session row as a dict."""
    token = secrets.token_urlsafe(32)
    tmp_dir = os.path.join(UPLOAD_TMP_DIR, token)
    os.makedirs(tmp_dir, exist_ok=True)
    with _db_connect() as conn:
        conn.execute(
            '''INSERT INTO upload_sessions
               (upload_token, filename, dest_path, tmp_dir, total_size,
                chunk_size, total_chunks, sha256_final, owner_type, owner_ref,
                anon_device_token)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            (token, filename, dest_path, tmp_dir, total_size,
             UPLOAD_CHUNK_SIZE, total_chunks, sha256_final, owner_type, owner_ref,
             anon_device_token)
        )
        conn.commit()
    return _upload_get(token)

def _upload_get(token: str) -> dict | None:
    """Fetch an upload session by token. Returns dict or None."""
    with _db_connect() as conn:
        row = conn.execute(
            'SELECT * FROM upload_sessions WHERE upload_token = ?', (token,)
        ).fetchone()
    if not row:
        return None
    keys = ['id','upload_token','filename','dest_path','tmp_dir','total_size',
            'chunk_size','total_chunks','chunks_received','sha256_final',
            'owner_type','owner_ref','anon_device_token','created_at','last_activity','completed']
    d = dict(zip(keys, row))
    d['chunks_received'] = json.loads(d['chunks_received'] or '[]')
    return d

def _upload_receive_chunk(token: str, chunk_index: int, data: bytes,
                          expected_size: int | None = None) -> dict:
    """Write chunk to disk, update session. Returns updated session.

    expected_size: if provided (from Content-Length header), must exactly match
    len(data).  A mismatch means the TCP connection dropped mid-transfer and the
    chunk buffer is truncated — we reject it rather than silently storing a
    partial chunk and later marking it as fully received.
    """
    session = _upload_get(token)
    if not session:
        raise KeyError('Upload session not found')
    if session['completed']:
        raise ValueError('Session already completed')

    # Reject truncated reads immediately so the client gets a 500 and retries.
    if expected_size is not None and len(data) != expected_size:
        raise ValueError(
            f'Chunk {chunk_index} truncated: received {len(data)} bytes, '
            f'expected {expected_size}'
        )

    # Write chunk file (safe outside the lock — each index has a unique filename)
    chunk_path = os.path.join(session['tmp_dir'], f'{chunk_index:06d}.chunk')
    with open(chunk_path, 'wb') as f:
        f.write(data)

    # Confirm the data actually landed on disk at the correct size.
    # stat() after close() is the cheapest way to catch mid-write out-of-space.
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

    # Serialise the read-modify-write so concurrent chunk uploads don't clobber
    # each other's entries in the JSON list.
    lock = _get_chunk_lock(token)
    with lock:
        # Re-read inside the lock to get the latest committed state
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

def _upload_assemble(token: str) -> tuple[str, str]:
    """Assemble all chunks into dest_path.

    Returns (dest_path, sha256_hex).  The SHA-256 is computed *inline* during
    the streaming copy — callers must NOT re-read the assembled file to hash it.
    """
    session = _upload_get(token)
    if not session:
        raise KeyError('Upload session not found')

    tmp_dir      = session['tmp_dir']
    dest_path    = session['dest_path']
    total_chunks = session['total_chunks']
    received     = set(session['chunks_received'])
    chunk_size   = session['chunk_size']

    # 1. Verify all chunks are recorded as received in the DB.
    if total_chunks == 0:
        # Zero-byte file — skip chunk checks, write an empty file directly.
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        open(dest_path, 'wb').close()
        with _db_connect() as conn:
            conn.execute(
                'UPDATE upload_sessions SET completed=1, last_activity=CURRENT_TIMESTAMP WHERE upload_token=?',
                (token,)
            )
            conn.commit()
        _release_chunk_lock(token)
        _assembly_progress_clear(token)
        try:
            shutil.rmtree(session['tmp_dir'], ignore_errors=True)
        except Exception:
            pass
        logging.info(f'Upload assembled (zero-byte): {dest_path}')
        return dest_path, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4825d3a65'  # sha256('')
    if total_chunks > 0:
        missing = [i for i in range(total_chunks) if i not in received]
        if missing:
            raise ValueError(f'Missing chunks: ...')

    # 2. Verify each chunk file actually exists on disk and has the right size.
    #    The last chunk may be smaller than chunk_size (remainder bytes), so we
    #    only enforce the exact size for all chunks except the last one.
    total_size = session['total_size']
    bad_files = []
    sorted_chunks = sorted(received)
    for idx in sorted_chunks:
        chunk_path = os.path.join(tmp_dir, f'{idx:06d}.chunk')
        if not os.path.exists(chunk_path):
            bad_files.append(f'chunk {idx} missing from disk')
            continue
        on_disk = os.path.getsize(chunk_path)
        is_last = (idx == sorted_chunks[-1])
        if is_last:
            # Last chunk: size = total_size - (chunk_size * idx), but allow ≤ chunk_size
            expected_last = total_size - chunk_size * idx if total_size > 0 else on_disk
            if on_disk != expected_last:
                bad_files.append(
                    f'chunk {idx} (last) size mismatch: {on_disk} B on disk, {expected_last} B expected'
                )
        else:
            if on_disk != chunk_size:
                bad_files.append(
                    f'chunk {idx} size mismatch: {on_disk} B on disk, {chunk_size} B expected'
                )
    if bad_files:
        raise ValueError('Chunk file integrity check failed: ' + '; '.join(bad_files))

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # 3. Stream-copy chunks into the final file while hashing inline.
    #    Using a 4 MiB read buffer keeps syscall overhead low for large files.
    #    usedforsecurity=False lets Python use the fastest available SHA-256
    #    implementation (e.g. OpenSSL hardware-accelerated) because we only
    #    need this for data-integrity checking, not cryptographic purposes.
    #    We report progress every 16 MiB to reduce lock contention.
    READ_BUF      = 4 * 1024 * 1024   # 4 MiB per read() call (was 1 MiB)
    REPORT_EVERY  = 16 * 1024 * 1024  # update progress dict every 16 MiB (was 4 MiB)
    try:
        hasher = hashlib.sha256(usedforsecurity=False)
    except TypeError:
        hasher = hashlib.sha256()  # Python < 3.9 fallback
    bytes_hashed  = 0
    last_reported = 0

    _assembly_progress_set(token, 0, total_size)

    try:
        with open(dest_path, 'wb') as out:
            for idx in sorted_chunks:
                chunk_path = os.path.join(tmp_dir, f'{idx:06d}.chunk')
                with open(chunk_path, 'rb') as cf:
                    while True:
                        block = cf.read(READ_BUF)
                        if not block:
                            break
                        out.write(block)
                        hasher.update(block)
                        bytes_hashed += len(block)
                        if bytes_hashed - last_reported >= REPORT_EVERY:
                            _assembly_progress_set(token, bytes_hashed, total_size)
                            last_reported = bytes_hashed
    except Exception as exc:
        _assembly_progress_set(token, bytes_hashed, total_size, error=str(exc))
        raise

    # 4. Verify whole-file SHA-256 if the client declared one at init time.
    actual_sha256 = hasher.hexdigest()
    if session['sha256_final'] and session['sha256_final'].lower() != actual_sha256:
        _assembly_progress_set(token, bytes_hashed, total_size,
                               error='SHA-256 mismatch')
        try:
            os.remove(dest_path)
        except OSError:
            pass
        raise ValueError(
            f'SHA-256 mismatch: expected {session["sha256_final"]}, got {actual_sha256}'
        )

    # 5. Mark complete in DB and clean up tmp chunks.
    _assembly_progress_set(token, total_size, total_size, done=True)
    with _db_connect() as conn:
        conn.execute(
            'UPDATE upload_sessions SET completed = 1, last_activity = CURRENT_TIMESTAMP WHERE upload_token = ?',
            (token,)
        )
        conn.commit()
    _release_chunk_lock(token)
    _assembly_progress_clear(token)
    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    logging.info(f'Upload assembled: {dest_path} ({actual_sha256[:12]}…)')
    return dest_path, actual_sha256

def _upload_session_status(session: dict) -> dict:
    """Return a client-friendly status dict for a session."""
    total   = session['total_chunks']
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
    }

def _purge_abandoned_upload_sessions() -> bool:
    """Delete upload sessions and their tmp dirs that have been idle past TTL."""
    try:
        cutoff = datetime.now() - timedelta(seconds=UPLOAD_SESSION_TTL)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')
        with _db_connect() as conn:
            rows = conn.execute(
                'SELECT upload_token, tmp_dir FROM upload_sessions WHERE last_activity < ? AND completed = 0',
                (cutoff_str,)
            ).fetchall()
            for token, tmp_dir in rows:
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    logging.info(f'Purged abandoned upload session {token[:12]}…')
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
