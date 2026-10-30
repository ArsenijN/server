"""Archive listing (file tree) for the preview, with an on-disk cache.

ZIP keeps its listing in the central directory, so it is read inline.
Tar(.gz) has no index: listing it means decompressing the whole file, which
for a multi-GB archive takes longer than the proxy waits. Those are built by
one low-priority background worker; the API answers 202 with progress until
the listing is cached, and the client polls.

Zip-bomb limits: tar is streamed header by header (never getmembers(), which
keeps every member in memory), entries are capped (listing marked truncated),
and each job has a time limit and a decompressed/compressed ratio limit.

Cache files live in ARCHIVE_TREE_CACHE_DIR (outside every user's quota), keyed
by path + size + mtime, so a changed or replaced archive is listed again.
"""
import hashlib, json, logging, os, queue, tarfile, threading, time, zipfile

from config import SECRETS_DIR

ARCHIVE_TREE_CACHE_DIR   = os.getenv('ARCHIVE_TREE_CACHE_DIR',
                                     os.path.join(SECRETS_DIR, 'archive_tree_cache'))
ARCHIVE_TREE_MAX_ENTRIES = int(os.getenv('ARCHIVE_TREE_MAX_ENTRIES', '20000'))
ARCHIVE_TREE_MAX_SECONDS = int(os.getenv('ARCHIVE_TREE_MAX_SECONDS', '900'))    # per tar job
ARCHIVE_TREE_MAX_RATIO   = int(os.getenv('ARCHIVE_TREE_MAX_RATIO', '200'))      # decompressed / compressed
ARCHIVE_TREE_CACHE_KEEP  = int(os.getenv('ARCHIVE_TREE_CACHE_KEEP', '500'))     # newest listings kept
_RATIO_MIN_BYTES         = 64 * 1024 * 1024   # ratio check only once this much was decompressed
_NICE                    = 10

TAR_EXTS = ('tar', 'gz', 'tgz')

# key -> {'status': 'queued'|'running'|'error', 'done': bytes, 'total': bytes, 'error': str}
_jobs: dict = {}
_jobs_lock  = threading.Lock()
_queue: 'queue.Queue[tuple[str, str]]' = queue.Queue()


def archive_ext(path: str) -> str:
    name = os.path.basename(path)
    return (name.rsplit('.', 1)[-1] if '.' in name else '').lower()


def _cache_key(abs_path: str) -> str:
    """Keyed on the content, not the path, so a FluxDrop copy (which keeps
    the mtime), move, rename or trip through the trash reuses the listing:
    size + mtime + the first and last 64 KB. Any edit changes the mtime."""
    st = os.stat(abs_path)
    h = hashlib.sha256(f'{st.st_size}\0{st.st_mtime_ns}\0'.encode())
    with open(abs_path, 'rb') as f:
        h.update(f.read(65536))
        if st.st_size > 65536:
            f.seek(max(65536, st.st_size - 65536))
            h.update(f.read(65536))
    return h.hexdigest()


def _cache_path(key: str) -> str:
    return os.path.join(ARCHIVE_TREE_CACHE_DIR, key + '.json')


def _cache_read(key: str) -> dict | None:
    try:
        with open(_cache_path(key), encoding='utf-8') as f:
            data = json.load(f)
        os.utime(_cache_path(key))   # mtime = last use, for pruning
        return data
    except (OSError, ValueError):
        return None


def _cache_write(key: str, data: dict) -> None:
    try:
        os.makedirs(ARCHIVE_TREE_CACHE_DIR, exist_ok=True)
        tmp = _cache_path(key) + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, separators=(',', ':'))
        os.replace(tmp, _cache_path(key))
        _cache_prune()
    except OSError:
        logging.exception('archive_tree: cache write failed')


def _cache_prune() -> None:
    try:
        files = [os.path.join(ARCHIVE_TREE_CACHE_DIR, n)
                 for n in os.listdir(ARCHIVE_TREE_CACHE_DIR) if n.endswith('.json')]
        if len(files) <= ARCHIVE_TREE_CACHE_KEEP:
            return
        files.sort(key=os.path.getmtime)
        for p in files[:len(files) - ARCHIVE_TREE_CACHE_KEEP]:
            os.remove(p)
    except OSError:
        pass


def _list_zip(abs_path: str) -> dict:
    # zipfile reads only the End-of-Central-Directory record and the Central
    # Directory, never compressed data: O(entries), not O(file size).
    entries, truncated = [], False
    with zipfile.ZipFile(abs_path, 'r') as zf:
        for info in zf.infolist():
            if len(entries) >= ARCHIVE_TREE_MAX_ENTRIES:
                truncated = True
                break
            entries.append({'name': info.filename,
                            'size': info.file_size if not info.is_dir() else None,
                            'is_dir': info.is_dir()})
    return {'format': 'zip', 'entries': entries, 'truncated': truncated,
            'truncated_reason': 'too many entries' if truncated else None}


class _CountingReader:
    """File wrapper that tracks how many compressed bytes were read."""
    def __init__(self, fh):
        self._fh, self.pos = fh, 0

    def read(self, n=-1):
        b = self._fh.read(n)
        self.pos += len(b)
        return b


def _list_tar(abs_path: str, key: str) -> dict:
    mode  = 'r|gz' if archive_ext(abs_path) in ('gz', 'tgz') else 'r|'
    entries, reason = [], None
    started = time.monotonic()
    with open(abs_path, 'rb') as raw:
        reader = _CountingReader(raw)
        # Stream mode: members are read one header at a time and file data is
        # skipped by reading through it, so memory stays flat.
        with tarfile.open(fileobj=reader, mode=mode) as tf:
            for member in tf:
                if len(entries) >= ARCHIVE_TREE_MAX_ENTRIES:
                    reason = 'too many entries'
                    break
                entries.append({'name': member.name,
                                'size': member.size if not member.isdir() else None,
                                'is_dir': member.isdir()})
                with _jobs_lock:
                    if key in _jobs:
                        _jobs[key]['done'] = reader.pos
                # Bytes really decompressed so far = where this header starts
                # (the sizes headers claim are not trusted). Gzip tops out
                # near 1000:1, so the time limit is the main guard; this one
                # cuts obvious bombs short.
                unpacked = member.offset
                if (unpacked > _RATIO_MIN_BYTES and reader.pos
                        and unpacked / reader.pos > ARCHIVE_TREE_MAX_RATIO):
                    reason = 'compression ratio too high (possible zip bomb)'
                    break
                if time.monotonic() - started > ARCHIVE_TREE_MAX_SECONDS:
                    reason = 'listing took too long'
                    break
    return {'format': 'tar', 'entries': entries, 'truncated': reason is not None,
            'truncated_reason': reason}


def _worker() -> None:
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), _NICE)
    except (AttributeError, OSError):
        pass
    while True:
        key, abs_path = _queue.get()
        with _jobs_lock:
            if key in _jobs:
                _jobs[key]['status'] = 'running'
        try:
            data = _list_tar(abs_path, key)
            _cache_write(key, data)
            with _jobs_lock:
                _jobs.pop(key, None)
            logging.info('archive_tree: listed %r (%d entries%s)', abs_path,
                         len(data['entries']),
                         f', truncated: {data["truncated_reason"]}' if data['truncated'] else '')
        except Exception as exc:
            logging.warning('archive_tree: listing %r failed: %s', abs_path, exc)
            with _jobs_lock:
                if key in _jobs:
                    _jobs[key].update(status='error', error=str(exc) or type(exc).__name__)
        finally:
            _queue.task_done()


threading.Thread(target=_worker, daemon=True, name='ArchiveTreeWorker').start()


def _enqueue(key: str, abs_path: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(key)
        if job is None:
            job = _jobs[key] = {'status': 'queued', 'done': 0,
                                'total': os.path.getsize(abs_path), 'error': None}
            _queue.put((key, abs_path))
        return dict(job)


def archive_tree_get(abs_path: str) -> tuple[int, dict]:
    """Return (http_status, body) for the listing of abs_path.

    200 with {format, entries, truncated, truncated_reason} when ready;
    202 with {status: 'pending', queued, done, total} while a tar job is
    queued or running (poll again); 415 for unsupported types; 500 when the
    listing failed (a later call retries it).
    """
    ext = archive_ext(abs_path)
    if ext not in ('zip',) + TAR_EXTS:
        return 415, {'error': f'.{ext} archive tree not supported.'}
    key = _cache_key(abs_path)
    cached = _cache_read(key)
    if cached is not None:
        return 200, cached
    if ext == 'zip':
        data = _list_zip(abs_path)
        _cache_write(key, data)
        return 200, data
    with _jobs_lock:
        job = _jobs.get(key)
        if job and job['status'] == 'error':
            _jobs.pop(key, None)       # report once, retry on the next call
            return 500, {'error': f'Archive listing failed: {job["error"]}'}
    job = _enqueue(key, abs_path)
    return 202, {'status': 'pending', 'queued': job['status'] == 'queued',
                 'done': job['done'], 'total': job['total']}


def archive_tree_prewarm(abs_path: str) -> None:
    """Queue a tar listing in the background (e.g. right after an upload)."""
    try:
        if archive_ext(abs_path) in TAR_EXTS:
            key = _cache_key(abs_path)
            if not os.path.exists(_cache_path(key)):
                _enqueue(key, abs_path)
    except OSError:
        pass
