#!/usr/bin/env python3
import sys
import os
import ssl
import threading
import time
import logging
import logging.handlers
import socket
import resource
import queue

# Shared event used by the HTTP server health-check to wait until server is ready
server_ready = threading.Event()

# Global blacklist and synchronization primitives
current_blacklist = set()
blacklist_lock = threading.Lock()
stop_update_event = threading.Event()

# --- Overlapped read-ahead for streaming responses ---------------------------

class PrefetchReader:
    """Iterate chunks from ``read_fn`` while a background thread reads ahead.

    Why this exists
    ---------------
    The obvious streaming loop::

        while True:
            chunk = src.read(BUF)     # disk busy, socket idle
            if not chunk: break
            sock.write(chunk)         # socket busy, disk idle

    strictly alternates. The disk sits idle while the socket drains and the
    socket sits idle while the disk seeks, so the two stages never overlap and
    their throughputs combine harmonically -- 1/(1/a + 1/b) -- instead of the
    pipeline running at min(a, b).

    Measured on the deployment box: downloads capped at ~38 MB/s while the
    drive was only 32-40% utilised with an average queue depth below 1.0 (i.e.
    usually nothing queued at all) and no CPU core above ~37%. Nothing was
    saturated; the loop simply never asked for the next block until the
    previous one had finished being written. Reading one block ahead keeps the
    device fed and lets the two stages run concurrently.

    Usage -- always as a context manager, so the reader thread is stopped even
    when the consumer bails out early (client disconnect is the common case)::

        with PrefetchReader(lambda: fh.read(BUF)) as chunks:
            for chunk in chunks:
                sock.write(chunk)

    ``read_fn`` must return ``b''`` at end of stream, per the file-object
    convention. It is called only from the reader thread, so it must not touch
    state the consumer mutates -- give it its own counter rather than sharing
    the consumer's "bytes written" tally.

    Exceptions raised by ``read_fn`` are re-raised in the consumer after any
    already-buffered chunks have been yielded, so callers keep their existing
    error handling.

    Memory: at most ``depth`` chunks queued, plus one in the reader's hand and
    one being written -- budget roughly ``(depth + 2) * chunk_size`` per active
    stream. Keep ``depth`` small on memory-tight hosts.
    """

    def __init__(self, read_fn, depth: int = 2, name: str = 'Prefetch'):
        if depth < 1:
            raise ValueError('depth must be >= 1')
        self._read_fn = read_fn
        self._q = queue.Queue(maxsize=depth)
        self._stop = threading.Event()
        self._exc = None
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            while not self._stop.is_set():
                chunk = self._read_fn()
                # Bounded put: a consumer that has gone away must not leave
                # this thread parked on a full queue for the life of the process.
                while not self._stop.is_set():
                    try:
                        self._q.put(chunk, timeout=0.25)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    return
        except BaseException as exc:      # re-raised in the consumer
            self._exc = exc

    def __iter__(self):
        while True:
            try:
                chunk = self._q.get(timeout=0.25)
            except queue.Empty:
                # Producer may have died (exception) without queuing a marker.
                if not self._thread.is_alive() and self._q.empty():
                    break
                continue
            if not chunk:
                break
            yield chunk
        if self._exc is not None:
            raise self._exc

    def close(self):
        """Signal the reader thread to stop and unpark it if it is blocked."""
        self._stop.set()
        try:
            while True:
                self._q.get_nowait()
        except queue.Empty:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


# --- File descriptor limit ---

def raise_fd_limit(target: int = 65536) -> None:
    """Raise the process open-file-descriptor limit as high as the OS allows.

    Why this matters:
      Each concurrent connection consumes one socket FD.  With 2000 VUs all
      queued in the ThreadPoolExecutor work queue, the OS has already accepted
      2000 sockets — all 2000 FDs are open even if only 100 workers are
      actively serving them.  Add file FDs for active transfers, log handles,
      SSL state, and Python internals and you easily exceed the default 1024
      soft limit, causing [Errno 24] Too many open files.

    This call is a safety-net inside the process.  You should also set the
    system limit permanently:
      • /etc/security/limits.conf:  add  "* soft nofile 65536"
                                         "* hard nofile 65536"
      • systemd service unit:       add  "LimitNOFILE=65536"  under [Service]
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            print(f"File descriptor limit raised: {soft} → {new_soft} "
                  f"(hard cap: {hard})")
        else:
            print(f"File descriptor limit already at {soft} (hard cap: {hard})")
    except Exception as e:
        print(f"Warning: could not raise file descriptor limit: {e}")

# --- Custom Logger ---
def _log_retention_days() -> int:
    try:
        from config import LOG_RETENTION_DAYS
        return max(1, int(LOG_RETENTION_DAYS))
    except Exception:
        return 90


class CustomLogger:
    # The real terminal stdout/stderr captured before any redirection.
    # Both stdout and stderr loggers write through this so neither fans
    # through the other's write() — which would double-log errors.
    _real_terminal = sys.stdout

    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = CustomLogger._real_terminal
        self.file_logger = logging.getLogger(log_file)
        self.file_logger.setLevel(logging.INFO)
        self.file_logger.propagate = False
        if not self.file_logger.handlers:          # ← only add once
            formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            # One file per day, rotated at midnight; only the newest
            # LOG_RETENTION_DAYS are kept (Privacy Policy §2.6 promises 90).
            # Old days are renamed <log_file>.YYYY-MM-DD and deleted in turn.
            file_handler = logging.handlers.TimedRotatingFileHandler(
                log_file, when='midnight', backupCount=_log_retention_days(), encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.file_logger.addHandler(file_handler)

    def write(self, message):
        self.terminal.write(message)
        if message.strip():
            self.file_logger.info(message.strip())

    def flush(self):
        try:
            self.terminal.flush()
        except Exception:
            pass
        for handler in self.file_logger.handlers:
            try:
                handler.flush()
            except Exception:
                pass

# --- Blacklist utilities ---

def load_blacklist_safely(blacklist_file):
    global current_blacklist
    try:
        with open(blacklist_file, 'r', encoding='utf-8') as file:
            new_blacklist = {line.strip() for line in file if line.strip()}
            with blacklist_lock:
                current_blacklist = new_blacklist
        print(f"Blacklist loaded: {len(current_blacklist)} entries.")
        return current_blacklist
    except FileNotFoundError:
        print(f"Blacklist file '{blacklist_file}' not found. Starting with an empty blacklist.")
        with blacklist_lock:
            current_blacklist = set()
        return set()
    except Exception as e:
        print(f"Error loading blacklist file '{blacklist_file}': {e}")
        return current_blacklist


def update_blacklist(blacklist_file, interval, stop_event):
    while not stop_event.is_set():
        print("Updating blacklist...")
        load_blacklist_safely(blacklist_file)
        stop_event.wait(interval)

# --- Health check / restart utilities ---

def restart_server():
    print("Restarting server due to failed health check...")
    python = sys.executable
    os.execv(python, [python] + sys.argv)


def _health_check_socket(host, port, label, initial_delay=10, interval=30, max_failures=3):
    host = '127.0.0.1' if host in ('0.0.0.0', '', '::') else host
    print(f"Health check ({label}) waiting for server to be ready...")
    server_ready.wait()
    time.sleep(initial_delay)

    consecutive_failures = 0
    while True:
        time.sleep(interval)
        try:
            # Use a real HTTP request — a pure socket.connect() succeeds even
            # when the thread pool is fully saturated (kernel accept buffer).
            #
            # BUGFIX: this used to hardcode https:// regardless of `label`,
            # so the HTTP health check (label="HTTP") sent a TLS ClientHello
            # at the plain-HTTP listener. The server correctly rejected it
            # as a bad request, urlopen saw it as SSL: WRONG_VERSION_NUMBER,
            # and 3 consecutive "failures" triggered a restart — every ~100s,
            # forever, of a server that was never actually broken.
            import urllib.request
            scheme = 'https' if label == 'HTTPS' else 'http'
            url = f"{scheme}://{host}:{port}/healthz"  # or /status, or any cheap path
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(url, timeout=5, context=ctx) as r:
                    r.read(64)
            else:
                with urllib.request.urlopen(url, timeout=5) as r:
                    r.read(64)
            consecutive_failures = 0
            print(f"Health check OK ({label})")
        except Exception as e:
            consecutive_failures += 1
            print(f"Health check failed ({label}): {e} "
                  f"(failure {consecutive_failures}/{max_failures})")
            if consecutive_failures >= max_failures:
                restart_server()
                return


def health_check_self_ping_http(server_ip, http_port):
    _health_check_socket(server_ip, http_port, label="HTTP")


def health_check_self_ping_https(server_ip, https_port):
    _health_check_socket(server_ip, https_port, label="HTTPS")


# --- Compressed static files ---
# Text assets (JS/CSS/HTML/SVG/JSON/Markdown) used to go out uncompressed —
# script.js alone was 456 KB on the wire instead of ~60 KB. build.sh writes
# pre-compressed "<file>.gz" (and ".br" if a brotli tool is available) next to
# each asset; serve_compressed_static() sends the best one the browser
# accepts, and gzips on the fly (cached in memory) when no copy exists.
import gzip as _gzip
import mimetypes as _mimetypes
from email.utils import formatdate as _formatdate, parsedate_to_datetime as _parsedate

_COMPRESSIBLE_EXTS = {'.js', '.mjs', '.css', '.html', '.htm', '.svg', '.json',
                      '.md', '.txt', '.xml', '.map'}
_GZ_MIN, _GZ_MAX_ONTHEFLY = 512, 4 * 1024 * 1024
_gz_cache: dict = {}              # path -> (mtime_ns, size, bytes)
_gz_cache_lock = threading.Lock()
_GZ_CACHE_MAX_ENTRIES = 64


def _accepts(accept_encoding: str, coding: str) -> bool:
    for part in accept_encoding.split(','):
        name, _, params = part.strip().partition(';')
        if name.strip().lower() == coding:
            return 'q=0' not in params.replace(' ', '') or 'q=0.' in params.replace(' ', '')
    return False


def _gzip_cached(filepath: str, st) -> bytes:
    key = filepath
    with _gz_cache_lock:
        hit = _gz_cache.get(key)
        if hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size:
            return hit[2]
    with open(filepath, 'rb') as f:
        data = _gzip.compress(f.read(), compresslevel=6, mtime=0)
    with _gz_cache_lock:
        if len(_gz_cache) >= _GZ_CACHE_MAX_ENTRIES:
            _gz_cache.pop(next(iter(_gz_cache)))
        _gz_cache[key] = (st.st_mtime_ns, st.st_size, data)
    return data


def serve_compressed_static(handler, filepath: str) -> bool:
    """Send *filepath* compressed if possible. True = response fully sent.

    Returns False (caller falls back to plain serving) for non-text files,
    tiny files, Range requests (byte ranges refer to the uncompressed file),
    or clients that don't accept gzip/br.
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in _COMPRESSIBLE_EXTS or not os.path.isfile(filepath):
        return False
    if handler.headers.get('Range'):
        return False
    ae = handler.headers.get('Accept-Encoding', '') or ''
    try:
        st = os.stat(filepath)
    except OSError:
        return False
    if st.st_size < _GZ_MIN:
        return False

    body = coding = None
    for enc, suffix in (('br', '.br'), ('gzip', '.gz')):
        side = filepath + suffix
        if _accepts(ae, enc) and os.path.isfile(side) and os.path.getmtime(side) >= st.st_mtime:
            try:
                with open(side, 'rb') as f:
                    body, coding = f.read(), enc
                break
            except OSError:
                pass
    if body is None and _accepts(ae, 'gzip') and st.st_size <= _GZ_MAX_ONTHEFLY:
        try:
            body, coding = _gzip_cached(filepath, st), 'gzip'
        except OSError:
            return False
    if body is None:
        return False

    # Conditional GET — same semantics SimpleHTTPRequestHandler uses.
    ims = handler.headers.get('If-Modified-Since')
    if ims and not handler.headers.get('If-None-Match'):
        try:
            if int(st.st_mtime) <= _parsedate(ims).timestamp():
                handler.send_response(304)
                handler.send_header('Vary', 'Accept-Encoding')
                handler.end_headers()
                return True
        except (TypeError, ValueError, OverflowError, IndexError):
            pass

    ctype = _mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
    if ext == '.md':
        ctype = 'text/markdown'
    if ctype.startswith('text/') or ctype in ('application/javascript', 'application/json',
                                              'image/svg+xml'):
        ctype += '; charset=utf-8'
    handler.send_response(200)
    handler.send_header('Content-Type', ctype)
    handler.send_header('Content-Encoding', coding)
    handler.send_header('Vary', 'Accept-Encoding')
    handler.send_header('Content-Length', str(len(body)))
    handler.send_header('Last-Modified', _formatdate(st.st_mtime, usegmt=True))
    handler.end_headers()
    if handler.command != 'HEAD':
        handler.wfile.write(body)
    return True


def send_body_compressed(handler, body: bytes, content_type: str,
                         headers: dict | None = None, status: int = 200) -> None:
    """Send an in-memory response (e.g. a patched index.html), gzipped when
    the client accepts it. For pages built per request, where there's no file
    for serve_compressed_static to work from."""
    coding = None
    if len(body) >= _GZ_MIN and _accepts(handler.headers.get('Accept-Encoding', '') or '', 'gzip'):
        body, coding = _gzip.compress(body, compresslevel=6, mtime=0), 'gzip'
    handler.send_response(status)
    handler.send_header('Content-Type', content_type)
    if coding:
        handler.send_header('Content-Encoding', coding)
    handler.send_header('Vary', 'Accept-Encoding')
    handler.send_header('Content-Length', str(len(body)))
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    if handler.command != 'HEAD':
        handler.wfile.write(body)
