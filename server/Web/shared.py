#!/usr/bin/env python3
import sys
import os
import ssl
import threading
import time
import logging
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
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
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
