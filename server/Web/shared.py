#!/usr/bin/env python3
import sys
import os
import ssl
import threading
import time
import logging
import socket
import resource

# Shared event used by the HTTP server health-check to wait until server is ready
server_ready = threading.Event()

# Global blacklist and synchronization primitives
current_blacklist = set()
blacklist_lock = threading.Lock()
stop_update_event = threading.Event()

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
