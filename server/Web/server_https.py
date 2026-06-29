#!/usr/bin/env python3
import http.server
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import os
import sys
import datetime
import logging # Using standard logging module for better control
import uuid # For generating unique IDs for CAPTCHA
from werkzeug.formparser import parse_form_data # For parsing multipart/form-data (cgi deprecated in Python 3.13+)
from urllib.parse import quote_plus
import random # For generating CAPTCHA challenges
import shutil # For securely moving uploaded files
from shared import CustomLogger, load_blacklist_safely, update_blacklist, health_check_self_ping_https, restart_server, raise_fd_limit, \
    current_blacklist, blacklist_lock, stop_update_event, server_ready
from config import SERVE_DIRECTORY, LOG_FILE_HTTPS, BLACKLIST_FILE, CERT_FILE, \
    KEY_FILE, PUBLIC_UPLOAD_DIR as UPLOAD_DIRECTORY, PUBLIC_DOMAIN, \
    WILDCARD_CERT_FILE, WILDCARD_KEY_FILE
import urllib.request as _urllib_req
import urllib.error   as _urllib_err
import posixpath as _psp
import re

# --- Configuration ---
# Read bind IP and SSL port from environment. Default to 0.0.0.0 and non-privileged 8443.
HTTPS_PORT = int(os.getenv('HTTPS_PORT', os.getenv('SSL_PORT', os.getenv('SERVER_PORT', '8443'))))
SERVER_IP = os.getenv('SERVER_IP', '0.0.0.0')
BLACKLIST_UPDATE_INTERVAL = 60 # seconds

# Port of the CDN server's plain-HTTP loopback listener (server_cdn.py
# run_internal_server).  Using the plain-HTTP port here avoids encrypting the
# loopback leg twice: the client already has a TLS session to THIS server, and
# a second TLS handshake to the CDN on the same machine wastes ~50% of the
# available throughput on software AES (i3 370M has no AES-NI).
CDN_INTERNAL_PORT = int(os.getenv('CDN_INTERNAL_PORT', '64799'))

# --- File Upload Security Settings ---
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5 MB in bytes
ALLOWED_EXTENSIONS = {'.txt', '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip'} # Whitelist of allowed file extensions

# --- CDN reverse proxy ---
# Paths that belong to server_cdn.py.  When the browser hits the HTTPS server
# on the standard port for these paths, we forward the request to the CDN
# server internally and stream the response back.  This means all API calls
# and the status page can use same-origin relative URLs and satisfy CSP.
#
# Paths NOT listed here fall through to the normal static-file handler
# (SERVE_DIRECTORY), which is correct for the SPA and its assets.
_CDN_PROXY_PREFIXES = (
    '/api/',
    '/auth/',
    '/share/',
    '/status',
    '/beacon',
    '/FluxDrop/',
    '/cdn/',
    '/CB_uploads/',
)

# ── Host-based reverse proxy ──────────────────────────────────────────────
# Maps a bare hostname to a backend service.  Any request whose Host header
# matches is forwarded wholesale — all paths, all methods — to the target.
# This is how subdomains reach internal services without a separate proxy.
#
# Each entry:
#   'hostname': {
#       'target':  'http://host:port'  — backend origin, no trailing slash
#       'enabled': True | False        — flip False to disable without deleting
#       'timeout': int                 — per-host proxy timeout in seconds
#   }
_HOST_PROXY: dict[str, dict] = {
    # Immich photo management — https://gallery.arseniusgen.dev
    'gallery.arseniusgen.dev': {
        'target':  'http://127.0.0.1:2283',
        'enabled': True,
        'timeout': 120,  # generous — Immich uploads/API can be slow
    },
    # Template for future services — copy, rename, set enabled=True:
    # 'service.arseniusgen.dev': {
    #     'target':  'http://127.0.0.1:PORT',
    #     'enabled': False,
    #     'timeout': 60,
    # },
}

def _get_host_proxy(headers) -> dict | None:
    """Return the active _HOST_PROXY entry for this request, or None."""
    host = headers.get('Host', '').split(':')[0].lower()
    entry = _HOST_PROXY.get(host)
    if entry and entry.get('enabled', True):
        return entry
    return None

def _proxy_to_host(handler, method: str, target_base: str, timeout: int = 60):
    # ── WebSocket tunnel ──────────────────────────────────────────────────
    # urllib cannot do WebSocket upgrades. Instead we open a raw TCP
    # connection to the backend and pipe bytes in both directions.
    if handler.headers.get('Upgrade', '').lower() == 'websocket':
        from urllib.parse import urlparse as _urlparse
        import socket as _raw_sock
        import threading as _thr

        _p = _urlparse(target_base)
        try:
            backend = _raw_sock.create_connection(
                (_p.hostname, _p.port or 80), timeout=10)
        except Exception as e:
            handler.send_response(502)
            msg = f'{{"error":"WS backend unreachable: {e}"}}'.encode()
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(msg)))
            handler.end_headers()
            handler.wfile.write(msg)
            return

        # Forward the original HTTP upgrade request to the backend
        _skip = frozenset({'host', 'content-length'})
        req  = f"{handler.command} {handler.path} HTTP/1.1\r\n"
        req += f"Host: {_p.hostname}:{_p.port or 80}\r\n"
        for k, v in handler.headers.items():
            if k.lower() not in _skip:
                req += f"{k}: {v}\r\n"
        req += "\r\n"
        backend.sendall(req.encode())

        # Read backend's 101 Switching Protocols and forward to client
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = backend.recv(4096)
            if not chunk:
                backend.close()
                return
            head += chunk
        handler.connection.sendall(head)

        # Pipe raw bytes in both directions until one side closes
        def _pipe(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try: src.close()
                except: pass
                try: dst.close()
                except: pass

        t1 = _thr.Thread(target=_pipe, args=(handler.connection, backend), daemon=True)
        t2 = _thr.Thread(target=_pipe, args=(backend, handler.connection), daemon=True)
        t1.start(); t2.start()
        # Don't join — release the executor thread immediately.
        # The daemon pipe threads will clean up when the socket closes.
        handler.close_connection = True
        return
    # ── end WebSocket tunnel ──────────────────────────────────────────────
    """Forward the current request to an arbitrary backend origin.

    Identical in structure to _proxy_to_cdn but with a configurable target
    URL and timeout instead of the hardcoded CDN loopback port.
    """
    _HOP_BY_HOP = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade', 'host',
    })
    _DEDUP_FROM_UPSTREAM = frozenset({
        'access-control-allow-origin', 'access-control-allow-methods',
        'access-control-allow-headers', 'access-control-allow-credentials',
        'access-control-max-age', 'cross-origin-resource-policy',
        'date', 'server',
    })

    target = f"{target_base}{handler.path}"
    _PROXY_MAX_BODY = 512 * 1024 * 1024

    body = None
    cl = handler.headers.get('Content-Length')
    if cl:
        cl_int = int(cl)
        if cl_int > _PROXY_MAX_BODY:
            handler.send_response(413)
            msg = b'{"error":"request body too large"}'
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(msg)))
            handler.end_headers()
            handler.wfile.write(msg)
            return
        if cl_int > 0:
            body = handler.rfile.read(cl_int)

    req = _urllib_req.Request(target, data=body, method=method)
    for k, v in handler.headers.items():
        if k.lower() not in _HOP_BY_HOP:
            try:
                req.add_header(k, v)
            except Exception:
                pass
    req.add_header('X-Forwarded-For', handler.client_address[0])
    req.add_header('X-Forwarded-Proto', 'https')

    _PROXY_BUF = 256 * 1024
    try:
        with _urllib_req.urlopen(req, timeout=timeout) as resp:
            handler.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in _HOP_BY_HOP | _DEDUP_FROM_UPSTREAM:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            handler._proxying = True
            handler.end_headers()
            handler._proxying = False
            while True:
                chunk = resp.read(_PROXY_BUF)
                if not chunk:
                    break
                try:
                    handler.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    break
    except _urllib_err.HTTPError as e:
        try:
            raw = e.read() or b''
        except Exception:
            raw = b''
        try:
            handler.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in _HOP_BY_HOP | _DEDUP_FROM_UPSTREAM | {'content-length'}:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            handler.send_header('Content-Length', str(len(raw)))
            handler._proxying = True
            handler.end_headers()
            handler._proxying = False
            handler.wfile.write(raw)
        except Exception:
            pass
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as exc:
        msg = f'{{"error":"host proxy error: {exc}"}}'.encode()
        try:
            handler.send_response(502)
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(msg)))
            handler.end_headers()
            handler.wfile.write(msg)
        except Exception:
            pass

# ── Root-domain path rewriting ────────────────────────────────────────────
# Maps a bare hostname to the URL subpath where the FluxDrop SPA is installed.
# When a request arrives on one of these domains the path is rewritten
# transparently so the app appears to live at /.  The SPA needs no JS changes:
# _APP_BASE is derived from window.location.pathname, so it becomes '' when
# the initial page load is at / — all navigateTo() calls then produce clean
# /files/... URLs instead of /fluxdrop_pp/files/...
_ROOT_DOMAIN_SUBPATH: dict[str, str] = {
    'fluxdrop.me':     '/fluxdrop_pp',
    'www.fluxdrop.me': '/fluxdrop_pp',
    # arseniusgen.dev intentionally excluded — behaves like arseniusgen.uk.to
    # (user navigates to /fluxdrop_pp/ explicitly on that domain).
}

# Extensions that identify static assets.  Requests for these get the subpath
# prepended and are served normally.  Everything else (/, /files/..., etc.)
# is treated as a SPA navigation URL and receives a patched index.html.
_STATIC_ASSET_EXTS = frozenset({
    '.js', '.css', '.map', '.json',
    '.svg', '.png', '.ico', '.jpg', '.jpeg', '.gif', '.webp', '.avif',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.html', '.htm', '.txt', '.xml', '.webmanifest',
})

def _proxy_to_cdn(handler, method: str = 'GET'):
    """Forward the current request to the CDN server and stream the response back.

    Works for GET, POST, DELETE, OPTIONS, PUT, PATCH.
    Strips hop-by-hop headers before forwarding and before sending back.

    Uses the CDN's plain-HTTP loopback port (CDN_INTERNAL_PORT) — NOT the HTTPS
    port — so the loopback leg is unencrypted.  The TLS session already exists
    between the real client and THIS server; adding a second TLS handshake to
    the loopback was halving throughput on the AES-NI-less i3 370M.
    """
    _HOP_BY_HOP = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade',
        'host',  # we set Host ourselves
    })
    # Strip these from the CDN's response so our end_headers() override is the
    # single source of truth — prevents duplicate CORS/Date/Server headers.
    _DEDUP_FROM_UPSTREAM = frozenset({
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-allow-credentials',
        'access-control-max-age',
        'cross-origin-resource-policy',
        'date',   # Python's BaseHTTPRequestHandler adds its own Date
        'server', # we want only our Server header, not the CDN's
    })

    target = f"http://127.0.0.1:{CDN_INTERNAL_PORT}{handler.path}"

    _PROXY_MAX_BODY = 512 * 1024 * 1024  # 512 MB hard cap; tune to your real max upload

    body = None
    cl = handler.headers.get('Content-Length')
    if cl:
        cl_int = int(cl)
        if cl_int > _PROXY_MAX_BODY:
            handler.send_response(413)
            msg = b'{"error":"request body too large"}'
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(msg)))
            handler.end_headers()
            handler.wfile.write(msg)
            return
        if cl_int > 0:
            body = handler.rfile.read(cl_int)

    req = _urllib_req.Request(target, data=body, method=method)
    for k, v in handler.headers.items():
        if k.lower() not in _HOP_BY_HOP:
            try:
                req.add_header(k, v)
            except Exception:
                pass
    # Forward the real client IP so CDN logs/blacklist work correctly
    req.add_header('X-Forwarded-For', handler.client_address[0])

    # Stream the response in chunks — never buffer the entire body.
    # This is critical for large file downloads (10-30 GB) where .read()
    # would try to hold the whole file in the server's RAM.
    _PROXY_BUF = 256 * 1024   # 256 KiB read buffer — small enough for low-RAM i3
    try:
        # ── Proxy timeout — must be generous for long-running CDN operations ─────
        # socket timeout applies to every individual send()/recv() call, NOT the
        # total transfer.  10 s is enough for light API calls but too short for:
        #   • chunk POSTs  — 25 MB body → CDN pwrite → SQLite update on a busy HDD
        #   • /complete    — buffer-strategy assembly streams all chunks to dest (minutes)
        # Downloads already have their own 90 s ceiling.
        _path_no_qs = handler.path.split('?')[0]
        _is_download_path   = _path_no_qs.startswith(('/cdn/', '/CB_uploads/'))
        _is_upload_chunk    = (method == 'POST'
                            and '/upload_session/' in _path_no_qs
                            and '/chunk/' in _path_no_qs)
        _is_upload_complete = (method == 'POST'
                            and '/upload_session/' in _path_no_qs
                            and _path_no_qs.endswith('/complete'))

        if _is_download_path:
            _proxy_timeout = 90
        elif _is_upload_chunk:
            _proxy_timeout = 60     # 25 MB pwrite on a busy spinner < 5 s; 60 s is generous
        elif _is_upload_complete:
            _proxy_timeout = 300    # buffer-strategy assembly of a multi-GB file can take minutes
        else:
            _proxy_timeout = 10

        with _urllib_req.urlopen(req, timeout=_proxy_timeout) as resp:
            handler.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in _HOP_BY_HOP | _DEDUP_FROM_UPSTREAM:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            # Signal end_headers() override to skip its own CORS injection —
            # the CDN's CORS headers are the authority for credentialed requests.
            handler._proxying = True
            handler.end_headers()
            handler._proxying = False
            # Stream body chunk by chunk directly to the client socket
            while True:
                chunk = resp.read(_PROXY_BUF)
                if not chunk:
                    break
                try:
                    handler.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    break   # client disconnected mid-download — normal for seeks/cancels
    except _urllib_err.HTTPError as e:
        # Forward the CDN's error response with its original headers intact.
        # Do NOT hardcode Content-Type or Content-Encoding — the CDN may have
        # sent gzip-compressed HTML/JSON, and overriding the headers causes the
        # browser to render garbled output.
        try:
            raw = e.read() or b''
        except Exception:
            raw = b''
        try:
            handler.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in _HOP_BY_HOP | _DEDUP_FROM_UPSTREAM | {'content-length'}:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            handler.send_header('Content-Length', str(len(raw)))
            handler._proxying = True
            handler.end_headers()
            handler._proxying = False
            handler.wfile.write(raw)
        except Exception:
            pass
    except (BrokenPipeError, ConnectionResetError):
        pass   # client disconnected before or during headers
    except Exception as exc:
        msg = f'{{"error":"proxy error: {exc}"}}'.encode()
        try:
            handler.send_response(502)
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(msg)))
            handler.end_headers()
            handler.wfile.write(msg)
        except Exception:
            pass


# --- CAPTCHA Storage ---
# Key: CAPTCHA ID (string), Value: (correct_answer, monotonic_timestamp)
captcha_challenges = {}
captcha_lock = threading.Lock()
CAPTCHA_TTL = 600  # 10 minutes — abandon protection against memory accumulation

def generate_captcha():
    """Generates a simple math CAPTCHA, stores its answer with a TTL timestamp."""
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operators = ['+', '-', '*']
    operator = random.choice(operators)

    question = f"{num1} {operator} {num2}"
    if operator == '+':
        answer = str(num1 + num2)
    elif operator == '-':
        answer = str(num1 - num2)
    else:  # '*'
        answer = str(num1 * num2)

    captcha_id = str(uuid.uuid4())
    now = time.monotonic()
    with captcha_lock:
        # N11: Evict stale entries on every insert to bound memory usage
        stale = [k for k, (_, ts) in captcha_challenges.items() if now - ts > CAPTCHA_TTL]
        for k in stale:
            del captcha_challenges[k]
        captcha_challenges[captcha_id] = (answer, now)
    return captcha_id, question

def verify_captcha(captcha_id, user_answer):
    """Verifies the user's CAPTCHA answer, removes the challenge, and checks TTL."""
    with captcha_lock:
        entry = captcha_challenges.pop(captcha_id, None)

    if entry is None:
        print(f"CAPTCHA verification failed: ID '{captcha_id}' not found or already used.")
        return False

    answer, ts = entry
    if time.monotonic() - ts > CAPTCHA_TTL:
        print(f"CAPTCHA expired for ID '{captcha_id}'.")
        return False

    if user_answer.strip() == answer:
        print(f"CAPTCHA verified successfully for ID '{captcha_id}'.")
        return True
    else:
        print(f"CAPTCHA verification failed for ID '{captcha_id}'.")
        return False



# --- Request Handler ---

def _cache_control_for_path(path: str) -> str:
    _ext  = _psp.splitext(path.split('?')[0])[1].lower()
    _base = _psp.basename(path.split('?')[0]).lower()
    if _base in ('index.html', 'index.htm'):
        return 'no-cache'
    if _ext in ('.woff', '.woff2', '.ttf', '.eot', '.otf'):
        return 'max-age=31536000, immutable'
    if _ext in ('.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico'):
        return 'max-age=86400'
    if _ext in ('.css', '.js', '.map'):
        return 'max-age=3600, must-revalidate'
    return ''

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    """
    Custom HTTP request handler that includes blacklist checking and file upload capabilities.
    """
    # ── Why timeout matters for long-running stability ────────────────────────
    # Without a timeout, a client that opens a TLS connection and then goes
    # silent (network drop, suspended laptop, zombie socket) holds one thread-
    # pool slot indefinitely.  After a few days of normal traffic these slots
    # accumulate until all 100 workers are stuck, new requests queue in the
    # kernel accept buffer, the health check still succeeds (TCP accepts), but
    # no requests are actually served — the server appears alive but is frozen.
    #
    # timeout = 45 s covers:
    #   • TLS handshake stall (client connects, never sends ClientHello)
    #   • Slow request body (POST with content but never finishing)
    #   • HTTP/1.1 keep-alive idle time between pipelined requests
    # Large file downloads are served in a streaming loop that writes chunks
    # continuously, so they are never affected by this idle timeout.
    timeout = 45  # seconds — kill idle/zombie connections

    def __init__(self, *args, **kwargs):
        # Ensure the upload directory exists
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
        # Pass directory to the parent constructor — this is thread-safe.
        # os.chdir() changes the *process-wide* cwd and races under ThreadingHTTPServer.
        super().__init__(*args, directory=SERVE_DIRECTORY, **kwargs)

    def end_headers(self):
        """Override end_headers to inject CORS and font-specific headers on every
        response this handler sends.

        Why needed: SimpleHTTPRequestHandler.do_GET() calls end_headers internally,
        bypassing any per-request patching. Without this override, font files (.woff2
        etc.) served from this static server carry no Access-Control-Allow-Origin
        header, which makes browsers reject them with "CORS Missing Allow Origin"
        when the font is fetched cross-origin (e.g. HTTP page loading an HTTPS asset,
        or any sub-resource loaded from a different port).

        Cross-Origin-Resource-Policy: cross-origin is also required for fonts and
        media loaded by pages on a different origin/scheme.

        When _proxying is True (set by _proxy_to_cdn) we skip injection entirely —
        the CDN already sent its own CORS headers and we must not duplicate them.
        Duplicate CORS headers cause browsers to reject the response outright.
        """
        if getattr(self, '_proxying', False):
            super().end_headers()
            return

        # Determine the file extension from the requested path so we can add
        # the extra font/media CORS hint only where needed.
        try:
            _ext = _psp.splitext(self.path.split('?')[0])[1].lower()
        except Exception:
            _ext = ''

        _FONT_EXTS = {'.woff', '.woff2', '.ttf', '.eot', '.otf'}
        if _ext in _FONT_EXTS:
            # Fonts always need explicit cross-origin permission
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
        else:
            self.send_header('Access-Control-Allow-Origin', '*')

        self.send_header('Access-Control-Allow-Methods',
                         'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, Authorization, Range, X-Requested-With')
        super().end_headers()

    def _set_headers(self, status_code=200, content_type='text/html'):
        """Helper to set common headers including CORS."""
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        # Allow all origins for simplicity in this example.
        # For production, replace '*' with specific allowed origins.
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


    def do_GET(self):
        # Fast-path health probe — must come first, before proxy and blacklist.
        if self.path == '/healthz':
            body = b'ok'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # ── Host-based proxy ─────────────────────────────────────────────────
        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'GET', _hp['target'], _hp.get('timeout', 60))

        client_ip = self.client_address[0]
        requested_path = self.path
        # Only log non-trivial paths to avoid lock contention under scanner floods
        # if not requested_path.startswith(('/healthz', '/favicon')):
        #     print(f"Request from: {client_ip} -> {requested_path}")
        # This is not the thing that I want, but I'll leave it here for other 
        # ones who needs it
        # There's old variant:
        print(f"Request from: {client_ip} -> {requested_path}")

        # --- Proxy CDN-owned paths to server_cdn.py internally ---
        # Instead of 302-redirecting (which exposes the CDN port to the browser
        # and breaks same-origin CSP), we forward the request to the CDN server
        # on the loopback interface and stream the response back transparently.
        # The browser always sees one origin (this server's port) — no CSP issues.
        _clean = requested_path.split('?')[0]
        if any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'GET')

        # ── Root-domain transparent path rewrite ──────────────────────────────
        # fluxdrop.me is a "root" domain that should show the app at / instead
        # of /fluxdrop_pp/.  arseniusgen.dev and arseniusgen.uk.to keep the
        # normal /fluxdrop_pp/ subpath behaviour.
        #
        # Two cases:
        #   Static asset (.js/.css/.svg/…) → prepend subpath and fall through to
        #       SimpleHTTPRequestHandler so the file is found on disk.
        #   Navigation   (/, /files/photos, any path without a known ext) →
        #       serve index.html with <base href="{subpath}/"> patched to
        #       <base href="/"> so relative assets resolve from root and
        #       _APP_BASE in script.js becomes '' → clean pushState URLs.
        #
        # Paths already carrying the subpath (/fluxdrop_pp/script.js …) are
        # skipped; those come from the SPA after the first load and are correct.
        # CDN paths (/api/, /share/, …) were already handled above this block.
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        _subpath   = _ROOT_DOMAIN_SUBPATH.get(_host_bare)
        if _subpath:
            _clean = requested_path.split('?')[0]
            if not (_clean == _subpath or _clean.startswith(_subpath + '/')):
                _ext = _psp.splitext(_clean)[1].lower()
                if _ext in _STATIC_ASSET_EXTS:
                    # Static asset: prepend subpath so SimpleHTTPRequestHandler
                    # finds it under SERVE_DIRECTORY/fluxdrop_pp/…
                    self.path = _subpath + requested_path
                    # Fall through to the normal handler below.
                else:
                    # Navigation URL (/, /files/photos, /files …):
                    # serve the app shell with a patched <base href="/">.
                    _index_fs = self.translate_path(_subpath + '/index.html')
                    try:
                        with open(_index_fs, 'rb') as _fh:
                            _html = _fh.read()
                        # Single targeted replace — won't clobber any other
                        # occurrence of the string inside the document body.
                        _html = _html.replace(
                            f'<base href="{_subpath}/">'.encode(),
                            b'<base href="/">',
                            1,
                        )
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                        self.send_header('Content-Length', str(len(_html)))
                        # Never cache the shell — a stale version with the wrong
                        # base href would silently break asset loading.
                        self.send_header('Cache-Control', 'no-cache, no-store')
                        self.end_headers()
                        self.wfile.write(_html)
                        return
                    except Exception as _e:
                        print(f'[root-domain rewrite] index.html read failed '
                              f'({_host_bare}): {_e}')
                        # Fall through → 404 from the normal static handler.

        # P11: SPA deep-link support — serve the app shell for any .../files[/...] path
        # so the browser history API can restore the correct folder on direct load or refresh.
        # Works whether the app is at root or a subdirectory (e.g. /fluxdrop_pp/).
        #
        # IMPORTANT: only rewrite when the segment immediately after '/files' is
        # end-of-string, '/', or '?' — i.e. it looks like a folder navigation URL.
        # Without this guard the rewrite also matches asset requests that happen
        # to contain '/files' in their path (e.g. /fluxdrop_pp/files/script.js),
        # causing the server to return index.html with Content-Type text/html for
        # those assets, which the browser then rejects as invalid JS/CSS.
        _clean_path = requested_path.split('?')[0]
        _files_idx  = _clean_path.find('/files')
        if _files_idx != -1:
            _after = _clean_path[_files_idx + 6:]   # chars after '/files'
            # Only rewrite SPA navigation paths, never asset files.
            # A real navigation path ends here, continues with '/', or has a query string.
            # An asset file continues with a non-slash character (e.g. '/files/script.js').
            _is_nav = (_after == '' or _after.startswith('/') or _after.startswith('?'))
            # Extra safety: don't rewrite if the path ends with a known static extension.
            _ext = _psp.splitext(_clean_path)[1].lower()
            _static_exts = {'.js', '.css', '.html', '.svg', '.png', '.ico',
                            '.jpg', '.jpeg', '.gif', '.webp', '.woff', '.woff2',
                            '.ttf', '.eot', '.map', '.json', '.txt'}
            if _is_nav and _ext not in _static_exts:
                # Rewrite to index.html in the same directory as the app
                _app_dir  = _clean_path[:_files_idx]   # e.g. '' or '/fluxdrop_pp'
                self.path = _app_dir + '/index.html'
                # fall through to the normal static-file handler below

        with blacklist_lock:
            if client_ip in current_blacklist:
                self.send_response(403)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(b"<h1>403 Forbidden</h1>Access Denied")))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                self.wfile.write(b"<h1>403 Forbidden</h1>Access Denied")
                return

        range_header = self.headers.get('Range')
        if range_header:
            m = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if m:
                start = int(m.group(1))
                end = m.group(2)
                path = self.translate_path(self.path)
                try:
                    file_size = os.path.getsize(path)
                    if end:
                        end = int(end)
                    else:
                        end = file_size - 1
                    if start > end or start >= file_size or end >= file_size:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{file_size}")
                        self.send_header("Content-type", "text/html")
                        self.send_header("Content-Length", str(len(b"<h1>416 Requested Range Not Satisfiable</h1>")))
                        self.send_header("Accept-Ranges", "bytes")
                        self.end_headers()
                        self.wfile.write(b"<h1>416 Requested Range Not Satisfiable</h1>")
                        return
                    content_length = end - start + 1
                    self.send_response(206)
                    self.send_header("Content-type", self.guess_type(path))
                    self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                    self.send_header("Content-Length", str(content_length))
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                    chunk_size = 2 * 1024 * 1024  # NEW: 2 MB chunks
                    bytes_left = content_length
                    with open(path, 'rb') as f:
                        f.seek(start)
                        while bytes_left > 0:
                            to_read = min(chunk_size, bytes_left)
                            data = f.read(to_read)
                            if not data:
                                break
                            try:
                                self.wfile.write(data)
                            except (BrokenPipeError, ConnectionResetError):
                                return  # client disconnected mid-range — normal
                            bytes_left -= len(data)
                    return
                except (BrokenPipeError, ConnectionResetError):
                    return  # headers already sent, client disconnected
                except Exception as e:
                    print(f"Error serving range: {e}")
                    # Only valid if headers were not yet sent (e.g. file missing)
                    try:
                        self.send_response(404)
                        self.send_header("Content-type", "text/html")
                        self.send_header("Content-Length", str(len(b"<h1>404 File not found</h1>")))
                        self.send_header("Accept-Ranges", "bytes")
                        self.end_headers()
                        self.wfile.write(b"<h1>404 File not found</h1>")
                    except Exception:
                        pass
                    return

        if requested_path == '/upload':
            # The FluxDrop CDN (server_cdn.py) handles all uploads.
            # This route previously contained an editing stub and is now removed.
            self.send_response(404)
            body = b"<h1>404 Not Found</h1><p>Uploads are handled by the FluxDrop CDN.</p>"
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        def patched_end_headers():
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "keep-alive")
            self.send_header("Keep-Alive", "timeout=30, max=100")
            _cc = _cache_control_for_path(self.path)
            if _cc:
                self.send_header("Cache-Control", _cc)
            super(RequestHandler, self).end_headers()
        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            super().do_GET()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client disconnected mid-transfer — normal under load, headers already sent
        except Exception as e:
            print(f"Error in default GET handler: {e}")
            try:
                self.send_response(500)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(b"<h1>500 Internal Server Error</h1>")))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                self.wfile.write(b"<h1>500 Internal Server Error</h1>")
            except Exception:
                pass
        finally:
            self.end_headers = old_end_headers

    def do_HEAD(self):
        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'HEAD', _hp['target'], _hp.get('timeout', 60))
        client_ip = self.client_address[0]
        requested_path = self.path

        # ── Root-domain rewrite (mirrors do_GET) ──────────────────────────────
        # The service worker issues HEAD requests to check cache freshness for
        # URLs it cached under _APP_BASE = '' paths (e.g. HEAD /script.js).
        # Without this rewrite those 404 because the file is at /fluxdrop_pp/.
        # Only static assets are rewritten here; for navigation paths we just
        # fall through — the SW never HEADs navigation URLs in practice.
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        _subpath   = _ROOT_DOMAIN_SUBPATH.get(_host_bare)
        if _subpath:
            _clean = requested_path.split('?')[0]
            if not (_clean == _subpath or _clean.startswith(_subpath + '/')):
                _ext = _psp.splitext(_clean)[1].lower()
                if _ext in _STATIC_ASSET_EXTS:
                    self.path = _subpath + requested_path

        with blacklist_lock:
            if client_ip in current_blacklist:
                self.send_response(403)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(b"<h1>403 Forbidden</h1>Access Denied")))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                return
        range_header = self.headers.get('Range')
        if range_header:
            m = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if m:
                start = int(m.group(1))
                end = m.group(2)
                path = self.translate_path(self.path)
                try:
                    file_size = os.path.getsize(path)
                    if end:
                        end = int(end)
                    else:
                        end = file_size - 1
                    if start > end or start >= file_size or end >= file_size:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{file_size}")
                        self.send_header("Content-type", "text/html")
                        self.send_header("Content-Length", str(len(b"<h1>416 Requested Range Not Satisfiable</h1>")))
                        self.send_header("Accept-Ranges", "bytes")
                        self.end_headers()
                        return
                    content_length = 0
                    self.send_response(206)
                    self.send_header("Content-type", self.guess_type(path))
                    self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                    self.send_header("Content-Length", str(content_length))
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                    return
                except Exception as e:
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Content-Length", str(len(b"<h1>404 File not found</h1>")))
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                    return
        def patched_end_headers():
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "keep-alive")
            self.send_header("Keep-Alive", "timeout=30, max=100")
            _cc = _cache_control_for_path(self.path)
            if _cc:
                self.send_header("Cache-Control", _cc)
            super(RequestHandler, self).end_headers()
        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            super().do_HEAD()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client disconnected
        except Exception as e:
            try:
                self.send_response(500)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(b"<h1>500 Internal Server Error</h1>")))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
            except Exception:
                pass
        finally:
            self.end_headers = old_end_headers

    def do_POST(self):
        """
        Handles POST requests, primarily for file uploads.
        Includes security checks and CAPTCHA verification.
        """

        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'POST', _hp['target'], _hp.get('timeout', 60))
        
        client_ip = self.client_address[0]
        print(f"POST request from: {client_ip} -> {self.path}")

        # Acquire the lock before checking the blacklist
        with blacklist_lock:
            if client_ip in current_blacklist:
                print(f"BLOCKED POST: {client_ip} - Access Denied")
                self._set_headers(403, 'text/html')
                self.wfile.write(b"<h1>403 Forbidden</h1><p>Access Denied.</p>")
                return

        # Proxy CDN-owned paths for POST (auth, api, share uploads, etc.)
        _clean_post = self.path.split('?')[0]
        if any(_clean_post == p.rstrip('/') or _clean_post.startswith(p) for p in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'POST')

        if self.path == '/upload':
            message = ""
            status = "error"
            try:
                # Parse the form data using werkzeug (cgi module was removed in Python 3.13+)
                environ = {
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                    'CONTENT_LENGTH': int(self.headers.get('Content-Length', 0)),
                    'wsgi.input': self.rfile,
                }
                stream, form, files = parse_form_data(environ)

                # --- CAPTCHA Verification ---
                captcha_id = form.get("captcha_id")
                user_captcha_answer = form.get("captcha_answer")

                if not verify_captcha(captcha_id, user_captcha_answer):
                    message = "CAPTCHA verification failed. Please try again."
                    print(f"Upload failed for {client_ip}: CAPTCHA failed.")
                    self._redirect_with_message('/upload', status, message)
                    return

                # --- File Upload Processing ---
                file_items = files.getlist('file') # werkzeug returns list of FileStorage objects
                if not file_items or not file_items[0]:
                    message = "No file was uploaded or file field is missing."
                    print(f"Upload failed for {client_ip}: {message}")
                    self._redirect_with_message('/upload', status, message)
                    return

                # Get original filename and extension
                file_item = file_items[0]  # werkzeug FileStorage object
                original_filename = os.path.basename(file_item.filename or 'upload')
                file_ext = os.path.splitext(original_filename)[1].lower()

                # --- Security Checks ---
                # 1. Check file extension against whitelist
                if file_ext not in ALLOWED_EXTENSIONS:
                    message = f"File type '{file_ext}' is not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
                    print(f"Upload failed for {client_ip}: Disallowed file type '{file_ext}'.")
                    self._redirect_with_message('/upload', status, message)
                    return

                # 2. Check file size
                file_item.seek(0, os.SEEK_END) # Go to end of file
                file_size = file_item.tell() # Get current position (size)
                file_item.seek(0) # Go back to beginning

                if file_size > MAX_FILE_SIZE:
                    message = f"File size ({file_size / (1024*1024):.2f} MB) exceeds the maximum allowed size ({MAX_FILE_SIZE / (1024*1024):.2f} MB)."
                    print(f"Upload failed for {client_ip}: File too large.")
                    self._redirect_with_message('/upload', status, message)
                    return
                
                # 3. Sanitize filename to prevent path traversal
                # Use uuid to generate a unique filename, preserving the original extension
                safe_filename = str(uuid.uuid4()) + file_ext
                upload_path = os.path.join(UPLOAD_DIRECTORY, safe_filename)

                # Ensure the resolved path is actually within the UPLOAD_DIRECTORY
                # This is a critical security check against path traversal attacks.
                if not os.path.abspath(upload_path).startswith(os.path.abspath(UPLOAD_DIRECTORY)):
                    message = "Attempted path traversal detected. File upload aborted."
                    print(f"Upload failed for {client_ip}: Path traversal attempt.")
                    self._redirect_with_message('/upload', status, message)
                    return

                # 4. Save the file securely
                # Use shutil.copyfileobj for robust file saving
                with open(upload_path, 'wb') as output_file:
                    shutil.copyfileobj(file_item.file, output_file)
                
                message = f"File '{original_filename}' uploaded successfully as '{safe_filename}'."
                status = "success"
                print(f"Upload successful for {client_ip}: '{original_filename}' -> '{safe_filename}'.")

            except Exception as e:
                message = f"An error occurred during upload: {e}"
                print(f"Upload error for {client_ip}: {e}")
            
            self._redirect_with_message('/upload', status, message)
        else:
            # For other POST requests, respond with 404 or a generic message
            self._set_headers(404, 'text/html')
            self.wfile.write(b"<h1>404 Not Found</h1><p>The requested POST resource was not found.</p>")

    def do_DELETE(self):
        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'DELETE', _hp['target'], _hp.get('timeout', 60))
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'DELETE')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PUT(self):
        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'PUT', _hp['target'], _hp.get('timeout', 60))
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'PUT')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PATCH(self):
        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'PATCH', _hp['target'], _hp.get('timeout', 60))
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'PATCH')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_OPTIONS(self):
        """Proxy OPTIONS to CDN for CORS preflight on CDN paths; else 204."""
        _hp = _get_host_proxy(self.headers)
        if _hp:
            return _proxy_to_host(self, 'OPTIONS', _hp['target'], _hp.get('timeout', 60))
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'OPTIONS')
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Token')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Keep-Alive', 'timeout=30, max=100')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _redirect_with_message(self, path, status, message):
        """Helper to redirect the client with status and message parameters."""
        encoded_message = quote_plus(message)
        self.send_response(303) # See Other
        self.send_header('Location', f"{path}?status={status}&message={encoded_message}")
        self.end_headers()

    def log_message(self, format, *args):
        logging.info('HTTPS %s - %s', self.address_string(), format % args)

    def log_error(self, format, *args):
        logging.warning('HTTPS %s - %s', self.address_string(), format % args)


# ---------------------------------------------------------------------------
# High-performance server subclass
#
#   Problem 1 — BrokenPipe / ConnectionReset stack traces
#     These flood the log file via sys.stderr, causing I/O lock contention
#     across all handler threads. They come from BaseServer.handle_error(),
#     not from the handler's log_error(), so overriding log_error() alone
#     does not suppress them. handle_error() on the server is overridden.
#
#   Problem 2 — Thread management strategy
#     ThreadingHTTPServer spawns one OS thread per connection with no limit.
#     A BoundedSemaphore that drops connections at capacity was tried first,
#     but this causes EOF / TCP RST errors on the client: the server closes
#     the socket before responding, which k6 (and real browsers) see as a
#     failure rather than a "server busy, please retry" signal.
#
#     The correct approach for an I/O-bound file server is a thread POOL
#     with a work QUEUE. Workers (threads) are bounded to keep CPU and memory
#     sane. When all workers are busy, new connections wait in the queue
#     instead of being rejected. Latency rises under heavy load, but the
#     client never sees an error — which matches the original behaviour.
#
#     This server is I/O-bound (file reads + socket writes release the GIL),
#     so threads can far outnumber CPU cores without GIL thrashing. 100
#     workers is a safe ceiling for the i5-6006U (2C/4T) while still serving
#     many more than 100 simultaneous connections (extras just queue briefly).
# ---------------------------------------------------------------------------
_MAX_WORKERS = 100  # active worker threads; tune up if you see high queue latency

class _QuietPooledHTTPServer(http.server.HTTPServer):
    """HTTPServer backed by a fixed-size thread pool.
    Connections are never dropped — they queue until a worker is free.
    """
    _SILENT_ERRORS = (BrokenPipeError, ConnectionResetError, ssl.SSLError)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS)

    def handle_error(self, request, client_address):
        """Silence harmless disconnect errors; log everything else normally."""
        if sys.exc_info()[0] in self._SILENT_ERRORS:
            return
        super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        """Hand the accepted socket to the thread pool (never drops it)."""
        self._pool.submit(self._handle_in_pool, request, client_address)

    def _handle_in_pool(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def server_close(self):
        self._pool.shutdown(wait=False)
        super().server_close()


# --- Main Server Logic ---
if __name__ == "__main__":
    sys.stdout = CustomLogger(LOG_FILE_HTTPS)
    sys.stderr = sys.stdout
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')

    raise_fd_limit()  # must be called before accepting connections

    print(f"Serving files from: {os.getcwd()}")
    print(f"Files can be uploaded to: {UPLOAD_DIRECTORY}")

    load_blacklist_safely(BLACKLIST_FILE)

    update_thread = threading.Thread(target=update_blacklist, args=(BLACKLIST_FILE, BLACKLIST_UPDATE_INTERVAL, stop_update_event))
    update_thread.daemon = True
    update_thread.start()

    # Start health check self-ping thread
    health_thread = threading.Thread(target=health_check_self_ping_https, args=(SERVER_IP, HTTPS_PORT))
    health_thread.daemon = True
    health_thread.start()

    httpd = _QuietPooledHTTPServer((SERVER_IP, HTTPS_PORT), RequestHandler)

    # --- SSL Context Setup ---

    # ── Helper: build a fully configured SSLContext ───────────────────────────
    def _make_ssl_context(certfile, keyfile):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        if hasattr(ssl, 'OP_PRIORITIZE_CHACHA'):
            ctx.options |= ssl.OP_PRIORITIZE_CHACHA
        try:
            ctx.set_session_cache_mode(ssl.SESS_CACHE_OFF)
        except AttributeError:
            pass
        ctx.options |= getattr(ssl, 'OP_NO_TICKET', 0)
        try:
            ctx.set_ciphersuites(
                'TLS_CHACHA20_POLY1305_SHA256:'
                'TLS_AES_256_GCM_SHA384:'
                'TLS_AES_128_GCM_SHA256'
            )
        except AttributeError:
            pass
        try:
            ctx.set_ciphers(
                'ECDHE+CHACHA20:ECDHE+AESGCM:DHE+CHACHA20:DHE+AESGCM:'
                '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK'
            )
        except ssl.SSLError as e:
            print(f'WARNING: Could not set TLS 1.2 cipher list: {e}')
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return ctx

    # ── Two contexts: default (uk.to + bare CF domains) and wildcard (*.CF) ──
    _CF_WILDCARD_DOMAINS = {
        'arseniusgen.dev', 'www.arseniusgen.dev',
        'fluxdrop.me',     'www.fluxdrop.me',
    }
    _CF_WILDCARD_SUFFIXES = ('.arseniusgen.dev', '.fluxdrop.me')

    try:
        context      = _make_ssl_context(CERT_FILE,          KEY_FILE)
        wildcard_ctx = _make_ssl_context(WILDCARD_CERT_FILE, WILDCARD_KEY_FILE)
    except FileNotFoundError as e:
        print(f"ERROR: Certificate file not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load SSL certificates: {e}")
        sys.exit(1)

    def _sni_callback(ssl_obj, server_name, base_ctx):
        if server_name is None:
            return  # no SNI — keep default context
        name = server_name.lower()
        if name in _CF_WILDCARD_DOMAINS or any(name.endswith(s) for s in _CF_WILDCARD_SUFFIXES):
            ssl_obj.context = wildcard_ctx

    context.set_servername_callback(_sni_callback)

    try:
        # Defer handshake to the worker threads to prevent main thread blocking
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    except Exception as e:
        print(f"ERROR: Error wrapping socket with SSL: {e}")
        sys.exit(1)

    print(f"Server starting on https://{SERVER_IP}:{HTTPS_PORT}/")
    print("=" * 50)
    
    # Signal the health check thread that the server is actively listening
    server_ready.set()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped. Signaling blacklist update thread to stop...")
        stop_update_event.set()
        update_thread.join(timeout=5)
        if update_thread.is_alive():
            print("Blacklist update thread did not terminate gracefully.")
    except Exception as e:
        print(f"Server error: {e}")
        stop_update_event.set()
        update_thread.join(timeout=5)
