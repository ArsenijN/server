#!/usr/bin/env python3
import http.server
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import os
import sys
from config import SERVE_DIRECTORY, LOG_FILE_HTTP, BLACKLIST_FILE
from config import PUBLIC_DOMAIN as _PUBLIC_DOMAIN
from config import HTTPS_PORT as _HTTPS_PORT
from shared import CustomLogger, load_blacklist_safely, update_blacklist, health_check_self_ping_http, restart_server, raise_fd_limit, \
    current_blacklist, blacklist_lock, stop_update_event, server_ready
import datetime
import logging # Using standard logging module for better control
import urllib.request as _urllib_req
import urllib.error   as _urllib_err
import posixpath as _psp
import re
import socket

HTTP_PORT = int(os.getenv('HTTP_PORT', os.getenv('SERVER_PORT', '8080')))
SERVER_IP = os.getenv('SERVER_IP', '0.0.0.0')
BLACKLIST_UPDATE_INTERVAL = 60 # seconds

# Port of the CDN server's plain-HTTP loopback listener (CDN_INTERNAL_PORT).
# Must NOT be the HTTP server's own port — that creates an infinite proxy loop.
CDN_HTTP_PORT = int(os.getenv('CDN_HTTP_PORT', '64799'))

# Auth/API paths carry credentials — never proxy them over plaintext.
# These are redirected 308 to HTTPS so the browser retries safely.
# All other CDN paths (share links, status page, downloads) continue to proxy
# so that old/embedded clients that lack TLS can still fetch public content.
_HTTPS_REDIRECT_PREFIXES = ('/api/', '/auth/')

# Root domains whose non-CDN HTTP traffic should be silently upgraded to HTTPS.
# fluxdrop.me/.me TLD supports HTTP so we need to handle it here.
# arseniusgen.dev is intentionally omitted — .dev TLD enforces HTTPS at the
# HSTS preload list level, so the browser never sends plain HTTP to that domain.
_ROOT_HTTPS_DOMAINS = frozenset({'fluxdrop.me', 'www.fluxdrop.me'})

# --- CDN reverse proxy (HTTP) ---
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

def _proxy_to_cdn_http(handler, method: str = 'GET'):
    """Forward request to the CDN HTTP listener on the loopback interface."""
    _HOP_BY_HOP = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade', 'host',
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
        'date',
        'server',
    })
    _PROXY_BUF = 256 * 1024   # 256 KiB — matches the HTTPS proxy
    target = f"http://127.0.0.1:{CDN_HTTP_PORT}{handler.path}"
    body = None
    cl = handler.headers.get('Content-Length')
    if cl and int(cl) > 0:
        body = handler.rfile.read(int(cl))
    req = _urllib_req.Request(target, data=body, method=method)
    for k, v in handler.headers.items():
        if k.lower() not in _HOP_BY_HOP:
            try:
                req.add_header(k, v)
            except Exception:
                pass
    req.add_header('X-Forwarded-For', handler.client_address[0])
    try:
        with _urllib_req.urlopen(req, timeout=60) as resp:
            handler.send_response(resp.status)
            # Forward Content-Length so the browser knows when the response ends.
            # Omitting it with HTTP/1.1 keep-alive causes NS_ERROR_NET_TIMEOUT.
            for k, v in resp.headers.items():
                if k.lower() not in _HOP_BY_HOP | _DEDUP_FROM_UPSTREAM:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            handler._proxying = True
            handler.end_headers()
            handler._proxying = False
            # Stream chunk by chunk — never buffer the full body in RAM.
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

def _cache_control_for_path(path: str) -> str:
    """Return the appropriate Cache-Control value for a static file path."""
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

# --- Request Handler ---
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler that includes blacklist checking and CORS support.
    """
    protocol_version = "HTTP/1.1"
    
    def __init__(self, *args, **kwargs):
        # Pass directory to the parent constructor — this is thread-safe.
        # os.chdir() changes the *process-wide* cwd and races under ThreadingHTTPServer.
        super().__init__(*args, directory=SERVE_DIRECTORY, **kwargs)

    def end_headers(self):
        """Inject CORS headers on every response so font files and API assets
        are accessible cross-origin (e.g. HTTP page loading subresources).

        When _proxying is True (set by _proxy_to_cdn_http) we skip injection —
        the CDN already sent its own CORS headers; duplicates break browsers.
        """
        if getattr(self, '_proxying', False):
            super().end_headers()
            return
        try:
            _ext = _psp.splitext(self.path.split('?')[0])[1].lower()
        except Exception:
            _ext = ''
        _FONT_EXTS = {'.woff', '.woff2', '.ttf', '.eot', '.otf'}
        self.send_header('Access-Control-Allow-Origin', '*')
        if _ext in _FONT_EXTS:
            self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
        self.send_header('Access-Control-Allow-Methods',
                         'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, Authorization, Range, X-Requested-With')
        super().end_headers()

    def add_cors_headers(self):
        """
        Adds CORS headers to allow cross-origin requests from any domain.
        """
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Content-Length")
        self.send_header("Access-Control-Max-Age", "86400")  # 24 hours

    def do_OPTIONS(self):
        """
        Handles CORS preflight requests.
        """
        client_ip = self.client_address[0]
        print(f"OPTIONS request from: {client_ip} -> {self.path}")
        
        # Check blacklist
        with blacklist_lock:
            if client_ip in current_blacklist:
                print(f"BLOCKED: {client_ip} - Access Denied")
                self.send_error(403, "Access Denied")
                return
        
        self.send_response(204)  # No Content
        self.add_cors_headers()
        self.end_headers()

    def do_GET(self):
        """
        Handles GET requests. Checks if the client's IP address is in the blacklist.
        If blacklisted, sends a 403 Forbidden response; otherwise, serves the file.
        Supports HTTP Range requests for partial content delivery.
        Always advertises Accept-Ranges support and includes CORS headers.
        """
        # Fast-path health probe — must come first, before blacklist/proxy/static
        # serving. This was missing entirely on the HTTP side (server_https.py
        # has always had it), so every health check fell through to
        # SimpleHTTPRequestHandler's static file lookup, found no file literally
        # named "healthz" in SERVE_DIRECTORY, and legitimately 404'd — which then
        # looked like a failed health check and triggered a restart loop.
        if self.path == '/healthz':
            body = b'ok'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        client_ip = self.client_address[0]
        requested_path = self.path
        print(f"Request from: {client_ip} -> {requested_path}")

        # --- Root-domain: upgrade all non-CDN HTTP traffic to HTTPS ──────────
        # fluxdrop.me has a root-domain SPA rewrite on the HTTPS side.  There is
        # no value serving the app shell over plain HTTP; redirect everything that
        # is not a CDN proxy path (share links, status, downloads — these are kept
        # on HTTP so old/embedded clients without TLS can still reach them).
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        if _host_bare in _ROOT_HTTPS_DOMAINS:
            _clean_rd = requested_path.split('?')[0]
            _is_cdn   = any(
                _clean_rd == p.rstrip('/') or _clean_rd.startswith(p)
                for p in _CDN_PROXY_PREFIXES
            )
            if not _is_cdn:
                _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
                self.send_response(308)
                self.send_header('Location',
                                 f'https://{_host_bare}{_port_suffix}{requested_path}')
                self.send_header('Content-Length', '0')
                self.send_header('Strict-Transport-Security',
                                 'max-age=300; includeSubDomains')
                self.end_headers()
                return

        # --- Redirect auth/API to HTTPS — never proxy credentials in plaintext ---
        # /auth/ and /api/ carry session tokens and passwords; sending them over
        # plain HTTP exposes them to anyone on the network path.  We 308-redirect
        # instead of blocking so the browser retries the exact request over TLS.
        # 308 preserves the HTTP method (POST stays POST, unlike 301/302).
        _clean = requested_path.split('?')[0]
        if any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _HTTPS_REDIRECT_PREFIXES):
            _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
            _location = f'https://{_PUBLIC_DOMAIN}{_port_suffix}{requested_path}'
            self.send_response(308)
            self.send_header('Location', _location)
            self.send_header('Content-Length', '0')
            # HSTS nudge so the browser remembers to use HTTPS next time
            self.send_header('Strict-Transport-Security', 'max-age=300; includeSubDomains')
            self.end_headers()
            return

        # --- Proxy CDN-owned paths to server_cdn.py internally ---
        _clean = requested_path.split('?')[0]
        if any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'GET')

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
                print(f"BLOCKED: {client_ip} - Access Denied")
                self.send_error(403, "Access Denied")
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
                    # Validate range
                    if end:
                        end = int(end)
                    else:
                        end = file_size - 1
                    # RFC 7233: If start > end or start >= file_size, 416
                    if start > end or start >= file_size or end >= file_size:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{file_size}")
                        self.send_header("Accept-Ranges", "bytes")
                        self.add_cors_headers()
                        self.end_headers()
                        return
                    # If the requested range is zero-length, respond with 206 and zero bytes
                    content_length = end - start + 1
                    self.send_response(206)
                    self.send_header("Content-type", self.guess_type(path))
                    self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                    self.send_header("Content-Length", str(content_length))
                    self.send_header("Accept-Ranges", "bytes")
                    self.add_cors_headers()
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
                        self.send_header("Accept-Ranges", "bytes")
                        self.add_cors_headers()
                        self.end_headers()
                        self.wfile.write(b"<h1>404 File not found</h1>")
                    except Exception:
                        pass
                    return
        
        # Fallback to default behavior, but advertise Accept-Ranges and add CORS headers
        def patched_end_headers():
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "keep-alive")
            self.send_header("Keep-Alive", "timeout=30, max=100")
            _cc = _cache_control_for_path(self.path)
            if _cc:
                self.send_header("Cache-Control", _cc)
            self.add_cors_headers()
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
                self.add_cors_headers()
                self.end_headers()
                self.wfile.write(b"<h1>500 Internal Server Error</h1>")
            except Exception:
                pass
        finally:
            self.end_headers = old_end_headers

    def do_HEAD(self):
        """
        Handles HEAD requests and advertises Accept-Ranges support.
        Ensures Content-Length is always set for HTTP/1.1 compliance.
        Includes CORS headers.
        """
        client_ip = self.client_address[0]
        requested_path = self.path

        # --- Root-domain: upgrade all non-CDN HTTP traffic to HTTPS ──────────
        # --- Redirect auth/API to HTTPS — never proxy credentials in plaintext ---
        # --- Proxy CDN-owned paths to server_cdn.py internally ---
        # None of this existed here at all (do_GET/do_POST/do_DELETE/do_PUT/
        # do_PATCH all have it) — every HEAD request just fell straight through
        # to the blacklist/range/static-file logic below, on port 80, with no
        # redirect and no proxy. For an API path like
        # /api/v1/upload_session/config (the client's connectivity probe) that
        # meant a guaranteed 404 from this server's own static-file handler.
        _clean = requested_path.split('?')[0]
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        if _host_bare in _ROOT_HTTPS_DOMAINS:
            _is_cdn = any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _CDN_PROXY_PREFIXES)
            if not _is_cdn:
                _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
                self.send_response(308)
                self.send_header('Location', f'https://{_host_bare}{_port_suffix}{requested_path}')
                self.send_header('Content-Length', '0')
                self.send_header('Strict-Transport-Security', 'max-age=300; includeSubDomains')
                self.end_headers()
                return
        if any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _HTTPS_REDIRECT_PREFIXES):
            _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
            self.send_response(308)
            self.send_header('Location', f'https://{_PUBLIC_DOMAIN}{_port_suffix}{requested_path}')
            self.send_header('Content-Length', '0')
            self.send_header('Strict-Transport-Security', 'max-age=300; includeSubDomains')
            self.end_headers()
            return
        if any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'HEAD')

        with blacklist_lock:
            if client_ip in current_blacklist:
                self.send_response(403)
                self.send_header("Content-type", "text/html")
                self.send_header("Content-Length", str(len(b"<h1>403 Forbidden</h1>Access Denied")))
                self.send_header("Accept-Ranges", "bytes")
                self.add_cors_headers()
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
                        self.add_cors_headers()
                        self.end_headers()
                        return
                    content_length = 0
                    self.send_response(206)
                    self.send_header("Content-type", self.guess_type(path))
                    self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                    self.send_header("Content-Length", str(content_length))
                    self.send_header("Accept-Ranges", "bytes")
                    self.add_cors_headers()
                    self.end_headers()
                    return
                except Exception as e:
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Content-Length", str(len(b"<h1>404 File not found</h1>")))
                    self.send_header("Accept-Ranges", "bytes")
                    self.add_cors_headers()
                    self.end_headers()
                    return
        
        # Fallback to default behavior, but advertise Accept-Ranges, Content-Length, and CORS
        def patched_end_headers():
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "keep-alive")
            self.send_header("Keep-Alive", "timeout=30, max=100")
            _cc = _cache_control_for_path(self.path)
            if _cc:
                self.send_header("Cache-Control", _cc)
            self.add_cors_headers()
            # Content-Length will be set by super().do_HEAD()
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
                self.add_cors_headers()
                self.end_headers()
            except Exception:
                pass
        finally:
            self.end_headers = old_end_headers

    def do_POST(self):
        client_ip = self.client_address[0]
        with blacklist_lock:
            if client_ip in current_blacklist:
                self.send_error(403, "Access Denied")
                return
        _p = self.path.split('?')[0]
        # Root-domain upgrade: fluxdrop.me non-CDN POST → HTTPS
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        if _host_bare in _ROOT_HTTPS_DOMAINS:
            if not any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
                _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
                self.send_response(308)
                self.send_header('Location', f'https://{_host_bare}{_port_suffix}{self.path}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _HTTPS_REDIRECT_PREFIXES):
            _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
            self.send_response(308)
            self.send_header('Location', f'https://{_PUBLIC_DOMAIN}{_port_suffix}{self.path}')
            self.send_header('Content-Length', '0')
            self.send_header('Strict-Transport-Security', 'max-age=300; includeSubDomains')
            self.end_headers()
            return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'POST')
        # Speed-test upload endpoint
        if self.path.startswith('/upload'):
            try:
                cl = int(self.headers.get('Content-Length', 0))
                if cl > 0:
                    self.rfile.read(cl)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.add_cors_headers()
                self.end_headers()
                self.wfile.write(b'{"status":"success"}')
            except Exception:
                self.send_response(500)
                self.end_headers()
            return
        if self.path.startswith('/ping'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.add_cors_headers()
            self.end_headers()
            self.wfile.write(b'pong')
            return
        self.send_response(405)
        self.add_cors_headers()
        self.end_headers()

    def do_DELETE(self):
        _p = self.path.split('?')[0]
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        if _host_bare in _ROOT_HTTPS_DOMAINS:
            if not any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
                _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
                self.send_response(308)
                self.send_header('Location', f'https://{_host_bare}{_port_suffix}{self.path}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _HTTPS_REDIRECT_PREFIXES):
            _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
            self.send_response(308)
            self.send_header('Location', f'https://{_PUBLIC_DOMAIN}{_port_suffix}{self.path}')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'DELETE')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PUT(self):
        _p = self.path.split('?')[0]
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        if _host_bare in _ROOT_HTTPS_DOMAINS:
            if not any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
                _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
                self.send_response(308)
                self.send_header('Location', f'https://{_host_bare}{_port_suffix}{self.path}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _HTTPS_REDIRECT_PREFIXES):
            _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
            self.send_response(308)
            self.send_header('Location', f'https://{_PUBLIC_DOMAIN}{_port_suffix}{self.path}')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'PUT')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PATCH(self):
        _p = self.path.split('?')[0]
        _host_bare = self.headers.get('Host', '').split(':')[0].lower()
        if _host_bare in _ROOT_HTTPS_DOMAINS:
            if not any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
                _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
                self.send_response(308)
                self.send_header('Location', f'https://{_host_bare}{_port_suffix}{self.path}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _HTTPS_REDIRECT_PREFIXES):
            _port_suffix = f':{_HTTPS_PORT}' if _HTTPS_PORT != 443 else ''
            self.send_response(308)
            self.send_header('Location', f'https://{_PUBLIC_DOMAIN}{_port_suffix}{self.path}')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'PATCH')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, format, *args):
        logging.info('HTTP %s - %s', self.address_string(), format % args)

    def log_error(self, format, *args):
        logging.warning('HTTP %s - %s', self.address_string(), format % args)


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
    _SILENT_ERRORS = (BrokenPipeError, ConnectionResetError)

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
    sys.stdout = CustomLogger(LOG_FILE_HTTP)
    sys.stderr = sys.stdout  # share the same instance — two separate instances = double writes

    raise_fd_limit()  # must be called before accepting connections

    print(f"Serving files from: {os.getcwd()}")

    load_blacklist_safely(BLACKLIST_FILE)

    update_thread = threading.Thread(target=update_blacklist, args=(BLACKLIST_FILE, BLACKLIST_UPDATE_INTERVAL, stop_update_event))
    update_thread.daemon = True
    update_thread.start()

    # Start health check self-ping thread
    health_thread = threading.Thread(target=health_check_self_ping_http, args=(SERVER_IP, HTTP_PORT))
    health_thread.daemon = True
    health_thread.start()

    httpd = _QuietPooledHTTPServer((SERVER_IP, HTTP_PORT), RequestHandler)

    print(f"HTTP Server starting on http://{SERVER_IP}:{HTTP_PORT}/")
    print("CORS enabled for all origins")
    print("=" * 50)

    try:
        # Start the server in a separate thread
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        # Give server time to start
        time.sleep(2)
        
        # Test if server is actually listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = sock.connect_ex((SERVER_IP, HTTP_PORT))
            if result == 0:
                print("Server is listening on the port")
                server_ready.set()  # Signal that server is ready
            else:
                print(f"Server is not listening on port {HTTP_PORT}")
        finally:
            sock.close()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nServer stopped. Signaling blacklist update thread to stop...")
        stop_update_event.set()
        update_thread.join(timeout=5)
        if update_thread.is_alive():
            print("Blacklist update thread did not terminate gracefully.")
        httpd.shutdown()
        httpd.server_close()
    except Exception as e:
        print(f"Server error: {e}")
        stop_update_event.set()
        update_thread.join(timeout=5)
        if httpd:
            httpd.shutdown()
            httpd.server_close()