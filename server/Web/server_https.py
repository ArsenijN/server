#!/usr/bin/env python3
import http.server
import ssl
import threading
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
from shared import CustomLogger, load_blacklist_safely, update_blacklist, health_check_self_ping_https, restart_server, current_blacklist, blacklist_lock, stop_update_event
from config import SERVE_DIRECTORY, LOG_FILE_HTTPS, BLACKLIST_FILE, CERT_FILE, KEY_FILE, PUBLIC_UPLOAD_DIR as UPLOAD_DIRECTORY, PUBLIC_DOMAIN

# --- Configuration ---
# Read bind IP and SSL port from environment. Default to 0.0.0.0 and non-privileged 8443.
HTTPS_PORT = int(os.getenv('HTTPS_PORT', os.getenv('SSL_PORT', os.getenv('SERVER_PORT', '8443'))))
SERVER_IP = os.getenv('SERVER_IP', '0.0.0.0')
BLACKLIST_UPDATE_INTERVAL = 60 # seconds

# Port of the CDN server (server_cdn.py) — share links redirect there.
CDN_HTTPS_PORT = int(os.getenv('CDN_HTTPS_PORT', '64800'))

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

import urllib.request as _urllib_req
import urllib.error   as _urllib_err

def _proxy_to_cdn(handler, method: str = 'GET'):
    """Forward the current request to the CDN server and stream the response back.

    Works for GET, POST, DELETE, OPTIONS, PUT, PATCH.
    Strips hop-by-hop headers before forwarding and before sending back.
    """
    _HOP_BY_HOP = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade',
        'host',  # we set Host ourselves
    })

    target = f"https://127.0.0.1:{CDN_HTTPS_PORT}{handler.path}"

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
    # Forward the real client IP so CDN logs/blacklist work correctly
    req.add_header('X-Forwarded-For', handler.client_address[0])

    # Use an SSL context that trusts the self-signed cert on the CDN
    import ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    # Stream the response in chunks — never buffer the entire body.
    # This is critical for large file downloads (10-30 GB) where .read()
    # would try to hold the whole file in the server's RAM.
    _PROXY_BUF = 256 * 1024   # 256 KiB read buffer — small enough for low-RAM i3
    try:
        with _urllib_req.urlopen(req, context=ctx, timeout=60) as resp:
            handler.send_response(resp.status)
            _cl = resp.headers.get('Content-Length')
            for k, v in resp.headers.items():
                if k.lower() not in _HOP_BY_HOP:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            handler.end_headers()
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
        try:
            raw = e.read() or b''
        except Exception:
            raw = b''
        try:
            handler.send_response(e.code)
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(raw)))
            handler.end_headers()
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
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    """
    Custom HTTP request handler that includes blacklist checking and file upload capabilities.
    """
    def __init__(self, *args, **kwargs):
        # Ensure the upload directory exists
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
        # Pass directory to the parent constructor — this is thread-safe.
        # os.chdir() changes the *process-wide* cwd and races under ThreadingHTTPServer.
        super().__init__(*args, directory=SERVE_DIRECTORY, **kwargs)

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
        client_ip = self.client_address[0]
        requested_path = self.path
        print(f"Request from: {client_ip} -> {requested_path}")

        # --- Proxy CDN-owned paths to server_cdn.py internally ---
        # Instead of 302-redirecting (which exposes the CDN port to the browser
        # and breaks same-origin CSP), we forward the request to the CDN server
        # on the loopback interface and stream the response back transparently.
        # The browser always sees one origin (this server's port) — no CSP issues.
        _clean = requested_path.split('?')[0]
        if any(_clean == p.rstrip('/') or _clean.startswith(p) for p in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'GET')

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
            import posixpath as _pp
            _ext = _pp.splitext(_clean_path)[1].lower()
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
            import re
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
                            self.wfile.write(data)
                            bytes_left -= len(data)
                    return
                except Exception as e:
                    print(f"Error serving range: {e}")
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Content-Length", str(len(b"<h1>404 File not found</h1>")))
                    self.send_header("Accept-Ranges", "bytes")
                    self.end_headers()
                    self.wfile.write(b"<h1>404 File not found</h1>")
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
            # Cache-Control by file type:
            #   index.html       → no-cache (always revalidate so deploys are instant)
            #   fonts/woff/woff2 → 1 year immutable (content never changes)
            #   other assets     → 1 hour, must-revalidate (Last-Modified handles 304)
            import posixpath as _psp
            _ext = _psp.splitext(self.path.split('?')[0])[1].lower()
            _base = _psp.basename(self.path.split('?')[0]).lower()
            if _base in ('index.html', 'index.htm'):
                self.send_header("Cache-Control", "no-cache")
            elif _ext in ('.woff', '.woff2', '.ttf', '.eot', '.otf'):
                self.send_header("Cache-Control", "max-age=31536000, immutable")
            elif _ext in ('.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico'):
                self.send_header("Cache-Control", "max-age=86400")
            elif _ext in ('.css', '.js', '.map'):
                self.send_header("Cache-Control", "max-age=3600, must-revalidate")
            super(RequestHandler, self).end_headers()
        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            super().do_GET()
        except Exception as e:
            print(f"Error in default GET handler: {e}")
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(b"<h1>500 Internal Server Error</h1>")))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            self.wfile.write(b"<h1>500 Internal Server Error</h1>")
        finally:
            self.end_headers = old_end_headers

    def do_HEAD(self):
        client_ip = self.client_address[0]
        requested_path = self.path
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
            import re
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
            import posixpath as _psp
            _ext = _psp.splitext(self.path.split('?')[0])[1].lower()
            _base = _psp.basename(self.path.split('?')[0]).lower()
            if _base in ('index.html', 'index.htm'):
                self.send_header("Cache-Control", "no-cache")
            elif _ext in ('.woff', '.woff2', '.ttf', '.eot', '.otf'):
                self.send_header("Cache-Control", "max-age=31536000, immutable")
            elif _ext in ('.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico'):
                self.send_header("Cache-Control", "max-age=86400")
            elif _ext in ('.css', '.js', '.map'):
                self.send_header("Cache-Control", "max-age=3600, must-revalidate")
            super(RequestHandler, self).end_headers()
        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            super().do_HEAD()
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", str(len(b"<h1>500 Internal Server Error</h1>")))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
        finally:
            self.end_headers = old_end_headers

    def do_POST(self):
        """
        Handles POST requests, primarily for file uploads.
        Includes security checks and CAPTCHA verification.
        """
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
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'DELETE')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PUT(self):
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'PUT')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PATCH(self):
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn(self, 'PATCH')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_OPTIONS(self):
        """Proxy OPTIONS to CDN for CORS preflight on CDN paths; else 204."""
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
        """
        Overrides the default log_message to route logs through our custom logger.
        """
        # This message will be routed through our CustomLogger due to sys.stdout/stderr redirect
        print(f"HTTPS: {format % args}")

# --- Main Server Logic ---
if __name__ == "__main__":
    sys.stdout = CustomLogger(LOG_FILE_HTTPS)
    sys.stderr = CustomLogger(LOG_FILE_HTTPS)

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

    httpd = http.server.ThreadingHTTPServer((SERVER_IP, HTTPS_PORT), RequestHandler)

    # --- SSL Context Setup ---
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"ERROR: SSL certificate or key file not found. Please ensure '{CERT_FILE}' and '{KEY_FILE}' exist.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Error loading SSL certificate chain: {e}")
        sys.exit(1)

    try:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    except Exception as e:
        print(f"ERROR: Error wrapping socket with SSL: {e}")
        sys.exit(1)

    print(f"Server starting on https://{SERVER_IP}:{HTTPS_PORT}/")
    print("=" * 50)

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
