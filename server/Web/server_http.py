#!/usr/bin/env python3
import http.server
import threading
import time
import os
import sys
from config import SERVE_DIRECTORY, LOG_FILE_HTTP, BLACKLIST_FILE
from shared import CustomLogger, load_blacklist_safely, update_blacklist, health_check_self_ping_http, restart_server, current_blacklist, blacklist_lock, stop_update_event, server_ready
import datetime
import logging # Using standard logging module for better control
HTTP_PORT = int(os.getenv('HTTP_PORT', os.getenv('SERVER_PORT', '8080')))
SERVER_IP = os.getenv('SERVER_IP', '0.0.0.0')
BLACKLIST_UPDATE_INTERVAL = 60 # seconds

# Port of the CDN server HTTP listener — share links redirect there when
# the user visits over plain HTTP (rare, but handled gracefully).
CDN_HTTP_PORT = int(os.getenv('CDN_HTTP_PORT', '63512'))
# PUBLIC_DOMAIN is used to build the redirect URL
from config import PUBLIC_DOMAIN as _PUBLIC_DOMAIN

 

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

import urllib.request as _urllib_req
import urllib.error   as _urllib_err

def _proxy_to_cdn_http(handler, method: str = 'GET'):
    """Forward request to the CDN HTTP listener on the loopback interface."""
    _HOP_BY_HOP = frozenset({
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailers', 'transfer-encoding', 'upgrade', 'host',
    })
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
    _PROXY_BUF = 256 * 1024
    try:
        with _urllib_req.urlopen(req, timeout=60) as resp:
            handler.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in _HOP_BY_HOP:
                    try:
                        handler.send_header(k, v)
                    except Exception:
                        pass
            handler.end_headers()
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
            handler.send_header('Content-Type', 'application/json')
            handler.send_header('Content-Length', str(len(raw)))
            handler.end_headers()
            handler.wfile.write(raw)
        except Exception:
            pass
    except (BrokenPipeError, ConnectionResetError):
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
        client_ip = self.client_address[0]
        requested_path = self.path
        print(f"Request from: {client_ip} -> {requested_path}")

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
                print(f"BLOCKED: {client_ip} - Access Denied")
                self.send_error(403, "Access Denied")
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
                            self.wfile.write(data)
                            bytes_left -= len(data)
                    return
                except Exception as e:
                    print(f"Error serving range: {e}")
                    # Always send a valid HTTP error response
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Accept-Ranges", "bytes")
                    self.add_cors_headers()
                    self.end_headers()
                    self.wfile.write(b"<h1>404 File not found</h1>")
                    return
        
        # Fallback to default behavior, but advertise Accept-Ranges and add CORS headers
        def patched_end_headers():
            self.send_header("Accept-Ranges", "bytes")
            self.add_cors_headers()
            super(RequestHandler, self).end_headers()
        
        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            super().do_GET()
        except Exception as e:
            print(f"Error in default GET handler: {e}")
            # Always send a valid HTTP error response
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.send_header("Accept-Ranges", "bytes")
            self.add_cors_headers()
            self.end_headers()
            self.wfile.write(b"<h1>500 Internal Server Error</h1>")
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
            self.add_cors_headers()
            # Content-Length will be set by super().do_HEAD()
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
            self.add_cors_headers()
            self.end_headers()
        finally:
            self.end_headers = old_end_headers

    def do_POST(self):
        client_ip = self.client_address[0]
        with blacklist_lock:
            if client_ip in current_blacklist:
                self.send_error(403, "Access Denied")
                return
        _p = self.path.split('?')[0]
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
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'DELETE')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PUT(self):
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'PUT')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PATCH(self):
        _p = self.path.split('?')[0]
        if any(_p == x.rstrip('/') or _p.startswith(x) for x in _CDN_PROXY_PREFIXES):
            return _proxy_to_cdn_http(self, 'PATCH')
        self.send_response(405)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, format, *args):
        print(f"HTTP: {format % args}")

# --- Main Server Logic ---
if __name__ == "__main__":
    sys.stdout = CustomLogger(LOG_FILE_HTTP)
    sys.stderr = CustomLogger(LOG_FILE_HTTP)

    print(f"Serving files from: {os.getcwd()}")

    load_blacklist_safely(BLACKLIST_FILE)

    update_thread = threading.Thread(target=update_blacklist, args=(BLACKLIST_FILE, BLACKLIST_UPDATE_INTERVAL, stop_update_event))
    update_thread.daemon = True
    update_thread.start()

    # Start health check self-ping thread
    health_thread = threading.Thread(target=health_check_self_ping_http, args=(SERVER_IP, HTTP_PORT))
    health_thread.daemon = True
    health_thread.start()

    httpd = http.server.ThreadingHTTPServer((SERVER_IP, HTTP_PORT), RequestHandler)

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
        import socket
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