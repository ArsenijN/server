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
import random # For generating CAPTCHA challenges
import shutil # For securely moving uploaded files
from shared import CustomLogger, load_blacklist_safely, update_blacklist, health_check_self_ping_https, restart_server, current_blacklist, blacklist_lock, stop_update_event
from config import SERVE_DIRECTORY, LOG_FILE_HTTPS, BLACKLIST_FILE, CERT_FILE, KEY_FILE, PUBLIC_UPLOAD_DIR as UPLOAD_DIRECTORY

# --- Configuration ---
# Read bind IP and SSL port from environment. Default to 0.0.0.0 and non-privileged 8443.
HTTPS_PORT = int(os.getenv('HTTPS_PORT', os.getenv('SSL_PORT', os.getenv('SERVER_PORT', '8443'))))
SERVER_IP = os.getenv('SERVER_IP', '0.0.0.0')
BLACKLIST_UPDATE_INTERVAL = 60 # seconds

# --- File Upload Security Settings ---
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5 MB in bytes
ALLOWED_EXTENSIONS = {'.txt', '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip'} # Whitelist of allowed file extensions

# --- CAPTCHA Storage ---
# This dictionary will store CAPTCHA challenges.
# In a real-world scenario, this would be a more robust session management
# or database to prevent memory leaks and ensure persistence.
# Key: CAPTCHA ID (string), Value: Correct Answer (string)
captcha_challenges = {}
captcha_lock = threading.Lock() # Lock for thread-safe access to captcha_challenges

def generate_captcha():
    """Generates a simple math CAPTCHA and stores its answer."""
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operators = ['+', '-', '*']
    operator = random.choice(operators)
    
    question = f"{num1} {operator} {num2}"
    if operator == '+':
        answer = str(num1 + num2)
    elif operator == '-':
        answer = str(num1 - num2)
    else: # '*'
        answer = str(num1 * num2)
    
    captcha_id = str(uuid.uuid4())
    with captcha_lock:
        captcha_challenges[captcha_id] = answer
    return captcha_id, question

def verify_captcha(captcha_id, user_answer):
    """Verifies the user's CAPTCHA answer and removes the challenge."""
    with captcha_lock:
        correct_answer = captcha_challenges.pop(captcha_id, None) # Get and remove
    
    if correct_answer is None:
        print(f"CAPTCHA verification failed: ID '{captcha_id}' not found or already used.")
        return False
    
    if user_answer.strip() == correct_answer:
        print(f"CAPTCHA verified successfully for ID '{captcha_id}'.")
        return True
    else:
        print(f"CAPTCHA verification failed: User answer '{user_answer}' vs correct '{correct_answer}' for ID '{captcha_id}'.")
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
        # Change to the directory we want to serve. This ensures the handler
        # serves files from the correct location regardless of where the script is run.
        os.chdir(SERVE_DIRECTORY)
        super().__init__(*args, **kwargs)

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

    def do_OPTIONS(self):
        """Handles CORS preflight requests."""
        self._set_headers(200) # Respond OK to preflight



    def do_GET(self):
        client_ip = self.client_address[0]
        requested_path = self.path
        print(f"Request from: {client_ip} -> {requested_path}")

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
            self._set_headers(200, 'text/html')
            captcha_id, captcha_question = generate_captcha()
            upload_form_html = f"""
            <!DOCTYPE html>
            <html lang="en">
            ...existing code...
            </html>
            """
            self.wfile.write(upload_form_html.encode('utf-8'))
            return
        def patched_end_headers():
            self.send_header("Accept-Ranges", "bytes")
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

    def _redirect_with_message(self, path, status, message):
        """Helper to redirect the client with status and message parameters."""
        encoded_message = http.server.quote_plus(message)
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
