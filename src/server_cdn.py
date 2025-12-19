#!/usr/bin/env python3
import os
import sys
import json
import ssl
import threading
import logging
import re
import shutil
import secrets
import requests
import hashlib
import smtplib
import sqlite3
from werkzeug.formparser import parse_form_data # For parsing multipart/form-data (cgi deprecated in Python 3.13+)
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse, parse_qs
from shared import CustomLogger
from config import SERVE_DIRECTORY, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE_CDN, CDN_UPLOAD_DIR, PUBLIC_DOMAIN

# ==============================================================================
# --- CONFIGURATION ---
# ==============================================================================
# --- Server Settings ---
ALLOWED_ORIGINS = {
    'arseniusgen.uk.to',
    'arsenius-gen.uk.to',
    'arsenius_gen.uk.to',
    '134.249.151.95'
}

# Host/ports
HOST = os.getenv('HOST', '0.0.0.0')
HTTP_PORT = int(os.getenv('HTTP_PORT', '63512'))
HTTPS_PORT = int(os.getenv('HTTPS_PORT', '64800'))

# Public domain and serve root
PUBLIC_DOMAIN = os.getenv('PUBLIC_DOMAIN', PUBLIC_DOMAIN)
# Default server root for CDN: use the larger media volume rather than the TestWeb SSD.
SERVE_ROOT = os.path.abspath(os.getenv('SERVE_ROOT', '/media/arsen/dab4b7b7-8867-4bf3-9304-6fd153c0a028'))
CATBOX_UPLOAD_DIR = os.getenv('CATBOX_UPLOAD_DIR', 'CB_uploads')

# Log & DB paths are imported from config
LOG_FILE = LOG_FILE_CDN

# --- Email Settings (FOR GMAIL APP PASSWORD) ---
# CRITICAL: Fill these out with your Gmail App Password credentials
SMTP_SERVER = os.getenv('SMTP_SERVER', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', os.getenv('SMTP_PORT', '587')))
SMTP_SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL', '')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD', '')

# ==============================================================================
# --- LOGGER SETUP (use shared CustomLogger) ---
# ==============================================================================
# Redirect print/stdout/stderr to our CustomLogger which writes to the log file
sys.stdout = CustomLogger(LOG_FILE)
sys.stderr = sys.stdout
# Configure the logging module to write to stderr (which is now CustomLogger)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)

# ==============================================================================
# --- DATABASE SETUP ---
# ==============================================================================
def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Main users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nickname TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Pending verifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nickname TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                verification_token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        ''')
        # Sessions table for token-based auth
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
    logging.info("Database initialized successfully.")

# ==============================================================================
# --- AUTHENTICATION & USER MANAGEMENT ---
# ==============================================================================
def hash_password(password, salt=None):
    """Hashes a password with a salt. Generates a new salt if one isn't provided."""
    if salt is None:
        salt = secrets.token_hex(16)
    salted_password = (salt + password).encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt

def send_verification_email(email, token):
    """Sends a verification email to the user."""
    if not all([SMTP_SENDER_EMAIL != 'your_email@gmail.com', SMTP_SENDER_PASSWORD != 'your_16_character_app_password']):
        logging.error("SMTP credentials are not configured. Cannot send verification email.")
        # For testing without email, log the link
        logging.info(f"EMAIL SIMULATION: Verification link for {email}: https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/auth/verify?token={token}")
        return True # Pretend it sent successfully

    verification_link = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/auth/verify?token={token}"
    subject = "Verify your FluxDrop Account"
    body = f"""
    Hello,

    Thank you for registering for FluxDrop. Please click the link below to verify your email address:
    {verification_link}

    This link will expire in 1 hour.

    If you did not register for this account, please ignore this email.

    Thanks,
    The FluxDrop Team
    """
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_SENDER_EMAIL
    msg['To'] = email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD)
            server.sendmail(SMTP_SENDER_EMAIL, [email], msg.as_string())
        logging.info(f"Verification email sent to {email}")
        return True
    except Exception as e:
        logging.exception(f"Failed to send verification email to {email}")
        return False

# ==============================================================================
# --- MAIN REQUEST HANDLER ---
# ==============================================================================
class AuthHandler(SimpleHTTPRequestHandler):
    server_version = "FluxDrop/4.0-Auth"
    
    # --- Route Patterns ---
    fluxdrop_api_pattern = re.compile(r'^/api/(v[1-3])/(list|download|upload|delete|rename|versions)(/.*)?$')
    catbox_api_path = '/user/api.php'
    auth_api_pattern = re.compile(r'^/auth/(register|login|logout|verify)$')

    def __init__(self, *args, **kwargs):
        # This is crucial for SimpleHTTPRequestHandler to serve files from the correct directory
        super().__init__(*args, directory=SERVE_ROOT, **kwargs)

    # --- Response Helpers ---
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS, PUT')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type, Range')
        self.send_header('Access-Control-Max-Age', '86400')

    def _send_response(self, status_code, content, content_type='application/json'):
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    # --- Authentication Middleware ---
    def _check_token_auth(self):
        """Checks for a Bearer token and validates it."""
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None # No token provided

        token = auth_header.split(' ', 1)[1]
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP", (token,))
            result = cursor.fetchone()
            if result:
                logging.info(f"Token auth success for user_id '{result[0]}'")
                return result[0] # Return user_id
        
        logging.warning(f"Token auth failed for token '{token}'")
        return None

    # --- Main Router (do_*) ---
    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Routes GET requests to the appropriate handler or serves static files."""
        parsed_url = urlparse(self.path)
        
        # Auth API calls (e.g., /auth/verify)
        auth_match = self.auth_api_pattern.match(parsed_url.path)
        if auth_match:
            command = auth_match.group(1)
            if command == 'verify':
                return self.handle_auth_verify(parsed_url.query)
            else:
                return self._send_response(405, json.dumps({"error": "Method Not Allowed"}))

        # FluxDrop API calls
        flux_match = self.fluxdrop_api_pattern.match(parsed_url.path)
        if flux_match:
            return self.handle_fluxdrop_api_get(flux_match)

        # For any other GET request, assume it's a static file.
        # The base class's do_GET will handle this.
        return super().do_GET()

    def do_POST(self):
        """Routes POST requests to the appropriate handler."""
        parsed_url = urlparse(self.path)

        # Auth API calls
        auth_match = self.auth_api_pattern.match(parsed_url.path)
        if auth_match:
            command = auth_match.group(1)
            content_len = int(self.headers.get('Content-Length', 0))
            post_body = self.rfile.read(content_len)
            data = json.loads(post_body)
            
            if command == 'register':
                return self.handle_auth_register(data)
            if command == 'login':
                return self.handle_auth_login(data)
            if command == 'logout':
                return self.handle_auth_logout()
            return self._send_response(404, json.dumps({"error": "Not Found"}))

        # CatBox API
        if parsed_url.path == self.catbox_api_path:
            return self.handle_catbox_api()

        # FluxDrop API
        flux_match = self.fluxdrop_api_pattern.match(parsed_url.path)
        if flux_match:
            return self.handle_fluxdrop_api_post(flux_match)
            
        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))
        
    # Other methods (PUT, DELETE) would follow a similar pattern, routing to a handler
    # and performing token auth first. I'll implement them within the FluxDrop handler.

    # --- Auth API Handlers ---
    def handle_auth_register(self, data):
        """Handles user registration."""
        username = data.get('username')
        nickname = data.get('nickname')
        email = data.get('email')
        password = data.get('password')

        if not all([username, nickname, email, password]):
            return self._send_response(400, json.dumps({"error": "Missing required fields."}))

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ? OR nickname = ? OR email = ?", (username, nickname, email))
            if cursor.fetchone():
                return self._send_response(409, json.dumps({"error": "Username, nickname, or email already exists."}))

        password_hash, salt = hash_password(password)
        verification_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=1)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO pending_verifications (username, nickname, email, password_hash, salt, verification_token, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, nickname, email, password_hash, salt, verification_token, expires_at)
            )
            conn.commit()

        if send_verification_email(email, verification_token):
            return self._send_response(201, json.dumps({"message": "Registration successful. Please check your email to verify your account."}))
        else:
            return self._send_response(500, json.dumps({"error": "Failed to send verification email."}))

    def handle_auth_verify(self, query_string):
        """Handles email verification from the link."""
        params = parse_qs(query_string)
        token = params.get('token', [None])[0]
        if not token:
            return self._send_response(400, "<h1>Verification Failed</h1><p>No token provided.</p>", 'text/html')

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pending_verifications WHERE verification_token = ? AND expires_at > CURRENT_TIMESTAMP", (token,))
            pending_user = cursor.fetchone()

            if not pending_user:
                return self._send_response(400, "<h1>Verification Failed</h1><p>Invalid or expired token.</p>", 'text/html')
            
            # Transfer user to the main users table
            # pending_user columns: id, username, nickname, email, password_hash, salt, verification_token, expires_at
            cursor.execute(
                "INSERT INTO users (username, nickname, email, password_hash, salt) VALUES (?, ?, ?, ?, ?)",
                (pending_user[1], pending_user[2], pending_user[3], pending_user[4], pending_user[5])
            )
            # Delete from pending table
            cursor.execute("DELETE FROM pending_verifications WHERE verification_token = ?", (token,))
            conn.commit()

        return self._send_response(200, "<h1>Verification Successful!</h1><p>Your account has been verified. You can now log in.</p>", 'text/html')

    def handle_auth_login(self, data):
        """Handles user login and issues a session token."""
        username = data.get('username')
        password = data.get('password')

        if not all([username, password]):
            return self._send_response(400, json.dumps({"error": "Missing username or password."}))

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user:
                return self._send_response(401, json.dumps({"error": "Invalid credentials."}))
            
            user_id, stored_hash, salt = user
            password_hash, _ = hash_password(password, salt)

            if password_hash != stored_hash:
                return self._send_response(401, json.dumps({"error": "Invalid credentials."}))
            
            # Issue a new session token
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(days=7) # Session expires in 7 days
            cursor.execute(
                "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
                (user_id, session_token, expires_at)
            )
            conn.commit()

        return self._send_response(200, json.dumps({"message": "Login successful.", "token": session_token, "username": username}))

    def handle_auth_logout(self):
        """Handles user logout by deleting the session token."""
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return self._send_response(400, json.dumps({"error": "No token provided."}))
        
        token = auth_header.split(' ', 1)[1]
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
            conn.commit()
        
        return self._send_response(200, json.dumps({"message": "Logout successful."}))

    # --- FluxDrop API Handlers ---
    def handle_fluxdrop_api_get(self, match):
        """Handles GET requests for the FluxDrop API."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))

        _, command, path_segment = match.groups()
        relative_path = unquote(path_segment if path_segment else '')
        # sanitize
        base_path = os.path.normpath(os.path.join(SERVE_ROOT, relative_path.lstrip('/')))
        if not os.path.realpath(base_path).startswith(os.path.realpath(SERVE_ROOT)):
            return self._send_response(400, json.dumps({"error": "Invalid path."}))

        if command == 'list':
            # If a file path was provided, list its parent; but better require dir
            target = base_path
            if os.path.isfile(target):
                target = os.path.dirname(target)

            if not os.path.isdir(target):
                return self._send_response(404, json.dumps({"error": "Directory not found."}))

            entries = []
            try:
                for name in sorted(os.listdir(target)):
                    p = os.path.join(target, name)
                    st = os.stat(p)
                    rel = '/' + os.path.relpath(p, SERVE_ROOT).replace(os.sep, '/')
                    entries.append({
                        "name": name,
                        "path": rel,
                        "is_dir": os.path.isdir(p),
                        "size": 0 if os.path.isdir(p) else st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')
                    })
                payload = {
                    "path": '/' + os.path.relpath(target, SERVE_ROOT).replace(os.sep, '/').strip('./'),
                    "entries": entries
                }
                return self._send_response(200, json.dumps(payload))
            except Exception as e:
                logging.exception("List failed")
                return self._send_response(500, json.dumps({"error": f"List failed: {e}"}))

        if command == 'download':
            # Expect base_path points to a file
            if not os.path.isfile(base_path):
                return self._send_response(404, json.dumps({"error": "File not found."}))

            try:
                file_size = os.path.getsize(base_path)
                range_header = self.headers.get('Range')
                self.send_response(206 if range_header else 200)
                self._send_cors_headers()
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(base_path)}"')
                self.send_header('Accept-Ranges', 'bytes')
                if range_header:
                    # Parse "bytes=start-end"
                    m = re.match(r"bytes=(\\d+)-(\\d+)?", range_header)
                    if m:
                        start = int(m.group(1))
                        end = int(m.group(2)) if m.group(2) else file_size - 1
                    else:
                        start, end = 0, file_size - 1
                    start = max(0, min(start, file_size - 1))
                    end = max(start, min(end, file_size - 1))
                    length = end - start + 1
                    self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                    self.send_header('Content-Length', str(length))
                    self.end_headers()
                    with open(base_path, 'rb') as f:
                        f.seek(start)
                        remaining = length
                        bufsize = 2 * 1024 * 1024  # NEW: 2 MB buffer
                        while remaining > 0:
                            chunk = f.read(min(bufsize, remaining))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)
                    return
                else:
                    self.send_header('Content-Length', str(file_size))
                    self.end_headers()
                    with open(base_path, 'rb') as f:
                        shutil.copyfileobj(f, self.wfile)
                    return
            except Exception as e:
                logging.exception("Download failed")
                return self._send_response(500, json.dumps({"error": f"Download failed: {e}"}))

        # Fallback for unimplemented commands
        return self._send_response(501, json.dumps({"message": f"FluxDrop command '{command}' not implemented."}))

    def handle_fluxdrop_api_post(self, match):
        """Handles POST requests for the FluxDrop API (e.g., upload)."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        
        # Your existing FluxDrop POST logic (upload) goes here
        self._send_response(501, json.dumps({"message": "FluxDrop upload not fully implemented in this version."}))
    
    # --- CatBox API Handler ---
    def handle_catbox_api(self):
        """Handles all requests to the CatBox API endpoint."""
        user_id = self._check_token_auth() # Returns user_id or None
        
        # Parse the form data using werkzeug (cgi module was removed in Python 3.13+)
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': self.headers.get('Content-Type', ''),
            'CONTENT_LENGTH': int(self.headers.get('Content-Length', 0)),
            'wsgi.input': self.rfile,
        }
        stream, form, files = parse_form_data(environ)
        reqtype = form.get('reqtype')
        
        # Note: 'userhash' is now ignored in favor of token auth.
        # Anonymous users (no token) can only upload.
        auth_user_display = f"user_id_{user_id}" if user_id else "anonymous"
        logging.info(f"CatBox API request from '{auth_user_display}': reqtype='{reqtype}'")

        if reqtype == 'fileupload':
            return self.handle_catbox_fileupload(files, form, auth_user_display)
        elif reqtype == 'urlupload':
            return self.handle_catbox_urlupload(files, form, auth_user_display)
        elif reqtype == 'deletefiles':
            if not user_id: # Must be authenticated to delete
                return self._send_response(401, "Unauthorized: A valid token is required to delete files.", "text/plain")
            return self.handle_catbox_deletefiles(files, form, auth_user_display)
        else:
            return self._send_response(501, "Album functionality is not implemented.", "text/plain")

    def handle_catbox_fileupload(self, files, form, auth_user_display):
        """Handles CatBox fileupload with streaming to avoid memory issues."""
        file_items = files.getlist('fileToUpload')
        if not file_items:
            return self._send_response(400, "Bad Request: Missing 'fileToUpload' field.", "text/plain")

        file_item = file_items[0]  # werkzeug FileStorage object
        if not file_item or not file_item.filename:
            return self._send_response(400, "Bad Request: No file selected for upload.", "text/plain")

        try:
            file_ext = os.path.splitext(file_item.filename)[1]
            random_name = secrets.token_urlsafe(6).lower().replace('-', '').replace('_', '')
            new_filename = f"{random_name}{file_ext}"
            
            save_path = os.path.normpath(os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR, new_filename))
            if not os.path.realpath(save_path).startswith(os.path.realpath(SERVE_ROOT)):
                return self._send_response(400, "Bad Request: Invalid path.", "text/plain")

            # Ensure upload directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Stream the file in chunks instead of reading all at once
            chunk_size = 2 * 1024 * 1024  # NEW: 2 MB chunks
            bytes_written = 0
            
            with open(save_path, 'wb') as f:
                while True:
                    chunk = file_item.file.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_written += len(chunk)
                    
                    # Optional: Log progress for large files
                    if bytes_written % (100 * 1024 * 1024) == 0:  # Every 100 MB
                        logging.info(f"Upload progress: {bytes_written / (1024*1024):.1f} MB written")

            file_url = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/{CATBOX_UPLOAD_DIR}/{new_filename}"
            logging.info(f"CatBox user '{auth_user_display}' uploaded '{file_item.filename}' ({bytes_written} bytes) to '{save_path}'")
            return self._send_response(200, file_url, "text/plain")

        except Exception as e:
            logging.exception("CatBox fileupload failed.")
            return self._send_response(500, f"Internal Server Error: {e}", "text/plain")

    def handle_catbox_urlupload(self, files, form, auth_user_display):
        """Handles CatBox urlupload."""
        url_to_upload = form.get('url')
        if not url_to_upload:
            return self._send_response(400, "Bad Request: Missing 'url' parameter.", "text/plain")

        try:
            with requests.get(url_to_upload, stream=True) as r:
                r.raise_for_status()
                
                original_filename = os.path.basename(urlparse(url_to_upload).path)
                file_ext = os.path.splitext(original_filename)[1] if original_filename else ''

                random_name = secrets.token_urlsafe(6).lower().replace('-', '').replace('_', '')
                new_filename = f"{random_name}{file_ext}"
                
                save_path = os.path.normpath(os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR, new_filename))
                if not os.path.realpath(save_path).startswith(os.path.realpath(SERVE_ROOT)):
                    return self._send_response(400, "Bad Request: Invalid path.", "text/plain")

                with open(save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            file_url = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/{CATBOX_UPLOAD_DIR}/{new_filename}"
            logging.info(f"CatBox user '{auth_user_display}' uploaded URL '{url_to_upload}' to '{save_path}'")
            self._send_response(200, file_url, "text/plain")

        except Exception as e:
            logging.exception("CatBox urlupload failed.")
            self._send_response(500, f"Internal Server Error: {e}", "text/plain")

    def handle_catbox_deletefiles(self, files, form, auth_user_display):
        """Handles CatBox deletefiles."""
        files_to_delete_str = form.get('files')
        if not files_to_delete_str:
            return self._send_response(400, "Bad Request: Missing 'files' parameter.", "text/plain")

        files = files_to_delete_str.split()
        error_list = []

        for filename in files:
            file_path = os.path.normpath(os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR, filename))
            if not os.path.realpath(file_path).startswith(os.path.realpath(SERVE_ROOT)) or not os.path.isfile(file_path):
                logging.warning(f"CatBox delete failed: File '{filename}' not found.")
                error_list.append(filename)
                continue
            
            try:
                os.remove(file_path)
                logging.info(f"CatBox user '{auth_user_display}' deleted file '{file_path}'")
            except Exception as e:
                logging.exception(f"CatBox delete failed for file '{file_path}'.")
                error_list.append(filename)
        
        if not error_list:
            return self._send_response(200, "Files deleted successfully.", "text/plain")
        else:
            return self._send_response(500, f"Errors deleting files: {', '.join(error_list)}", "text/plain")


# ==============================================================================
# --- SERVER EXECUTION ---
# ==============================================================================
def run_server(port, use_ssl=False):
    """Configures and runs a single server instance (HTTP or HTTPS)."""
    server_address = (HOST, port)
    server = ThreadingHTTPServer(server_address, AuthHandler)
    proto = 'HTTPS' if use_ssl else 'HTTP'
    if use_ssl:
        if not all(os.path.exists(f) for f in [CERT_FILE, KEY_FILE]):
            logging.critical(f"SSL cert/key not found. Cannot start {proto}.")
            return
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except Exception as e:
            logging.critical(f"Fatal error setting up SSL for port {port}: {e}")
            return
    logging.info(f"Starting {proto} server on {HOST}:{port}, serving files from {SERVE_ROOT}")
    try:
        server.serve_forever()
    except Exception as e:
        logging.critical(f"{proto} server on port {port} failed: {e}")
    finally:
        server.server_close()
        logging.info(f"{proto} server on port {port} has shut down.")

if __name__ == '__main__':
    # --- Pre-flight Checks & Setup ---
    init_db() # Initialize the database
    
    # Create necessary directories
    for dir_path in [SERVE_ROOT, os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR)]:
        if not os.path.isdir(dir_path):
            logging.warning(f"Directory '{dir_path}' does not exist. Creating it.")
            try:
                os.makedirs(dir_path)
            except Exception as e:
                logging.critical(f"Could not create directory '{dir_path}': {e}")
                sys.exit(1)

    # --- Start Server Threads ---
    http_thread = threading.Thread(target=run_server, args=(HTTP_PORT, False), name="HTTP-Thread", daemon=True)
    https_thread = threading.Thread(target=run_server, args=(HTTPS_PORT, True), name="HTTPS-Thread", daemon=True)
    
    http_thread.start()
    https_thread.start()
    
    try:
        # Keep the main thread alive to handle shutdown
        while http_thread.is_alive() and https_thread.is_alive():
            http_thread.join(timeout=1)
            https_thread.join(timeout=1)
    except KeyboardInterrupt:
        logging.info("Main thread received KeyboardInterrupt. Shutting down.")
    finally:
        logging.info("Shutdown complete.")
