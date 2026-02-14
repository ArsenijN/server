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
    'www.arseniusgen.uk.to',
    'arsenius-gen.uk.to',
    'arsenius_gen.uk.to',
    '134.249.151.95',
    'localhost'
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

# When the server starts we load any environment-style key/value pairs from a
# file in the secrets directory so that credentials can live on disk but never
# be checked in.  This is what you asked for:
#
#   /home/arsen/servers/self-host/site/Web/secrets/smtp.env
#
# The file should contain lines like "SMTP_SERVER=smtp.gmail.com" etc.  You can
# put additional variables there later for other secrets, they will all be
# injected into os.environ before we read them below.

from config import SECRETS_DIR

def _load_env_file(path):
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, val = line.split('=', 1)
                # do not overwrite existing environment vars
                os.environ.setdefault(key.strip(), val.strip())
    except FileNotFoundError:
        # it's fine if the file does not exist yet
        pass

# try common names; user can create one locally
_load_env_file(os.path.join(SECRETS_DIR, 'smtp.env'))
_load_env_file(os.path.join(SECRETS_DIR, 'credentials_local.env'))

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
    logging.info(f"Using DB_FILE={DB_FILE}")
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
        # Table to mark files as protected and optionally store a hashed access token
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protected_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relative_path TEXT UNIQUE NOT NULL,
                protected INTEGER DEFAULT 0,
                token_hash TEXT,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        # Record CDN upload metadata so we can later show who uploaded each file.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cdn_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT UNIQUE NOT NULL,
                uploaded_by INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by) REFERENCES users (id)
            )
        ''')
        conn.commit()
    logging.info("Database initialized successfully.")


def _is_file_protected(relative_path):
    """Returns True if the file (relative to SERVE_ROOT, leading slash) is marked protected."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT protected FROM protected_files WHERE relative_path = ?", (relative_path,))
        r = cursor.fetchone()
        return bool(r and r[0])


def _check_token_for_file(relative_path, token):
    """Checks whether the provided token (plain) matches the stored hash for the file."""
    if not token:
        return False
    h = hashlib.sha256(token.encode('utf-8')).hexdigest()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT token_hash FROM protected_files WHERE relative_path = ? AND protected = 1", (relative_path,))
        r = cursor.fetchone()
        if not r or not r[0]:
            return False
        return h == r[0]


def _mark_file_protected(relative_path, created_by=None):
    """Marks a file as protected in the DB. Does not generate a token (token can be generated by admin CLI)."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO protected_files (relative_path, protected, created_by) VALUES (?, 1, ?) ON CONFLICT(relative_path) DO UPDATE SET protected=1, created_by=excluded.created_by",
            (relative_path, created_by)
        )
        conn.commit()


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

def send_verification_email(email, token, username):
    """Sends a verification email to the user.

    The function can operate in three modes:
    1. **Simulation** – when SMTP settings are missing or explicitly
       left as placeholders.  In this case we log the verification link and
       return ``True`` so the caller treats the address as "sent".
    2. **Real send** – when all SMTP parameters are present.  A failure
       during the SMTP transaction is logged but does **not** cause the
       registration to fail; we fall back to simulation in that scenario.
    3. **Error** – only if an unexpected exception occurs *outside* the
       SMTP block (such as formatting the message) will we return ``False``.
    """
    verification_link = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/auth/verify?token={token}"

    # If essential SMTP configuration is missing, simulate and log.
    if not SMTP_SERVER or not SMTP_SENDER_EMAIL or not SMTP_SENDER_PASSWORD:
        logging.error("SMTP configuration incomplete; simulating verification email.")
        logging.info(f"EMAIL SIMULATION: Verification link for {email}: {verification_link}")
        return True

    # Compose the message once, regardless of send outcome.
    subject = "Verify your FluxDrop Account"
    # send an HTML email so we can display the logo inline.
    body = f"""
    <html><body>
    <p><img src=\"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/fluxdrop_pp/icon.svg\" alt=\"FluxDrop logo\" width=\"64\"></p>
    <p>Hello {username},</p>
    <p>Thank you for registering for FluxDrop. Please click the link below to verify your email address:</p>
    <p><a href=\"{verification_link}\">{verification_link}</a></p>
    <p>This link will expire in 1 hour.</p>
    <p>If you did not register for this account, please ignore this email.</p>
    <p>Thanks,<br>The FluxDrop Team</p>
    </body></html>
    """
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = SMTP_SENDER_EMAIL
    msg['To'] = email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # ensure connection established
            server.ehlo()
            if SMTP_PORT == 587:
                server.starttls()
                server.ehlo()
            server.login(SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD)
            server.sendmail(SMTP_SENDER_EMAIL, [email], msg.as_string())
        logging.info(f"Verification email sent to {email}")
        return True
    except Exception:
        # don't let SMTP errors interrupt registration flow; log and simulate
        logging.exception(f"Failed to send verification email to {email}, falling back to simulation")
        logging.info(f"EMAIL SIMULATION: Verification link for {email}: {verification_link}")
        return True

# ==============================================================================
# --- MAIN REQUEST HANDLER ---
# ==============================================================================
class AuthHandler(SimpleHTTPRequestHandler):
    server_version = "FluxDrop/4.0-Auth"
    
    # --- Route Patterns ---
    # Add mkdir to supported FluxDrop commands
    fluxdrop_api_pattern = re.compile(r'^/api/(v[1-3])/(list|download|upload|delete|rename|mkdir|versions)(/.*)?$')
    catbox_api_path = '/user/api.php'
    auth_api_pattern = re.compile(r'^/auth/(register|login|logout|verify)$')

    def __init__(self, *args, **kwargs):
        # This is crucial for SimpleHTTPRequestHandler to serve files from the correct directory
        super().__init__(*args, directory=SERVE_ROOT, **kwargs)

    # --- Response Helpers ---
    def _send_cors_headers(self):
        """Send CORS headers. If an Origin header is present and allowed, echo it and allow credentials.
        Otherwise fall back to wildcard for simple requests.
        """
        origin = self.headers.get('Origin')
        allowed = False
        if origin:
            try:
                parsed = urlparse(origin)
                origin_host = parsed.hostname
            except Exception:
                origin_host = None
            if origin_host and origin_host in ALLOWED_ORIGINS:
                self.send_header('Access-Control-Allow-Origin', origin)
                # Allow cookies/authorization headers when origin is explicit
                self.send_header('Access-Control-Allow-Credentials', 'true')
                allowed = True

        if not allowed:
            # Fallback (useful for simple anonymous requests)
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
        """Checks for a Bearer token and validates it.

        The token may be supplied either as an "Authorization: Bearer ..." header
        (preferred) or as a ``?token=...`` query parameter which is useful for
        downloads opened in a new tab where headers are not preserved.
        """
        # First try header
        auth_header = self.headers.get('Authorization')
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
        else:
            # fallback: check query string
            parsed = urlparse(self.path)
            token = parse_qs(parsed.query).get('token', [None])[0]
        if not token:
            return None # No token provided

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP", (token,))
            result = cursor.fetchone()
            if result:
                logging.info(f"Token auth success for user_id '{result[0]}'")
                return result[0] # Return user_id
        
        logging.warning(f"Token auth failed for token '{token}'")
        return None

    # --- Static file protection enforcement ---
    def send_head(self):
        """Override send_head to enforce token checks for protected static files.
        We expect a token in the URL query as ?token=...
        """
        # Parse path and possible query string
        parsed = urlparse(self.path)
        filepath = self.translate_path(parsed.path)

        # If the path is a file under SERVE_ROOT, check protection
        if os.path.isfile(filepath):
            rel = '/' + os.path.relpath(filepath, SERVE_ROOT).replace(os.sep, '/')
            try:
                if _is_file_protected(rel):
                    params = parse_qs(parsed.query)
                    token = params.get('token', [None])[0]
                    if not _check_token_for_file(rel, token):
                        # Deny access
                        self.send_response(403)
                        self._send_cors_headers()
                        self.send_header('Content-Type', 'text/html')
                        self.end_headers()
                        self.wfile.write(b"<h1>403 Forbidden</h1><p>This file requires a valid access token.</p>")
                        return None
            except Exception:
                logging.exception("Error checking file protection")
                self.send_response(500)
                self._send_cors_headers()
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>500 Internal Server Error</h1>")
                return None

        # Fall back to default behavior
        return super().send_head()

    # --- Main Router (do_*) ---
    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_HEAD(self):
        # Ensure CORS and Accept-Ranges headers are present on HEAD responses
        def patched_end_headers():
            self.send_header('Accept-Ranges', 'bytes')
            self._send_cors_headers()
            super(AuthHandler, self).end_headers()

        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            return super().do_HEAD()
        finally:
            self.end_headers = old_end_headers

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
        # Patch end_headers to include CORS and Accept-Ranges, then call base handler.
        def patched_end_headers():
            self.send_header('Accept-Ranges', 'bytes')
            self._send_cors_headers()
            super(AuthHandler, self).end_headers()

        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            return super().do_GET()
        finally:
            self.end_headers = old_end_headers

    def do_POST(self):
        """Routes POST requests to the appropriate handler."""
        parsed_url = urlparse(self.path)

        # Auth API calls
        auth_match = self.auth_api_pattern.match(parsed_url.path)
        if auth_match:
            command = auth_match.group(1)
            try:
                # logout doesn't include a JSON body
                if command == 'logout':
                    return self.handle_auth_logout()

                # For register/login we expect a JSON body
                content_len = int(self.headers.get('Content-Length', 0))
                if content_len <= 0:
                    return self._send_response(400, json.dumps({"error": "Empty request body."}))
                post_body = self.rfile.read(content_len)
                try:
                    data = json.loads(post_body)
                except Exception:
                    logging.exception("Failed to parse JSON body for auth endpoint")
                    return self._send_response(400, json.dumps({"error": "Invalid JSON body."}))
                
                if command == 'register':
                    return self.handle_auth_register(data)
                if command == 'login':
                    return self.handle_auth_login(data)
                if command == 'logout':
                    return self.handle_auth_logout()
                return self._send_response(404, json.dumps({"error": "Not Found"}))
            except Exception:
                logging.exception("Unexpected error handling auth request")
                return self._send_response(500, json.dumps({"error": "Internal server error"}))

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
            # Check against confirmed users first
            cursor.execute("SELECT id FROM users WHERE username = ? OR nickname = ? OR email = ?", (username, nickname, email))
            if cursor.fetchone():
                return self._send_response(409, json.dumps({"error": "Username, nickname, or email already exists."}))
            # Also ensure we don't already have a pending verification for the same details
            cursor.execute("SELECT id FROM pending_verifications WHERE username = ? OR nickname = ? OR email = ?", (username, nickname, email))
            if cursor.fetchone():
                return self._send_response(409, json.dumps({"error": "A registration is already pending for that username, nickname or email."}))

        password_hash, salt = hash_password(password)
        verification_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=1)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO pending_verifications (username, nickname, email, password_hash, salt, verification_token, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, nickname, email, password_hash, salt, verification_token, expires_at)
                )
                conn.commit()
            except sqlite3.IntegrityError as ie:
                # This should be rare due to our earlier checks but may occur in race
                logging.warning(f"Integrity error when inserting pending_verification: {ie}")
                return self._send_response(409, json.dumps({"error": "Username, nickname, or email already exists (pending)."}))

        if send_verification_email(email, verification_token, username):
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
                logging.info(f"Login attempt for unknown user: {username}")
                return self._send_response(401, json.dumps({"error": "Invalid credentials."}))
            
            user_id, stored_hash, salt = user
            password_hash, _ = hash_password(password, salt)

            if password_hash != stored_hash:
                logging.info(f"Login failed for user_id={user_id} (username={username}): password mismatch")
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

        # Helper to calculate a user's personal root directory
        def user_base_path_for(user_id):
            return os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))

        # --- Special path: CDN area ---
        # Use "/cdn" prefix to refer to the global CDN upload directory.  The
        # caller must still provide a valid token (i.e. be logged in) but once
        # authenticated any user can browse/download files from the shared CDN
        # volume.  Returned paths keep the "/cdn" prefix so the client can
        # distinguish them from per-user entries.
        if relative_path.startswith('/cdn'):
            cdn_rel = relative_path[len('/cdn'):]
            base_path = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
            # Security: forbid escaping the CDN directory
            if not os.path.realpath(base_path).startswith(os.path.realpath(CDN_UPLOAD_DIR)):
                return self._send_response(400, json.dumps({"error": "Invalid path."}))
        else:
            # Normal per-user FluxDrop paths
            if relative_path.startswith('/') and relative_path.split('/')[1].lower() == 'fluxdrop':
                parts = relative_path.lstrip('/').split('/')
                if len(parts) < 2:
                    return self._send_response(400, json.dumps({"error": "Invalid FluxDrop path."}))
                target_user = parts[1]
                if str(target_user) != str(user_id):
                    return self._send_response(403, json.dumps({"error": "Forbidden: cannot access other user's area."}))
                sub_path = '/' + '/'.join(parts[2:]) if len(parts) > 2 else '/'
                base_path = os.path.normpath(os.path.join(user_base_path_for(user_id), sub_path.lstrip('/')))
            else:
                base_path = os.path.normpath(os.path.join(user_base_path_for(user_id), relative_path.lstrip('/')))

        # For non-CDN requests ensure path stays under the user's FluxDrop tree.
        if not relative_path.startswith('/cdn') and not os.path.realpath(base_path).startswith(os.path.realpath(os.path.join(SERVE_ROOT, 'FluxDrop'))):
            return self._send_response(400, json.dumps({"error": "Invalid path."}))

        # Ensure the user's FluxDrop directory exists (create on first use) to avoid 404 after login
        try:
            user_dir = user_base_path_for(user_id)
            os.makedirs(user_dir, exist_ok=True)
        except Exception:
            logging.exception("Failed to ensure user FluxDrop directory exists")

        if command == 'list':
            # shared helper to produce an entry list for a given root and prefix
            def list_directory(root_dir, prefix=""):
                if os.path.isfile(root_dir):
                    root_dir = os.path.dirname(root_dir)
                if not os.path.isdir(root_dir):
                    return None, None
                entries = []
                for name in sorted(os.listdir(root_dir)):
                    p = os.path.join(root_dir, name)
                    st = os.stat(p)
                    rel = prefix + '/' + os.path.relpath(p, root_dir).replace(os.sep, '/')
                    entries.append({
                        "name": name,
                        "path": rel,
                        "is_dir": os.path.isdir(p),
                        "size": 0 if os.path.isdir(p) else st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')
                    })
                current_rel = prefix + '/' + os.path.relpath(root_dir, root_dir).replace(os.sep, '/').strip('./')
                return current_rel or '/', entries

            # Determine whether this is a CDN path or a user path
            if relative_path.startswith('/cdn'):
                # don't allow anonymous browsing of the CDN tree; require a valid
                # session token.  (Later we may support shared tokens that permit
                # per-file access without revealing the whole directory.)
                if user_id is None:
                    return self._send_response(403, json.dumps({"error": "Authentication required for CDN listing."}))

                # remove leading /cdn for filesystem operations
                cdn_rel = relative_path[len('/cdn'):]
                target = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
                prefix = '/cdn' + ('' if cdn_rel == '' else cdn_rel)
                current, entries = list_directory(target, prefix)
                if entries is None:
                    return self._send_response(404, json.dumps({"error": "Directory not found."}))

                # populate uploader map for CDN files
                uploads = {}
                try:
                    with sqlite3.connect(DB_FILE) as conn2:
                        cur = conn2.cursor()
                        cur.execute(
                            "SELECT filename, users.username FROM cdn_uploads LEFT JOIN users ON cdn_uploads.uploaded_by = users.id"
                        )
                        for fn, uname in cur:
                            uploads[fn] = uname or None
                except Exception:
                    logging.exception("Failed to load CDN uploader info")

                # augment each entry
                for e in entries:
                    if e.get('is_dir'):
                        continue
                    # derive simple filename from path after last slash
                    fname = os.path.basename(e['path'])
                    if fname in uploads:
                        e['uploader'] = uploads[fname]

                payload = {"path": current, "entries": entries}
                return self._send_response(200, json.dumps(payload))
            else:
                # behave as before for per-user area
                target = base_path
                if os.path.isfile(target):
                    target = os.path.dirname(target)
                if not os.path.isdir(target):
                    return self._send_response(404, json.dumps({"error": "Directory not found."}))
                entries = []
                try:
                    user_dir = user_base_path_for(user_id)
                    for name in sorted(os.listdir(target)):
                        p = os.path.join(target, name)
                        st = os.stat(p)
                        rel = '/' + os.path.relpath(p, user_dir).replace(os.sep, '/')
                        entries.append({
                            "name": name,
                            "path": rel,
                            "is_dir": os.path.isdir(p),
                            "size": 0 if os.path.isdir(p) else st.st_size,
                            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')
                        })
                    payload = {
                        "path": '/' + os.path.relpath(target, user_dir).replace(os.sep, '/').strip('./'),
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

            # Determine a normalized relative path for protection checks.  Use
            # "/cdn" prefix for CDN files; otherwise compute relative to SERVE_ROOT
            if relative_path.startswith('/cdn'):
                rel_path_for_db = relative_path  # already begins with /cdn
            else:
                rel_path_for_db = '/' + os.path.relpath(base_path, SERVE_ROOT).replace(os.sep, '/')

            if _is_file_protected(rel_path_for_db):
                parsed = urlparse(self.path)
                token = parse_qs(parsed.query).get('token', [None])[0]
                if not _check_token_for_file(rel_path_for_db, token):
                    return self._send_response(403, json.dumps({"error": "Forbidden: valid token required to download this file."}))

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
        _, command, path_segment = match.groups()
        relative_path = unquote(path_segment if path_segment else '')

        # Determine user root: /FluxDrop/<user_id>/... or user's root if no FluxDrop prefix
        def user_base_path_for(user_id):
            return os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))

        # Target base for operations; allow a special "/cdn" prefix that operates
        # on CDN_UPLOAD_DIR instead of the per-user directory.  The prefix is kept
        # in the API path so clients can tell where the file lives.
        if relative_path.startswith('/cdn'):
            cdn_rel = relative_path[len('/cdn'):]
            base_fs = os.path.normpath(CDN_UPLOAD_DIR)
            target_fs_path = os.path.normpath(os.path.join(base_fs, cdn_rel.lstrip('/')))
        elif relative_path.startswith('/') and relative_path.split('/')[1].lower() == 'fluxdrop':
            # Path is like /FluxDrop/<id>/rest/of/path
            parts = relative_path.lstrip('/').split('/')
            if len(parts) < 2:
                return self._send_response(400, json.dumps({"error": "Invalid FluxDrop path."}))
            target_user = parts[1]
            # Allow only if target_user matches authenticated user_id
            if str(target_user) != str(user_id):
                return self._send_response(403, json.dumps({"error": "Forbidden: cannot access other user's area."}))
            sub_path = '/' + '/'.join(parts[2:]) if len(parts) > 2 else '/'
            base_fs = user_base_path_for(user_id)
            target_fs_path = os.path.normpath(os.path.join(base_fs, sub_path.lstrip('/')))
        else:
            # Default to authenticated user's root
            base_fs = user_base_path_for(user_id)
            target_fs_path = os.path.normpath(os.path.join(base_fs, relative_path.lstrip('/')))

        # Ensure we don't escape serve root (skip check for CDN paths)
        if not relative_path.startswith('/cdn') and not os.path.realpath(target_fs_path).startswith(os.path.realpath(os.path.join(SERVE_ROOT, 'FluxDrop'))):
            return self._send_response(400, json.dumps({"error": "Invalid path."}))

        # Ensure user base exists
        os.makedirs(base_fs, exist_ok=True)

        # Handle commands
        if command == 'upload':
            # Parse multipart form
            # Werkzeug expects WSGI environ values to be strings (not ints).
            # Use the header value verbatim (or empty string) so werkzeug._plain_int
            # can strip() it safely.
            environ = {
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                'CONTENT_LENGTH': self.headers.get('Content-Length', ''),
                'wsgi.input': self.rfile,
            }
            try:
                stream, form, files = parse_form_data(environ)
                file_items = files.getlist('fileToUpload')
                if not file_items:
                    return self._send_response(400, json.dumps({"error": "Missing fileToUpload field."}))
                file_item = file_items[0]
                filename = os.path.basename(file_item.filename)

                # If the client uploaded a placeholder file (used by the UI to create folders),
                # treat the target path as a directory to create and save the placeholder inside it.
                placeholder_names = ('.placeholder', '.create_marker')
                if filename in placeholder_names:
                    # Create the target directory and save the placeholder inside it
                    save_dir = target_fs_path
                    os.makedirs(save_dir, exist_ok=True)
                    save_path = os.path.normpath(os.path.join(save_dir, filename))
                else:
                    # Normal file upload: if target_fs_path is an existing dir, save into it;
                    # otherwise, if target_fs_path appears to be a file path, use its dirname.
                    if os.path.isdir(target_fs_path) or (str(target_fs_path).endswith(os.sep)):
                        save_dir = target_fs_path
                    else:
                        save_dir = os.path.dirname(target_fs_path)
                    os.makedirs(save_dir, exist_ok=True)
                    save_path = os.path.normpath(os.path.join(save_dir, filename))
                if not os.path.realpath(save_path).startswith(os.path.realpath(base_fs)):
                    return self._send_response(400, json.dumps({"error": "Invalid save path."}))
                # werkzeug FileStorage exposes the uploaded stream as .stream
                with open(save_path, 'wb') as f:
                    while True:
                        chunk = file_item.stream.read(2 * 1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)

                # Construct the public URL.  For CDN uploads use the "/cdn" prefix,
                # otherwise use the normal FluxDrop path.
                if relative_path.startswith('/cdn'):
                    # compute the path beneath CDN_UPLOAD_DIR and prefix
                    cdn_rel = os.path.relpath(save_path, CDN_UPLOAD_DIR).replace(os.sep, '/')
                    file_url = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/cdn/{cdn_rel}"
                else:
                    file_url = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/FluxDrop/{user_id}/{os.path.relpath(save_path, base_fs).replace(os.sep, '/')}"
                return self._send_response(200, json.dumps({"message": "Upload successful", "url": file_url}))
            except Exception as e:
                logging.exception("FluxDrop upload failed")
                return self._send_response(500, json.dumps({"error": str(e)}))

        if command == 'delete':
            # Expect JSON body with 'paths': [list of paths relative to user's root]
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    logging.exception('Failed to parse JSON body for delete')
                    return self._send_response(400, json.dumps({"error": "Invalid JSON body."}))

                paths = data.get('paths', []) if isinstance(data, dict) else []
                errors = []
                # strip potential prefix on each path to keep compatibility with
                # previous behaviour and to avoid leaking internal names
                def strip_prefix(p):
                    # handle per-user paths
                    if p.startswith('/FluxDrop/'):
                        parts = p.lstrip('/').split('/', 2)
                        if len(parts) >= 2 and parts[1] == str(user_id):
                            return '/' + parts[2] if len(parts) >= 3 else '/'
                    # strip /cdn prefix for CDN operations
                    if p.startswith('/cdn/') or p == '/cdn':
                        return p[len('/cdn'):]
                    return p

                for p in paths:
                    p_clean = strip_prefix(p)
                    target = os.path.normpath(os.path.join(base_fs, p_clean.lstrip('/')))
                    if not os.path.realpath(target).startswith(os.path.realpath(base_fs)):
                        errors.append(p)
                        continue
                    try:
                        if os.path.isfile(target):
                            os.remove(target)
                        elif os.path.isdir(target):
                            shutil.rmtree(target)
                        else:
                            errors.append(p)
                    except Exception as e:
                        logging.exception(f"Delete failed for {target}")
                        errors.append(p)
                if errors:
                    return self._send_response(500, json.dumps({"error": "Some deletes failed", "failed": errors}))
                return self._send_response(200, json.dumps({"message": "Deleted"}))
            except Exception as e:
                logging.exception("FluxDrop delete failed")
                return self._send_response(500, json.dumps({"error": str(e)}))

        if command == 'rename':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                data = json.loads(body) if body else {}
                old = data.get('old')
                new = data.get('new')
                if not old or not new:
                    return self._send_response(400, json.dumps({"error": "Missing old or new field"}))
                # strip an optional leading /FluxDrop/<user_id> prefix so clients can
                # send either the full returned path or a user-relative path.
                def strip_prefix(p):
                    if p.startswith('/FluxDrop/'):
                        parts = p.lstrip('/').split('/', 2)  # ['FluxDrop','<id>','rest...']
                        if len(parts) >= 2 and parts[1] == str(user_id):
                            return '/' + parts[2] if len(parts) >= 3 else '/'
                    if p.startswith('/cdn/') or p == '/cdn':
                        return p[len('/cdn'):]
                    return p
                old = strip_prefix(old)
                new = strip_prefix(new)
                old_path = os.path.normpath(os.path.join(base_fs, old.lstrip('/')))
                new_path = os.path.normpath(os.path.join(base_fs, new.lstrip('/')))
                if not os.path.realpath(old_path).startswith(os.path.realpath(base_fs)) or not os.path.realpath(new_path).startswith(os.path.realpath(base_fs)):
                    return self._send_response(400, json.dumps({"error": "Invalid path."}))
                # Make sure source exists and we don't attempt a no-op rename.
                if not os.path.exists(old_path):
                    logging.warning(f"Rename failed: source not found {old_path}")
                    return self._send_response(404, json.dumps({"error": "Source not found."}))

                if os.path.abspath(old_path) == os.path.abspath(new_path):
                    logging.info(f"Rename requested with identical source and target: {old_path}")
                    return self._send_response(400, json.dumps({"error": "Old and new paths are identical."}))

                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                os.rename(old_path, new_path)
                return self._send_response(200, json.dumps({"message": "Renamed"}))
            except Exception as e:
                logging.exception("FluxDrop rename failed")
                return self._send_response(500, json.dumps({"error": str(e)}))

        if command == 'mkdir':
            # Create a directory under the authenticated user's base path.
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    logging.exception('Failed to parse JSON body for mkdir')
                    return self._send_response(400, json.dumps({"error": "Invalid JSON body."}))

                path = data.get('path') if isinstance(data, dict) else None
                if not path:
                    return self._send_response(400, json.dumps({"error": "Missing 'path' field."}))
                # Handle both special CDN prefix and absolute FluxDrop paths.
                if isinstance(path, str) and path.startswith('/cdn'):
                    cdn_rel = path[len('/cdn'):]
                    target_dir = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
                elif isinstance(path, str) and path.startswith('/') and path.split('/')[1].lower() == 'fluxdrop':
                    parts = path.lstrip('/').split('/')
                    if len(parts) < 2:
                        return self._send_response(400, json.dumps({"error": "Invalid FluxDrop path."}))
                    target_user = parts[1]
                    if str(target_user) != str(user_id):
                        return self._send_response(403, json.dumps({"error": "Forbidden: cannot create directories in another user's area."}))
                    sub_path = '/' + '/'.join(parts[2:]) if len(parts) > 2 else '/'
                    target_dir = os.path.normpath(os.path.join(user_base_path_for(user_id), sub_path.lstrip('/')))
                else:
                    target_dir = os.path.normpath(os.path.join(base_fs, path.lstrip('/')))

                if not os.path.realpath(target_dir).startswith(os.path.realpath(base_fs)):
                    return self._send_response(400, json.dumps({"error": "Invalid path."}))

                os.makedirs(target_dir, exist_ok=True)
                logging.info(f"Created directory for user {user_id}: {target_dir}")
                # return path relative to the user's root instead of SERVE_ROOT
                if target_dir.startswith(os.path.realpath(CDN_UPLOAD_DIR)) or relative_path.startswith('/cdn'):
                    # report with /cdn prefix
                    rel = os.path.relpath(target_dir, CDN_UPLOAD_DIR).replace(os.sep, '/')
                    path_out = '/cdn/' + rel if rel and rel != '.' else '/cdn'
                else:
                    user_dir = user_base_path_for(user_id)
                    path_out = '/' + os.path.relpath(target_dir, user_dir).replace(os.sep, '/')
                return self._send_response(201, json.dumps({"message": "Directory created", "path": path_out}))
            except Exception as e:
                logging.exception('FluxDrop mkdir failed')
                return self._send_response(500, json.dumps({"error": str(e)}))

        # Not implemented commands
        return self._send_response(501, json.dumps({"message": f"FluxDrop command '{command}' not implemented."}))
    
    # --- CatBox API Handler ---
    def handle_catbox_api(self):
        """Handles all requests to the CatBox API endpoint."""
        user_id = self._check_token_auth() # Returns user_id or None
        
        # Parse the form data using werkzeug (cgi module was removed in Python 3.13+)
        # Werkzeug expects WSGI environ values to be strings (not ints).
        # Use the header value verbatim (or empty string) so werkzeug._plain_int
        # can strip() it safely.
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': self.headers.get('Content-Type', ''),
            'CONTENT_LENGTH': self.headers.get('Content-Length', ''),
            'wsgi.input': self.rfile,
        }
        stream, form, files = parse_form_data(environ)
        reqtype = form.get('reqtype')
        
        # Note: 'userhash' is now ignored in favor of token auth.
        # Anonymous users (no token) can only upload.
        auth_user_display = f"user_id_{user_id}" if user_id else "anonymous"
        logging.info(f"CatBox API request from '{auth_user_display}': reqtype='{reqtype}'")

        if reqtype == 'fileupload':
            return self.handle_catbox_fileupload(files, form, auth_user_display, user_id)
        elif reqtype == 'urlupload':
            return self.handle_catbox_urlupload(files, form, auth_user_display)
        elif reqtype == 'deletefiles':
            if not user_id: # Must be authenticated to delete
                return self._send_response(401, "Unauthorized: A valid token is required to delete files.", "text/plain")
            return self.handle_catbox_deletefiles(files, form, auth_user_display)
        else:
            return self._send_response(501, "Album functionality is not implemented.", "text/plain")

    def handle_catbox_fileupload(self, files, form, auth_user_display, user_id=None):
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

            # If the uploader requested protection, mark the file as protected in the DB.
            # The actual access token is created separately via the admin CLI (generate_token.py).
            protected_flag = form.get('protected') or form.get('require_token')
            if protected_flag and str(protected_flag).lower() in ('1', 'true', 'on'):
                # store relative path with leading slash
                rel = '/' + os.path.relpath(save_path, SERVE_ROOT).replace(os.sep, '/')
                try:
                    _mark_file_protected(rel, created_by=user_id)
                    logging.info(f"Marked uploaded file as protected: {rel} (created_by={user_id})")
                    # Inform the uploader that the file requires a token to be viewed
                    return self._send_response(200, file_url + "\n[PROTECTED] This file requires a token to view. Generate a token using the server CLI.", "text/plain")
                except Exception:
                    logging.exception("Failed to mark file as protected in DB")
                    return self._send_response(500, "Internal Server Error: failed to mark file protected", "text/plain")

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
