#!/usr/bin/env python3
import os
import sys
import json
import ssl
import threading
import time
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
        # Short-lived, file-scoped, resumable download tokens.
        # These are separate from session tokens: knowing a session token does NOT
        # grant download access; the client must first call /api/v1/download_token
        # to mint a fresh download token for a specific file.
        # A token stays valid until it expires, enabling Range-based resume after
        # a network interruption.  bytes_confirmed tracks how far a previous
        # transfer reached so the server can hint the safe resume offset.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS download_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                relative_path TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                bytes_confirmed INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Persistent public share links (like Google Drive "anyone with the link").
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                owner_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                is_dir INTEGER DEFAULT 0,
                require_account INTEGER DEFAULT 0,
                track_stats INTEGER DEFAULT 1,
                allow_anon_upload INTEGER DEFAULT 0,
                allow_auth_upload INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT NULL,
                access_count INTEGER DEFAULT 0,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
        ''')
        # Migration: add expires_at column to existing DBs that predate this column.
        try:
            cursor.execute("ALTER TABLE shared_links ADD COLUMN expires_at TIMESTAMP DEFAULT NULL")
            conn.commit()
        except Exception:
            pass  # column already exists
        # Per-access audit log for shared links.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS share_access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                user_id INTEGER,
                action TEXT DEFAULT 'view',
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    logging.info("Database initialized successfully.")


# ==============================================================================
# --- SHARE LINK HELPERS ---
# ==============================================================================

def _create_share(user_id: int, path: str, is_dir: bool, require_account: bool,
                  track_stats: bool, allow_anon_upload: bool, allow_auth_upload: bool,
                  expires_at=None) -> str:
    """Mint a new public share token and store it. Returns the raw token.
    expires_at: ISO datetime string or None for no expiry.
    """
    raw = secrets.token_urlsafe(24)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """INSERT INTO shared_links
               (token, owner_id, path, is_dir, require_account, track_stats,
                allow_anon_upload, allow_auth_upload, created_at, expires_at, access_count)
               VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,0)""",
            (raw, user_id, path, 1 if is_dir else 0,
             1 if require_account else 0, 1 if track_stats else 0,
             1 if allow_anon_upload else 0, 1 if allow_auth_upload else 0,
             expires_at)
        )
        conn.commit()
    return raw


def _get_shares_for_user(user_id: int) -> list:
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """SELECT token, path, is_dir, require_account, track_stats,
                      allow_anon_upload, allow_auth_upload, created_at, expires_at, access_count
               FROM shared_links WHERE owner_id = ? ORDER BY created_at DESC""",
            (user_id,)
        )
        return [dict(r) for r in cur.fetchall()]


def _get_share(token: str) -> dict | None:
    """Return share metadata if token exists and has not expired; else None."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM shared_links WHERE token = ?", (token,))
        r = cur.fetchone()
        if not r:
            return None
        share = dict(r)
        # Enforce optional expiry
        if share.get('expires_at'):
            try:
                exp = datetime.fromisoformat(share['expires_at'])
                if datetime.now() > exp:
                    return None   # treat expired share as non-existent
            except Exception:
                pass
        return share


def _update_share(token: str, owner_id: int, fields: dict):
    allowed = {'require_account', 'track_stats', 'allow_anon_upload', 'allow_auth_upload', 'expires_at'}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    parts = []
    vals = []
    for k, v in updates.items():
        parts.append(f"{k} = ?")
        if k == 'expires_at':
            vals.append(v if v else None)   # store None to remove expiry
        else:
            vals.append(1 if v else 0)
    vals += [token, owner_id]
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute(
            f"UPDATE shared_links SET {', '.join(parts)} WHERE token = ? AND owner_id = ?", vals
        )
        conn.commit()
        return cur.rowcount > 0


def _delete_share(token: str, owner_id: int) -> bool:
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute(
            "DELETE FROM shared_links WHERE token = ? AND owner_id = ?", (token, owner_id)
        )
        conn.commit()
        return cur.rowcount > 0


def _log_share_access(token: str, user_id, action: str = 'view'):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO share_access_log (token, user_id, action, accessed_at) VALUES (?,?,?,CURRENT_TIMESTAMP)",
                (token, user_id, action)
            )
            conn.execute(
                "UPDATE shared_links SET access_count = access_count + 1 WHERE token = ?", (token,)
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to log share access")


def _get_share_stats(token: str, owner_id: int) -> list | None:
    """Return access log for a share the requesting user owns."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Verify ownership
        cur.execute("SELECT id FROM shared_links WHERE token = ? AND owner_id = ?", (token, owner_id))
        if not cur.fetchone():
            return None
        cur.execute(
            """SELECT l.accessed_at, u.username, l.action
               FROM share_access_log l
               LEFT JOIN users u ON l.user_id = u.id
               WHERE l.token = ?
               ORDER BY l.accessed_at DESC LIMIT 200""",
            (token,)
        )
        return [dict(r) for r in cur.fetchall()]


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
# --- DOWNLOAD TOKEN HELPERS ---
# Download tokens are short-lived (default 60 s), file-scoped, and single-use.
# A valid session token alone is NOT sufficient to download a file via HTTP GET;
# the client must call POST /api/v1/download_token with a valid session and the
# target file path to mint a fresh download token, then pass it as ?dl_token=
# within the TTL window.  This ensures session tokens never appear in server
# logs or browser history.
# ==============================================================================
# Tokens are valid for 1 hour so interrupted downloads can resume within that window.
DOWNLOAD_TOKEN_TTL_SECONDS = int(os.getenv("DOWNLOAD_TOKEN_TTL", "3600"))


def _mint_download_token(relative_path: str, user_id: int) -> str:
    """Create and store a resumable download token for *relative_path*.

    The token is valid for DOWNLOAD_TOKEN_TTL_SECONDS (default 1 h).  The same
    token may be reused with HTTP Range requests to resume an interrupted
    download — there is no single-use restriction.  Tokens expire after the TTL
    and are purged by the background worker.
    Returns the raw (unhashed) token string the client should use.
    """
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires_at = datetime.now() + timedelta(seconds=DOWNLOAD_TOKEN_TTL_SECONDS)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO download_tokens (token_hash, relative_path, user_id, expires_at, bytes_confirmed) VALUES (?, ?, ?, ?, 0)",
            (token_hash, relative_path, user_id, expires_at)
        )
        conn.commit()
    return raw


def _validate_download_token(relative_path: str, raw_token: str) -> dict | None:
    """Validate a download token without consuming it.

    Returns a dict with token metadata (including bytes_confirmed) if valid,
    or None if the token is invalid, expired, or does not match the path.
    This allows the same token to be reused for Range-based resume requests.
    """
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, bytes_confirmed FROM download_tokens
               WHERE token_hash = ? AND relative_path = ? AND expires_at > CURRENT_TIMESTAMP""",
            (token_hash, relative_path)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {"id": row[0], "bytes_confirmed": row[1]}


def _update_token_progress(token_id: int, bytes_confirmed: int):
    """Update the bytes_confirmed counter for a download token.

    Called after each successful chunk so that if the connection drops the
    client (and server) both know the safe resume offset.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "UPDATE download_tokens SET bytes_confirmed = ? WHERE id = ?",
                (bytes_confirmed, token_id)
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to update download token progress")


def _purge_expired_download_tokens():
    """Remove expired download tokens. Call periodically to keep the table small."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "DELETE FROM download_tokens WHERE expires_at <= CURRENT_TIMESTAMP"
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to purge expired download tokens")


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
    download_token_pattern = re.compile(r'^/api/(v[1-3])/download_token$')
    shares_list_pattern = re.compile(r'^/api/(v[1-3])/shares$')
    shares_item_pattern = re.compile(r'^/api/(v[1-3])/shares/([A-Za-z0-9_\-]+)$')
    shares_stats_pattern = re.compile(r'^/api/(v[1-3])/shares/([A-Za-z0-9_\-]+)/stats$')
    public_share_pattern = re.compile(r'^/share/([A-Za-z0-9_\-]+)(/.*)?$')
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

        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS, PUT, PATCH')
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

        # Block ALL direct access to /FluxDrop/ — files there must be accessed
        # only through the authenticated /api/ endpoints, never via a bare URL.
        # This prevents directory listing, guessable paths, and token leaks.
        norm_path = parsed.path.rstrip("/")
        if norm_path.lower().startswith("/fluxdrop"):
            self.send_response(403)
            self._send_cors_headers()
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<h1>403 Forbidden</h1><p>Direct access to this area is not permitted. Use the FluxDrop API.</p>"
            )
            return None

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

        # Share stats endpoint (must come before shares_item_pattern)
        stats_match = self.shares_stats_pattern.match(parsed_url.path)
        if stats_match:
            return self.handle_share_stats(stats_match.group(2))

        # Share list endpoint
        if self.shares_list_pattern.match(parsed_url.path):
            return self.handle_shares_list()

        # Public share page / file access
        pub_match = self.public_share_pattern.match(parsed_url.path)
        if pub_match:
            return self.handle_public_share(pub_match.group(1), pub_match.group(2), parsed_url)

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

        # Download-token minting endpoint
        dt_match = self.download_token_pattern.match(parsed_url.path)
        if dt_match:
            return self.handle_mint_download_token()

        # Share list/create
        if self.shares_list_pattern.match(parsed_url.path):
            return self.handle_shares_create()

        # Public share upload: POST /share/<token>/upload
        pub_upload = re.match(r'^/share/([A-Za-z0-9_\-]+)/upload$', parsed_url.path)
        if pub_upload:
            return self.handle_public_share_upload(pub_upload.group(1))

        # CatBox API
        if parsed_url.path == self.catbox_api_path:
            return self.handle_catbox_api()

        # FluxDrop API
        flux_match = self.fluxdrop_api_pattern.match(parsed_url.path)
        if flux_match:
            return self.handle_fluxdrop_api_post(flux_match)

        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    def do_PATCH(self):
        """Routes PATCH requests (used to update share settings)."""
        parsed_url = urlparse(self.path)
        item_match = self.shares_item_pattern.match(parsed_url.path)
        if item_match:
            return self.handle_share_update(item_match.group(2))
        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    def do_DELETE(self):
        """Routes DELETE requests (used to revoke shares)."""
        parsed_url = urlparse(self.path)
        item_match = self.shares_item_pattern.match(parsed_url.path)
        if item_match:
            return self.handle_share_delete(item_match.group(2))
        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

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

    # --- Share API Handlers ---

    def handle_shares_list(self):
        """GET /api/v1/shares — list all shares owned by the authenticated user."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        shares = _get_shares_for_user(user_id)
        return self._send_response(200, json.dumps({"shares": shares}))

    def handle_shares_create(self):
        """POST /api/v1/shares — create a new share link."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body)
        except Exception:
            return self._send_response(400, json.dumps({"error": "Invalid JSON body."}))

        path = data.get("path")
        if not path:
            return self._send_response(400, json.dumps({"error": "Missing 'path' field."}))

        # Normalise and resolve path to ensure it belongs to this user
        if not path.startswith("/"):
            path = "/" + path
        is_dir = bool(data.get("is_dir", False))

        # Verify the file/folder actually exists under the user's area
        user_root = os.path.realpath(os.path.join(SERVE_ROOT, "FluxDrop", str(user_id)))
        if path.startswith("/cdn"):
            fs_path = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, path[len("/cdn"):].lstrip("/")))
            if not os.path.realpath(fs_path).startswith(os.path.realpath(CDN_UPLOAD_DIR)):
                return self._send_response(403, json.dumps({"error": "Forbidden"}))
        else:
            fs_path = os.path.normpath(os.path.join(user_root, path.lstrip("/")))
            if not os.path.realpath(fs_path).startswith(user_root):
                return self._send_response(403, json.dumps({"error": "Forbidden"}))
        if not os.path.exists(fs_path):
            return self._send_response(404, json.dumps({"error": "Path not found."}))

        token = _create_share(
            user_id=user_id,
            path=path,
            is_dir=is_dir,
            require_account=bool(data.get("require_account", False)),
            track_stats=bool(data.get("track_stats", True)),
            allow_anon_upload=bool(data.get("allow_anon_upload", False)),
            allow_auth_upload=bool(data.get("allow_auth_upload", False)),
            expires_at=data.get("expires_at") or None,
        )
        logging.info(f"User {user_id} created share token {token} for path '{path}'")
        return self._send_response(201, json.dumps({"token": token, "path": path}))

    def handle_share_update(self, token: str):
        """PATCH /api/v1/shares/<token> — update settings on an owned share."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body)
        except Exception:
            return self._send_response(400, json.dumps({"error": "Invalid JSON body."}))
        if not _update_share(token, user_id, data):
            return self._send_response(404, json.dumps({"error": "Share not found or not owned by you."}))
        return self._send_response(200, json.dumps({"ok": True}))

    def handle_share_delete(self, token: str):
        """DELETE /api/v1/shares/<token> — revoke a share."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        if not _delete_share(token, user_id):
            return self._send_response(404, json.dumps({"error": "Share not found or not owned by you."}))
        logging.info(f"User {user_id} revoked share token {token}")
        return self._send_response(200, json.dumps({"ok": True}))

    def handle_share_stats(self, token: str):
        """GET /api/v1/shares/<token>/stats — access log for an owned share."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        logs = _get_share_stats(token, user_id)
        if logs is None:
            return self._send_response(404, json.dumps({"error": "Share not found or not owned by you."}))
        return self._send_response(200, json.dumps({"logs": logs}))

    def handle_public_share(self, token: str, sub_path, parsed_url):
        """GET /share/<token>[/sub/path] — public share page or file download."""
        share = _get_share(token)
        if not share:
            return self._send_response(404, "<h1>404 — Share Not Found</h1><p>This link is invalid or has been revoked.</p>", "text/html")

        # Determine the requesting user (may be None for anonymous)
        visitor_user_id = self._check_token_auth()

        # Enforce account requirement
        if share["require_account"] and not visitor_user_id:
            return self._send_response(
                200,
                self._render_share_login_page(token),
                "text/html"
            )

        # Resolve the shared path to a filesystem path for the owner
        owner_id = share["owner_id"]
        base_path_str = share["path"]

        if base_path_str.startswith("/cdn"):
            owner_root = os.path.realpath(CDN_UPLOAD_DIR)
            rel = base_path_str[len("/cdn"):].lstrip("/")
            base_fs = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, rel))
        else:
            owner_root = os.path.realpath(os.path.join(SERVE_ROOT, "FluxDrop", str(owner_id)))
            base_fs = os.path.normpath(os.path.join(owner_root, base_path_str.lstrip("/")))

        # Handle sub-path navigation within a shared folder
        if sub_path and sub_path.strip("/"):
            target_fs = os.path.normpath(os.path.join(base_fs, sub_path.lstrip("/")))
        else:
            target_fs = base_fs

        # Security: stay within the shared base
        if not os.path.realpath(target_fs).startswith(os.path.realpath(base_fs)):
            return self._send_response(403, json.dumps({"error": "Forbidden: path outside shared area."}))

        # --- File download ---
        if os.path.isfile(target_fs):
            if share["track_stats"]:
                _log_share_access(token, visitor_user_id, action="download")
            file_size = os.path.getsize(target_fs)
            range_header = self.headers.get("Range")
            if range_header:
                m = re.match(r'bytes=(\d+)-(\d*)', range_header)
                start = int(m.group(1)) if m else 0
                end = int(m.group(2)) if m and m.group(2) else file_size - 1
                start = max(0, min(start, file_size - 1))
                end = max(start, min(end, file_size - 1))
                length = end - start + 1
                self.send_response(206)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(target_fs)}"')
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(length))
                self.end_headers()
                with open(target_fs, "rb") as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(65536, remaining))
                        if not chunk: break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            else:
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(target_fs)}"')
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(file_size))
                self.end_headers()
                with open(target_fs, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk: break
                        self.wfile.write(chunk)
            return

        # --- Directory listing page ---
        if os.path.isdir(target_fs):
            if share["track_stats"]:
                _log_share_access(token, visitor_user_id, action="view")
            return self._send_response(200, self._render_share_page(share, token, target_fs, base_fs, sub_path or ""), "text/html")

        return self._send_response(404, "<h1>404 — Not Found</h1>", "text/html")

    def _render_share_page(self, share, token, target_fs, base_fs, sub_path):
        """Render the public share HTML page with recursive folder listing."""
        owner_name = ""
        try:
            with sqlite3.connect(DB_FILE) as conn:
                r = conn.execute("SELECT nickname FROM users WHERE id = ?", (share["owner_id"],)).fetchone()
                if r: owner_name = r[0]
        except Exception: pass

        sub_path_clean = (sub_path or "").strip("/")
        visitor_user_id = self._check_token_auth()

        # --- Breadcrumb ---
        crumb_parts = sub_path_clean.split("/") if sub_path_clean else []
        crumbs_html = f'<a href="/share/{token}" style="color:#3b82f6;text-decoration:none">Home</a>'
        for i, part in enumerate(crumb_parts):
            crumb_url = f"/share/{token}/" + "/".join(crumb_parts[:i+1])
            crumbs_html += f' <span style="color:#94a3b8">/</span> <a href="{crumb_url}" style="color:#3b82f6;text-decoration:none">{part}</a>'

        # --- Build entry rows (recursive helper) ---
        def build_rows(directory, indent=0):
            rows = ""
            try:
                names = sorted(os.listdir(directory), key=lambda n: (not os.path.isdir(os.path.join(directory, n)), n.lower()))
            except PermissionError:
                return rows
            for name in names:
                entry_fs = os.path.join(directory, name)
                rel_from_base = os.path.relpath(entry_fs, base_fs).replace(os.sep, "/")
                entry_url = f"/share/{token}/{rel_from_base}"
                st = os.stat(entry_fs)
                mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                pad = indent * 20
                if os.path.isdir(entry_fs):
                    rows += f"""<tr class="entry-row">
                        <td style="padding:8px 12px 8px {12+pad}px">
                            <a href="{entry_url}" style="color:#3b82f6;text-decoration:none;font-weight:500">📁 {name}</a>
                        </td>
                        <td style="padding:8px 12px;color:#94a3b8">—</td>
                        <td style="padding:8px 12px;color:#94a3b8">{mtime}</td>
                        <td style="padding:8px 12px"></td>
                    </tr>"""
                    # If we're viewing this directory or a parent of it, expand its children
                    if sub_path_clean == rel_from_base or sub_path_clean.startswith(rel_from_base + "/"):
                        rows += build_rows(entry_fs, indent + 1)
                else:
                    size_str = f"{st.st_size / 1024:.1f} KB" if st.st_size < 1_048_576 else f"{st.st_size / 1_048_576:.2f} MB"
                    rows += f"""<tr class="entry-row">
                        <td style="padding:8px 12px 8px {12+pad}px">
                            <a href="{entry_url}" download style="color:#1e293b;text-decoration:none">📄 {name}</a>
                        </td>
                        <td style="padding:8px 12px;color:#64748b;font-size:13px">{size_str}</td>
                        <td style="padding:8px 12px;color:#94a3b8;font-size:13px">{mtime}</td>
                        <td style="padding:8px 12px">
                            <a href="{entry_url}" download
                               style="background:#3b82f6;color:white;text-decoration:none;padding:3px 10px;border-radius:5px;font-size:12px">↓</a>
                        </td>
                    </tr>"""
            return rows

        # If we're looking at a sub-folder page, show only its contents; else show full tree from root
        list_root = target_fs if os.path.isdir(target_fs) else base_fs
        if sub_path_clean and os.path.isdir(target_fs):
            entries_html = build_rows(target_fs, indent=0)
            # Back link
            parent_url = ("/share/" + token + "/" + "/".join(crumb_parts[:-1])).rstrip("/") if crumb_parts else f"/share/{token}"
            back_row = f'<tr><td colspan="4" style="padding:6px 12px"><a href="{parent_url}" style="color:#64748b;text-decoration:none;font-size:13px">⬆ Parent folder</a></td></tr>'
            entries_html = back_row + entries_html
        else:
            entries_html = build_rows(base_fs, indent=0)

        if not entries_html:
            entries_html = '<tr><td colspan="4" style="padding:16px;color:#94a3b8;text-align:center">This folder is empty</td></tr>'

        # --- Upload section ---
        upload_section = ""
        if share["allow_anon_upload"] or (share["allow_auth_upload"] and visitor_user_id):
            upload_section = f"""
            <div style="margin-top:24px;padding:16px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px">
                <h3 style="margin:0 0 10px;font-size:15px;color:#166534">Upload files to this folder</h3>
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                    <input type="file" id="upload-file" multiple style="font-size:14px">
                    <button onclick="uploadFiles()"
                        style="background:#16a34a;color:white;border:none;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:14px;flex-shrink:0">
                        Upload
                    </button>
                    <span id="upload-status" style="font-size:13px;color:#166534"></span>
                </div>
                <div id="upload-progress" style="margin-top:8px"></div>
                <script>
                async function uploadFiles(){{
                    const files = document.getElementById('upload-file').files;
                    if(!files.length){{document.getElementById('upload-status').textContent='No files selected';return;}}
                    const statusEl = document.getElementById('upload-status');
                    const progressEl = document.getElementById('upload-progress');
                    statusEl.textContent = `Uploading ${{files.length}} file(s)…`;
                    let done = 0, failed = 0;
                    for(const f of files){{
                        const fd = new FormData(); fd.append('file', f, f.name);
                        progressEl.textContent = `[${{done+failed+1}}/${{files.length}}] ${{f.name}}…`;
                        try{{
                            const r = await fetch('/share/{token}/upload', {{method:'POST', body:fd}});
                            if(r.ok) done++; else failed++;
                        }}catch(e){{ failed++; }}
                    }}
                    statusEl.textContent = `Done: ${{done}} uploaded${{failed ? ', '+failed+' failed' : ''}}`;
                    progressEl.textContent = '';
                    if(done > 0) setTimeout(()=>location.reload(), 1200);
                }}
                </script>
            </div>"""

        # --- Expiry badge ---
        expiry_badge = ""
        if share.get("expires_at"):
            try:
                exp = datetime.fromisoformat(share["expires_at"])
                expiry_badge = f'&nbsp;<span style="background:#fef9c3;color:#854d0e;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600">⏰ Expires {exp.strftime("%Y-%m-%d")}</span>'
            except Exception: pass

        folder_name = os.path.basename(base_fs.rstrip("/")) or "Shared Folder"
        current_title = os.path.basename(target_fs.rstrip("/")) if sub_path_clean else folder_name

        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FluxDrop — {current_title}</title>
<link rel="icon" type="image/svg" sizes="32x32" href="https://arseniusgen.uk.to/fluxdrop_pp/icon.svg">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  *{{box-sizing:border-box}}
  body{{font-family:Inter,sans-serif;background:#f0f9ff;min-height:100vh;margin:0;padding:24px 16px}}
  .card{{background:white;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.10);padding:28px;max-width:900px;margin:0 auto}}
  table{{width:100%;border-collapse:collapse}}
  th{{text-align:left;padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;border-bottom:2px solid #e2e8f0;white-space:nowrap}}
  .entry-row:hover td{{background:#f8fafc}}
  a{{color:inherit}}
  .crumbs{{font-size:13px;color:#64748b;margin-bottom:16px;display:flex;align-items:center;gap:4px;flex-wrap:wrap}}
</style>
</head><body>
<div class="card">
  <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px">
    <div style="font-size:36px;line-height:1">{'📁' if share['is_dir'] else '📄'}</div>
    <div style="flex:1;min-width:0">
      <h1 style="margin:0 0 4px;font-size:20px;font-weight:700;color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{current_title}</h1>
      <div style="font-size:13px;color:#94a3b8">
        Shared by <strong style="color:#475569">{owner_name}</strong>
        {'&nbsp;<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600">🔒 Account required</span>' if share["require_account"] else ''}
        {expiry_badge}
      </div>
    </div>
  </div>

  <div class="crumbs">{crumbs_html}</div>

  <table>
    <thead><tr>
      <th>Name</th><th>Size</th><th>Modified</th><th style="width:50px"></th>
    </tr></thead>
    <tbody>{entries_html}</tbody>
  </table>
  {upload_section}
  <div style="margin-top:20px;padding-top:14px;border-top:1px solid #f1f5f9;font-size:12px;color:#cbd5e1;text-align:center">
    Powered by <a href="https://{PUBLIC_DOMAIN}/fluxdrop_pp/index.html" style="color:#93c5fd;text-decoration:none;font-weight:600">FluxDrop</a>
  </div>
</div>
</body></html>"""

    def _render_share_login_page(self, token):
        cdn_origin = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}"
        share_path = f"/share/{token}"
        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FluxDrop — Login to Access</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box}}
body{{font-family:Inter,sans-serif;background:#f0f9ff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:16px}}
.card{{background:white;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.1);padding:36px;max-width:380px;width:100%;text-align:center}}
input{{width:100%;padding:10px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:14px;font-family:Inter,sans-serif;margin-bottom:10px;outline:none;transition:border .15s}}
input:focus{{border-color:#3b82f6}}
.btn{{width:100%;padding:11px;background:#3b82f6;color:white;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;font-family:Inter,sans-serif}}
.btn:hover{{background:#2563eb}}
.btn:disabled{{background:#93c5fd;cursor:not-allowed}}
.err{{color:#ef4444;font-size:13px;margin-top:6px;min-height:18px}}
</style>
</head><body>
<div class="card">
  <div style="font-size:46px;margin-bottom:12px">🔒</div>
  <h2 style="margin:0 0 6px;color:#1e293b;font-size:20px">Login Required</h2>
  <p style="color:#64748b;font-size:13px;margin:0 0 22px">This shared link requires a FluxDrop account.</p>

  <input type="text"     id="usr" placeholder="Username"  autocomplete="username">
  <input type="password" id="pwd" placeholder="Password"  autocomplete="current-password">
  <button class="btn" id="login-btn" onclick="doLogin()">Login &amp; Continue</button>
  <div class="err" id="err"></div>

  <div style="margin-top:16px;font-size:12px;color:#94a3b8">
    Already logged in on this device?
    <a href="#" onclick="useStoredToken()" style="color:#3b82f6;text-decoration:none">Use saved session</a>
  </div>
</div>

<script>
const CDN = {cdn_origin!r};
const SHARE = {share_path!r};

// If the user already has a valid token in localStorage from the FluxDrop app,
// offer to use it immediately without re-entering credentials.
function useStoredToken() {{
  const t = localStorage.getItem('fluxdrop_token');
  if (!t) {{ document.getElementById('err').textContent = 'No saved session found. Please log in.'; return; }}
  redirect(t);
}}

async function doLogin() {{
  const btn = document.getElementById('login-btn');
  const err = document.getElementById('err');
  const usr = document.getElementById('usr').value.trim();
  const pwd = document.getElementById('pwd').value;
  if (!usr || !pwd) {{ err.textContent = 'Please enter username and password.'; return; }}
  btn.disabled = true; btn.textContent = 'Logging in…'; err.textContent = '';
  try {{
    const r = await fetch(CDN + '/auth/login', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: usr, password: pwd}})
    }});
    const data = await r.json();
    if (!r.ok) {{ err.textContent = data.error || 'Login failed.'; btn.disabled = false; btn.textContent = 'Login & Continue'; return; }}
    // Optionally persist to localStorage so the FluxDrop app also picks it up
    localStorage.setItem('fluxdrop_token', data.token);
    localStorage.setItem('fluxdrop_username', data.username);
    redirect(data.token);
  }} catch(e) {{
    err.textContent = 'Network error: ' + e.message;
    btn.disabled = false; btn.textContent = 'Login & Continue';
  }}
}}

function redirect(token) {{
  // Append token as query param so the server can verify it on the next
  // navigation request (browser page load can't send Authorization headers).
  window.location.href = CDN + SHARE + '?token=' + encodeURIComponent(token);
}}

// Auto-try stored token on page load (silent, no error shown)
(function() {{
  const t = localStorage.getItem('fluxdrop_token');
  if (t) redirect(t);
}})();
</script>
</body></html>"""

    # --- FluxDrop API Handlers ---

    def handle_public_share_upload(self, token: str):
        """POST /share/<token>/upload — anonymous or authenticated upload into a shared folder."""
        share = _get_share(token)
        if not share or not share["is_dir"]:
            return self._send_response(404, json.dumps({"error": "Share not found or not a folder."}))

        visitor_user_id = self._check_token_auth()

        # Permission check
        if share["allow_anon_upload"]:
            pass  # anyone allowed
        elif share["allow_auth_upload"] and visitor_user_id:
            pass  # logged-in user allowed
        else:
            return self._send_response(403, json.dumps({"error": "Uploads not permitted on this share."}))

        # Resolve the shared folder path for the owner
        owner_id = share["owner_id"]
        base_path_str = share["path"]
        if base_path_str.startswith("/cdn"):
            dest_dir = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, base_path_str[len("/cdn"):].lstrip("/")))
        else:
            dest_dir = os.path.normpath(os.path.join(SERVE_ROOT, "FluxDrop", str(owner_id), base_path_str.lstrip("/")))

        if not os.path.isdir(dest_dir):
            return self._send_response(404, json.dumps({"error": "Shared folder not found on disk."}))

        try:
            content_type = self.headers.get("Content-Type", "")
            environ = {
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
                "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                "wsgi.input": self.rfile,
            }
            stream, form, files = parse_form_data(environ)
            file_item = files.get("file")
            if not file_item or not file_item.filename:
                return self._send_response(400, json.dumps({"error": "No file in request."}))

            safe_name = os.path.basename(file_item.filename)
            save_path = os.path.normpath(os.path.join(dest_dir, safe_name))
            if not os.path.realpath(save_path).startswith(os.path.realpath(dest_dir)):
                return self._send_response(400, json.dumps({"error": "Invalid filename."}))

            with open(save_path, "wb") as f:
                while True:
                    chunk = file_item.stream.read(1 * 1024 * 1024)
                    if not chunk: break
                    f.write(chunk)

            if share["track_stats"]:
                _log_share_access(token, visitor_user_id, action="upload")
            logging.info(f"Share upload: token={token} file='{safe_name}' user={visitor_user_id}")
            return self._send_response(200, "OK", "text/plain")
        except Exception as e:
            logging.exception("Public share upload failed")
            return self._send_response(500, json.dumps({"error": str(e)}))

    def handle_mint_download_token(self):
        """POST /api/v1/download_token
        Body (JSON): { "path": "<relative_path_as_returned_by_list>" }

        Requires a valid session token (Bearer or ?token=).  Returns a short-lived
        (DOWNLOAD_TOKEN_TTL_SECONDS), single-use download token bound to the
        requested path.  The caller must use this token via ?dl_token= on the
        /api/v1/download/<path> endpoint within the TTL window.

        Session tokens must NEVER be used directly as ?token= on download URLs —
        this endpoint exists precisely to avoid that.
        """
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body)
        except Exception:
            return self._send_response(400, json.dumps({"error": "Invalid JSON body."}))

        relative_path = data.get("path")
        if not relative_path or not isinstance(relative_path, str):
            return self._send_response(400, json.dumps({"error": "Missing or invalid 'path' field."}))

        # Normalise: must start with /
        if not relative_path.startswith("/"):
            relative_path = "/" + relative_path

        # Resolve the filesystem path using the SAME logic as handle_fluxdrop_api_get
        # so that whatever path format the list API returns is accepted here too.
        #
        # Three supported formats (all returned by the list endpoint):
        #   /cdn/<rest>               → CDN_UPLOAD_DIR/<rest>
        #   /FluxDrop/<user_id>/<rest>→ SERVE_ROOT/FluxDrop/<user_id>/<rest>  (full absolute form)
        #   /<rest>                   → SERVE_ROOT/FluxDrop/<user_id>/<rest>   (user-relative form)

        user_fluxdrop_root = os.path.realpath(
            os.path.join(SERVE_ROOT, "FluxDrop", str(user_id))
        )

        if relative_path.startswith("/cdn"):
            cdn_rel = relative_path[len("/cdn"):].lstrip("/")
            fs_path = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel))
            allowed_root = os.path.realpath(CDN_UPLOAD_DIR)
            # Canonical path stored in DB must match what the download handler expects
            canonical_path = relative_path

        elif relative_path.lower().startswith("/fluxdrop/"):
            # Absolute form: /FluxDrop/<user_id>/rest/of/path
            parts = relative_path.lstrip("/").split("/", 2)  # ['FluxDrop', '<id>', 'rest...']
            if len(parts) < 2 or parts[1] != str(user_id):
                return self._send_response(403, json.dumps({"error": "Forbidden: path belongs to a different user."}))
            sub = parts[2] if len(parts) > 2 else ""
            fs_path = os.path.normpath(os.path.join(SERVE_ROOT, "FluxDrop", str(user_id), sub))
            allowed_root = user_fluxdrop_root
            # Normalise to user-relative form for storage (matches download handler)
            canonical_path = "/" + sub if sub else "/"

        else:
            # User-relative form: /2026 02 22/file.mp4  → FluxDrop/<user_id>/2026 02 22/file.mp4
            fs_path = os.path.normpath(
                os.path.join(SERVE_ROOT, "FluxDrop", str(user_id), relative_path.lstrip("/"))
            )
            allowed_root = user_fluxdrop_root
            canonical_path = relative_path  # already user-relative

        if not os.path.realpath(fs_path).startswith(allowed_root):
            return self._send_response(403, json.dumps({"error": "Forbidden: path outside your accessible area."}))

        # Use the canonical path as the token key so download validation matches
        relative_path = canonical_path

        if not os.path.isfile(fs_path):
            return self._send_response(404, json.dumps({"error": "File not found."}))

        raw_token = _mint_download_token(relative_path, user_id)
        _purge_expired_download_tokens()  # opportunistic housekeeping

        # Stat the file so the client knows total size for progress display
        try:
            total_size = os.path.getsize(fs_path)
        except Exception:
            total_size = None

        return self._send_response(200, json.dumps({
            "download_token": raw_token,
            "path": relative_path,
            "expires_in": DOWNLOAD_TOKEN_TTL_SECONDS,
            "total_size": total_size,
            "bytes_confirmed": 0,
            "note": "Use ?dl_token=<token> on the download endpoint. Token is valid for expires_in seconds and supports HTTP Range resume."
        }))

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

            # Determine a normalized relative path for token/protection DB lookups.
            # Must match the canonical_path stored by handle_mint_download_token:
            #   CDN files  -> /cdn/<rest>  (relative to CDN_UPLOAD_DIR)
            #   User files -> /<rest>      (relative to the user's FluxDrop root)
            if relative_path.startswith('/cdn'):
                rel_path_for_db = relative_path  # already begins with /cdn
            else:
                rel_path_for_db = '/' + os.path.relpath(base_path, user_base_path_for(user_id)).replace(os.sep, '/')

            # --- Download-token gate ---
            # Every download must present a valid dl_token minted by POST
            # /api/v1/download_token.  The token is NOT consumed on use — it
            # remains valid until it expires (default 1 h) so the client can
            # resume an interrupted download using HTTP Range requests with the
            # same dl_token.  bytes_confirmed is updated after each chunk and
            # exposed via X-Bytes-Confirmed so the client knows the safe resume
            # offset even if the connection drops mid-stream.
            parsed_qs = parse_qs(urlparse(self.path).query)
            dl_token = parsed_qs.get('dl_token', [None])[0]
            token_meta = _validate_download_token(rel_path_for_db, dl_token)
            if token_meta is None:
                return self._send_response(403, json.dumps({
                    "error": "Forbidden: a valid download token is required.",
                    "hint": "POST /api/v1/download_token with your session token to mint one."
                }))
            token_id = token_meta["id"]

            if _is_file_protected(rel_path_for_db):
                file_token = parsed_qs.get('token', [None])[0]
                if not _check_token_for_file(rel_path_for_db, file_token):
                    return self._send_response(403, json.dumps({"error": "Forbidden: valid file-access token required for this protected file."}))

            try:
                file_size = os.path.getsize(base_path)
                range_header = self.headers.get('Range')
                bufsize = 2 * 1024 * 1024   # 2 MB chunks
                progress_interval = 8 * 1024 * 1024  # write DB every 8 MB

                if range_header:
                    # Resumable partial download
                    m = re.match(r'bytes=(\d+)-(\d*)', range_header)
                    if m:
                        start = int(m.group(1))
                        end = int(m.group(2)) if m.group(2) else file_size - 1
                    else:
                        start, end = 0, file_size - 1
                    start = max(0, min(start, file_size - 1))
                    end = max(start, min(end, file_size - 1))
                    length = end - start + 1
                    self.send_response(206)
                    self._send_cors_headers()
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(base_path)}"')
                    self.send_header('Accept-Ranges', 'bytes')
                    self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                    self.send_header('Content-Length', str(length))
                    # Expose confirmed offset so client knows safe resume point
                    self.send_header('X-Bytes-Confirmed', str(token_meta['bytes_confirmed']))
                    self.send_header('X-Token-Expires-In', str(DOWNLOAD_TOKEN_TTL_SECONDS))
                    self.end_headers()
                    bytes_sent = start
                    last_confirmed = token_meta['bytes_confirmed']
                    with open(base_path, 'rb') as f:
                        f.seek(start)
                        remaining = length
                        while remaining > 0:
                            chunk = f.read(min(bufsize, remaining))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            bytes_sent += len(chunk)
                            remaining -= len(chunk)
                            if bytes_sent - last_confirmed >= progress_interval:
                                _update_token_progress(token_id, bytes_sent)
                                last_confirmed = bytes_sent
                    _update_token_progress(token_id, bytes_sent)
                    return
                else:
                    # Full download (no Range header)
                    self.send_response(200)
                    self._send_cors_headers()
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(base_path)}"')
                    self.send_header('Accept-Ranges', 'bytes')
                    self.send_header('Content-Length', str(file_size))
                    self.send_header('X-Bytes-Confirmed', '0')
                    self.send_header('X-Token-Expires-In', str(DOWNLOAD_TOKEN_TTL_SECONDS))
                    self.end_headers()
                    bytes_sent = 0
                    last_confirmed = 0
                    with open(base_path, 'rb') as f:
                        while True:
                            chunk = f.read(bufsize)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            bytes_sent += len(chunk)
                            if bytes_sent - last_confirmed >= progress_interval:
                                _update_token_progress(token_id, bytes_sent)
                                last_confirmed = bytes_sent
                    _update_token_progress(token_id, bytes_sent)
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
                    chunk = file_item.stream.read(chunk_size)
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

def _token_purge_worker():
    """Background thread: purge expired/used download tokens every 5 minutes."""
    while True:
        time.sleep(300)
        _purge_expired_download_tokens()


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

    # --- Start Background Workers ---
    purge_thread = threading.Thread(target=_token_purge_worker, name="TokenPurge", daemon=True)
    purge_thread.start()

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
