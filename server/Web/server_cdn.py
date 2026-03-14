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
import bcrypt
import collections
import smtplib
import sqlite3
from werkzeug.formparser import parse_form_data # For parsing multipart/form-data (cgi deprecated in Python 3.13+)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, quote, urlparse, parse_qs
from shared import CustomLogger, current_blacklist, blacklist_lock, load_blacklist_safely, update_blacklist, stop_update_event
from config import SERVE_DIRECTORY, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE_CDN, CDN_UPLOAD_DIR, BLACKLIST_FILE, PUBLIC_DOMAIN as _CONFIG_PUBLIC_DOMAIN

# ==============================================================================
# --- HTML SNIPPET LOADER ---
# ==============================================================================
_SNIPPETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snippets')

def _load_snippet(filename: str) -> str:
    """Load an HTML snippet from the snippets/ subfolder."""
    with open(os.path.join(_SNIPPETS_DIR, filename), encoding='utf-8') as f:
        return f.read()

def _render_snippet(filename: str, **kwargs) -> str:
    """Load a snippet and substitute {PLACEHOLDER} tokens safely.

    Unlike str.format(), this only replaces tokens whose names are explicitly
    passed as keyword arguments, so CSS rules like *{box-sizing:border-box}
    and JS template literals like ${previewUrl} are left completely untouched.
    """
    template = _load_snippet(filename)
    for key, value in kwargs.items():
        template = template.replace('{' + key + '}', str(value))
    return template

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
    # 'localhost' removed — allows any page on the visitor's machine to make
    # credentialed cross-origin requests to the server. Not needed in production.
}

# Host/ports
HOST = os.getenv('HOST', '0.0.0.0')
HTTP_PORT = int(os.getenv('HTTP_PORT', '63512'))
HTTPS_PORT = int(os.getenv('HTTPS_PORT', '64800'))

# Public domain and serve root
PUBLIC_DOMAIN = os.getenv('PUBLIC_DOMAIN', _CONFIG_PUBLIC_DOMAIN)
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

def _load_env_file(path: str) -> None:
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

# Track when this process started (for server uptime on /status)
_SERVER_START_TIME = time.time()

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
from contextlib import contextmanager

# Per-upload-session lock to serialise concurrent chunk writes.
# Without this, 4 parallel XHRs all read the same chunks_received list
# and each write back only their own addition — losing the other 3.
_chunk_locks = {}
_chunk_locks_mutex = threading.Lock()

def _get_chunk_lock(token):
    with _chunk_locks_mutex:
        if token not in _chunk_locks:
            _chunk_locks[token] = threading.Lock()
        return _chunk_locks[token]

def _release_chunk_lock(token):
    with _chunk_locks_mutex:
        _chunk_locks.pop(token, None)


@contextmanager
def _db_connect():
    """Open a SQLite connection with WAL mode and a lock timeout.

    Used as a context manager — the connection is always closed on exit,
    preventing connection leaks in long-running daemon threads.

    - timeout=15: wait up to 15 s for a lock instead of failing immediately.
    - WAL journal mode: allows concurrent readers alongside a single writer,
      eliminating lock pile-ups under multi-threaded load after extended uptime.

    Raises RuntimeError if the DB directory is not accessible (e.g. the
    containing drive is unmounted), so callers get a clear error rather than
    a cryptic sqlite3.OperationalError.
    """
    db_dir = os.path.dirname(os.path.abspath(DB_FILE))
    if not os.path.isdir(db_dir):
        raise RuntimeError(
            f"DB directory is not accessible: '{db_dir}'. "
            "The drive may be unmounted or the path may not exist."
        )
    conn = sqlite3.connect(DB_FILE, timeout=15)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
    finally:
        conn.close()


def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    logging.info(f"Using DB_FILE={DB_FILE}")
    with _db_connect() as conn:
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
                allow_preview INTEGER DEFAULT 0,
                allow_cdn_embed INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT NULL,
                access_count INTEGER DEFAULT 0,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
        ''')
        # Migrations: add columns that may be missing in older DBs
        for _col, _default in [
            ('expires_at', 'NULL'),
            ('allow_preview', '0'),
            ('allow_cdn_embed', '0'),
        ]:
            try:
                cursor.execute(f"ALTER TABLE shared_links ADD COLUMN {_col} {'TIMESTAMP DEFAULT NULL' if _col == 'expires_at' else 'INTEGER DEFAULT ' + _default}")
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
        # Resumable chunked upload sessions.
        # upload_token   — opaque token returned to the client at init; used to
        #                  resume from any device without a session token.
        # dest_path      — absolute path where the finished file will land.
        # tmp_path       — directory holding received chunk files (*.chunk).
        # total_size     — declared total file size in bytes (-1 = unknown).
        # chunk_size     — negotiated chunk size in bytes.
        # chunks_received— bitmask stored as JSON list of received chunk indices.
        # sha256_final   — optional whole-file SHA-256 hex the client declared.
        # owner_type     — 'user' | 'share' | 'catbox'
        # owner_ref      — user_id or share token string
        # last_activity  — updated on every chunk; used for TTL purging.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS upload_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_token TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                dest_path TEXT NOT NULL,
                tmp_dir TEXT NOT NULL,
                total_size INTEGER DEFAULT -1,
                chunk_size INTEGER NOT NULL,
                total_chunks INTEGER DEFAULT -1,
                chunks_received TEXT DEFAULT '[]',
                sha256_final TEXT,
                owner_type TEXT NOT NULL,
                owner_ref TEXT NOT NULL,
                anon_device_token TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed INTEGER DEFAULT 0
            )
        ''')
        # Persistent status snapshots for the uptime history graph.
        # One row per 5-minute sample; keeps ~90 days = ~25920 rows max (tiny).
        # status: 'ok' | 'degraded' | 'down'
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS status_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sampled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                http_up INTEGER DEFAULT 1,
                https_up INTEGER DEFAULT 1,
                db_ok INTEGER DEFAULT 1,
                mem_pct INTEGER DEFAULT 0,
                disk_pct INTEGER DEFAULT 0,
                cause TEXT DEFAULT NULL
            )
        ''')
        # Automatic incident log — one row per status-change event.
        # cause: human-readable string describing what triggered the transition.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP DEFAULT NULL,
                severity TEXT NOT NULL,
                cause TEXT NOT NULL,
                detail TEXT DEFAULT NULL
            )
        ''')
        # Admin message board — manually posted notices shown on /status.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message_board (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT NOT NULL DEFAULT 'info',
                title TEXT NOT NULL,
                body TEXT DEFAULT NULL
            )
        ''')
        # Network connectivity outage log.
        # Записується при кожному збої та відновленні інтернет-з'єднання.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS net_outages (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at       REAL    NOT NULL,
                ended_at         REAL    DEFAULT NULL,
                duration_sec     REAL    DEFAULT NULL,
                probe_host       TEXT    NOT NULL DEFAULT '8.8.8.8',
                confirmed_external INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

    # ── Schema migrations (safe to run on every startup) ──────────────────
    # ALTER TABLE IF NOT EXISTS ... ADD COLUMN is not supported in older SQLite;
    # instead we check the column list and add only if missing.
    with _db_connect() as conn:
        def _add_column_if_missing(table: str, column: str, definition: str) -> None:
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()]
            if column not in cols:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
                logging.info(f'Migration: added {table}.{column}')

        _add_column_if_missing('status_snapshots', 'cause',      'TEXT DEFAULT NULL')
        _add_column_if_missing('status_snapshots', 'net_ok',     'INTEGER DEFAULT 1')
        _add_column_if_missing('status_snapshots', 'latency_ms', 'REAL DEFAULT NULL')
        _add_column_if_missing('net_outages', 'note', 'TEXT DEFAULT NULL')
        _add_column_if_missing('users', 'is_admin', 'INTEGER NOT NULL DEFAULT 0')
        conn.commit()

    logging.info("Database initialized successfully.")


# ==============================================================================
# --- RESUMABLE UPLOAD HELPERS ---
# ==============================================================================

# Chunk size and abandoned-session TTL are tunable via env
UPLOAD_CHUNK_SIZE   = int(os.getenv('UPLOAD_CHUNK_SIZE',   str(25 * 1024 * 1024)))   # 25 MB
UPLOAD_SESSION_TTL  = int(os.getenv('UPLOAD_SESSION_TTL',  str(48 * 3600)))           # 48 h
MAX_JSON_BODY       = int(os.getenv('MAX_JSON_BODY',        str(1  * 1024 * 1024)))   # 1 MB — cap all JSON request bodies
MAX_UPLOAD_BYTES    = int(os.getenv('MAX_UPLOAD_BYTES',     str(10 * 1024 * 1024 * 1024)))  # 10 GB legacy upload cap
# Temp chunks land on the CDN drive itself, avoiding /tmp exhaustion
UPLOAD_TMP_DIR      = os.getenv('UPLOAD_TMP_DIR', os.path.join(
    '/media/arsen/dab4b7b7-8867-4bf3-9304-6fd153c0a028', '.upload_sessions'
))

def _upload_init(filename: str, dest_path: str, total_size: int,
                 total_chunks: int, sha256_final: str | None,
                 owner_type: str, owner_ref: str,
                 anon_device_token: str | None = None) -> dict:
    """Create a new upload session. Returns the session row as a dict."""
    token = secrets.token_urlsafe(32)
    tmp_dir = os.path.join(UPLOAD_TMP_DIR, token)
    os.makedirs(tmp_dir, exist_ok=True)
    with _db_connect() as conn:
        conn.execute(
            '''INSERT INTO upload_sessions
               (upload_token, filename, dest_path, tmp_dir, total_size,
                chunk_size, total_chunks, sha256_final, owner_type, owner_ref,
                anon_device_token)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
            (token, filename, dest_path, tmp_dir, total_size,
             UPLOAD_CHUNK_SIZE, total_chunks, sha256_final, owner_type, owner_ref,
             anon_device_token)
        )
        conn.commit()
    return _upload_get(token)

def _upload_get(token: str) -> dict | None:
    """Fetch an upload session by token. Returns dict or None."""
    with _db_connect() as conn:
        row = conn.execute(
            'SELECT * FROM upload_sessions WHERE upload_token = ?', (token,)
        ).fetchone()
    if not row:
        return None
    keys = ['id','upload_token','filename','dest_path','tmp_dir','total_size',
            'chunk_size','total_chunks','chunks_received','sha256_final',
            'owner_type','owner_ref','anon_device_token','created_at','last_activity','completed']
    d = dict(zip(keys, row))
    d['chunks_received'] = json.loads(d['chunks_received'] or '[]')
    return d

def _upload_receive_chunk(token: str, chunk_index: int, data: bytes) -> dict:
    """Write chunk to disk, verify SHA-256, update session. Returns updated session."""
    session = _upload_get(token)
    if not session:
        raise KeyError('Upload session not found')
    if session['completed']:
        raise ValueError('Session already completed')

    # Write chunk file (safe outside the lock — each index has a unique filename)
    chunk_path = os.path.join(session['tmp_dir'], f'{chunk_index:06d}.chunk')
    with open(chunk_path, 'wb') as f:
        f.write(data)

    # Serialise the read-modify-write so concurrent chunk uploads don't clobber
    # each other's entries in the JSON list.
    lock = _get_chunk_lock(token)
    with lock:
        # Re-read inside the lock to get the latest committed state
        fresh = _upload_get(token)
        if not fresh:
            raise KeyError('Upload session disappeared')
        received = fresh['chunks_received']
        if chunk_index not in received:
            received.append(chunk_index)
            received.sort()
        with _db_connect() as conn:
            conn.execute(
                '''UPDATE upload_sessions
                   SET chunks_received = ?, last_activity = CURRENT_TIMESTAMP
                   WHERE upload_token = ?''',
                (json.dumps(received), token)
            )
            conn.commit()
    return _upload_get(token)

def _upload_assemble(token: str) -> str:
    """Assemble all chunks into dest_path. Returns dest_path on success."""
    session = _upload_get(token)
    if not session:
        raise KeyError('Upload session not found')

    tmp_dir    = session['tmp_dir']
    dest_path  = session['dest_path']
    total_chunks = session['total_chunks']
    received   = set(session['chunks_received'])

    # Verify all chunks present
    if total_chunks > 0:
        missing = [i for i in range(total_chunks) if i not in received]
        if missing:
            raise ValueError(f'Missing chunks: {missing[:10]}{"…" if len(missing)>10 else ""}')

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # Assemble in order
    hasher = hashlib.sha256()
    with open(dest_path, 'wb') as out:
        for idx in sorted(received):
            chunk_path = os.path.join(tmp_dir, f'{idx:06d}.chunk')
            with open(chunk_path, 'rb') as cf:
                while True:
                    block = cf.read(4 * 1024 * 1024)
                    if not block:
                        break
                    out.write(block)
                    hasher.update(block)

    # Verify whole-file SHA-256 if client provided one
    actual_sha256 = hasher.hexdigest()
    if session['sha256_final'] and session['sha256_final'].lower() != actual_sha256:
        os.remove(dest_path)
        raise ValueError(
            f'SHA-256 mismatch: expected {session["sha256_final"]}, got {actual_sha256}'
        )

    # Mark complete and clean up chunk dir
    with _db_connect() as conn:
        conn.execute(
            'UPDATE upload_sessions SET completed = 1, last_activity = CURRENT_TIMESTAMP WHERE upload_token = ?',
            (token,)
        )
        conn.commit()
    _release_chunk_lock(token)  # free the per-session lock entry
    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    logging.info(f'Upload assembled: {dest_path} ({actual_sha256[:12]}…)')
    return dest_path

def _upload_session_status(session: dict) -> dict:
    """Return a client-friendly status dict for a session."""
    total   = session['total_chunks']
    received = session['chunks_received']
    return {
        'upload_token':    session['upload_token'],
        'filename':        session['filename'],
        'chunk_size':      session['chunk_size'],
        'total_chunks':    total,
        'chunks_received': received,
        'missing_chunks':  [i for i in range(total) if i not in received] if total > 0 else [],
        'completed':       bool(session['completed']),
        'last_activity':   session['last_activity'],
    }

def _purge_abandoned_upload_sessions() -> bool:
    """Delete upload sessions and their tmp dirs that have been idle past TTL."""
    try:
        cutoff = datetime.now() - timedelta(seconds=UPLOAD_SESSION_TTL)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')
        with _db_connect() as conn:
            rows = conn.execute(
                'SELECT upload_token, tmp_dir FROM upload_sessions WHERE last_activity < ? AND completed = 0',
                (cutoff_str,)
            ).fetchall()
            for token, tmp_dir in rows:
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    logging.info(f'Purged abandoned upload session {token[:12]}…')
                    _release_chunk_lock(token)
                except Exception:
                    pass
            if rows:
                conn.execute(
                    'DELETE FROM upload_sessions WHERE last_activity < ? AND completed = 0',
                    (cutoff_str,)
                )
                conn.commit()
        return True
    except Exception:
        logging.exception('Failed to purge abandoned upload sessions')
        return False


def _build_snapshot_cause(http_up: bool, https_up: bool, db_ok: bool,
                           mem_pct: int, disk_pct: int) -> str | None:
    """Return a short human-readable cause string when something is not fully ok."""
    parts = []
    if not http_up:
        parts.append('HTTP server unreachable')
    if not https_up:
        parts.append('HTTPS server unreachable')
    if not db_ok:
        parts.append('database query failed')
    if mem_pct >= 95:
        parts.append(f'memory critical ({mem_pct}%)')
    elif mem_pct >= 85:
        parts.append(f'memory high ({mem_pct}%)')
    if disk_pct >= 90:
        parts.append(f'disk critical ({disk_pct}%)')
    elif disk_pct >= 75:
        parts.append(f'disk usage high ({disk_pct}%)')
    return '; '.join(parts) if parts else None


def _record_status_snapshot(http_up: bool, https_up: bool, db_ok: bool,
                            mem_pct: int, disk_pct: int,
                            net_ok: bool = True,
                            latency_ms: float | None = None) -> None:
    """Write one status sample to the DB. Prunes rows older than 90 days.

    Also maintains the incident_log table: opens a new incident when the
    status transitions away from 'ok', and closes any open incident when it
    returns to 'ok'.
    """
    if http_up and https_up and db_ok:
        status = 'ok'
    elif not http_up or not https_up:
        status = 'down'
    else:
        status = 'degraded'

    cause = _build_snapshot_cause(http_up, https_up, db_ok, mem_pct, disk_pct)

    try:
        with _db_connect() as conn:
            conn.execute(
                '''INSERT INTO status_snapshots
                   (status, http_up, https_up, db_ok, mem_pct, disk_pct, cause, net_ok, latency_ms)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (status, int(http_up), int(https_up), int(db_ok), mem_pct, disk_pct, cause,
                 int(net_ok), latency_ms)
            )
            # Keep only 90 days of data (90*24*12 = 25920 five-minute samples)
            conn.execute(
                "DELETE FROM status_snapshots WHERE sampled_at < datetime('now', '-90 days')"
            )

            # --- incident tracking ---
            open_incident = conn.execute(
                "SELECT id FROM incident_log WHERE resolved_at IS NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()

            if status != 'ok' and open_incident is None:
                # New outage — open a fresh incident
                severity = 'critical' if status == 'down' else 'degraded'
                detail = (
                    f"http_up={http_up}, https_up={https_up}, "
                    f"db_ok={db_ok}, mem={mem_pct}%, disk={disk_pct}%"
                )
                conn.execute(
                    '''INSERT INTO incident_log (severity, cause, detail)
                       VALUES (?,?,?)''',
                    (severity, cause or 'unknown', detail)
                )
            elif status == 'ok' and open_incident is not None:
                # Recovered — close the incident
                conn.execute(
                    "UPDATE incident_log SET resolved_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (open_incident[0],)
                )

            conn.commit()
    except Exception:
        logging.exception('Failed to record status snapshot')


# ==============================================================================
# --- NETWORK CONNECTIVITY MONITOR ---
# ==============================================================================

_NET_PROBE_HOSTS = [
    ('8.8.8.8', 53,  'Google DNS'),
    ('1.1.1.1', 53,  'Cloudflare DNS'),
]
_NET_PROBE_TIMEOUT  = 3
_NET_PROBE_INTERVAL      = 30   # normal polling interval (s)
_NET_PROBE_INTERVAL_DOWN = 5    # faster polling during outage (s)

# Shared state — written by _net_monitor_worker, read by status.json handler
_net_monitor_state = {
    'ok':           True,
    'latency_ms':   None,
    'outage_id':    None,    # rowid of open net_outages row, or None
    'outage_since': None,    # unix timestamp of outage start
}
_net_state_lock = threading.Lock()

# ── Auth rate limiter ──────────────────────────────────────────────────────
_rl_lock     = threading.Lock()
_rl_attempts: dict[str, list[float]] = collections.defaultdict(list)
_RL_WINDOW   = 60    # seconds per window
_RL_MAX_AUTH = 10    # max login/register attempts per IP per window
_RL_MAX_API  = 30    # max sensitive-API attempts per IP per window

def _rate_limit(ip: str, bucket: str = "auth", max_hits: int | None = None) -> bool:
    """Return True (allowed) or False (throttled). Thread-safe."""
    limit = max_hits if max_hits is not None else (_RL_MAX_AUTH if bucket == "auth" else _RL_MAX_API)
    key   = f"{bucket}:{ip}"
    now   = time.monotonic()
    with _rl_lock:
        ts = _rl_attempts[key]
        _rl_attempts[key] = [t for t in ts if now - t < _RL_WINDOW]
        if len(_rl_attempts[key]) >= limit:
            return False
        _rl_attempts[key].append(now)
        return True


def _net_probe_once() -> tuple[bool, float | None]:
    """TCP-connect to each probe host; return (is_ok, avg_latency_ms).

    is_ok is True when at least ONE host responds (avoids false positives
    from a single temporarily unreachable server).  Declared outage only
    when BOTH fail.
    """
    import socket as _ps
    ok_lats = []
    for host, port, _ in _NET_PROBE_HOSTS:
        t0 = time.monotonic()
        try:
            with _ps.create_connection((host, port), timeout=_NET_PROBE_TIMEOUT):
                ok_lats.append((time.monotonic() - t0) * 1000)
        except Exception:
            pass
    if not ok_lats:
        return False, None
    return True, round(sum(ok_lats) / len(ok_lats), 2)


def _dd_check_google() -> bool | None:
    """Rough DownDetector check for Google/ISP outages.

    Returns True  → DownDetector shows active user reports (external issue)
            False → DownDetector looks clear
            None  → check failed (network itself may be down)
    """
    try:
        import urllib.request as _ur, ssl as _ssl
        ctx = _ssl.create_default_context()
        req = _ur.Request(
            'https://downdetector.com/status/google/',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with _ur.urlopen(req, timeout=5, context=ctx) as r:
            body = r.read(8192).decode('utf-8', errors='ignore').lower()
        return ('problems at google' in body or 'user reports indicate' in body)
    except Exception:
        return None


def _open_net_outage(probe_host: str) -> int | None:
    try:
        with _db_connect() as conn:
            cur = conn.execute(
                'INSERT INTO net_outages (started_at, probe_host) VALUES (?, ?)',
                (time.time(), probe_host)
            )
            conn.commit()
            return cur.lastrowid
    except Exception:
        logging.exception('NetMonitor: failed to open outage record')
        return None


def _close_net_outage(outage_id: int, started_at: float,
                      confirmed_external: bool = False) -> None:
    try:
        now = time.time()
        dur = round(now - started_at, 1)
        with _db_connect() as conn:
            conn.execute(
                '''UPDATE net_outages
                   SET ended_at=?, duration_sec=?, confirmed_external=?
                   WHERE id=?''',
                (now, dur, 1 if confirmed_external else 0, outage_id)
            )
            conn.commit()
        logging.warning(
            f'NetMonitor: connectivity restored after {dur:.0f}s'
            + (' (external confirmed)' if confirmed_external else '')
        )
    except Exception:
        logging.exception('NetMonitor: failed to close outage record')


def _net_monitor_worker() -> None:
    """Background daemon thread — probes internet every N seconds.

    On outage:
      1. Opens a net_outages row.
      2. Spawns a one-shot thread to check DownDetector (non-blocking).
      3. Polls every 5 s until connectivity is restored.
    On recovery:
      4. Closes the net_outages row with duration + external flag.
    """
    logging.info('NetMonitor: started (probing %s)',
                 ', '.join(f'{h}:{p}' for h, p, _ in _NET_PROBE_HOSTS))
    while True:
        is_ok, latency = _net_probe_once()

        with _net_state_lock:
            was_ok       = _net_monitor_state['ok']
            outage_id    = _net_monitor_state['outage_id']
            outage_since = _net_monitor_state['outage_since']

            _net_monitor_state['ok']         = is_ok
            _net_monitor_state['latency_ms'] = latency

            if not is_ok and was_ok:
                logging.warning('NetMonitor: connectivity LOST')
                oid = _open_net_outage(_NET_PROBE_HOSTS[0][0])
                _net_monitor_state['outage_id']   = oid
                _net_monitor_state['outage_since'] = time.time()

                def _bg_dd(oid_=oid):
                    confirmed = _dd_check_google()
                    if confirmed is not None and oid_:
                        try:
                            with _db_connect() as _c:
                                _c.execute(
                                    'UPDATE net_outages SET confirmed_external=? WHERE id=?',
                                    (1 if confirmed else 0, oid_)
                                )
                                _c.commit()
                        except Exception:
                            pass
                threading.Thread(target=_bg_dd, daemon=True, name='DDCheck').start()

            elif is_ok and not was_ok and outage_id is not None:
                ext = False
                try:
                    with _db_connect() as _c:
                        row = _c.execute(
                            'SELECT confirmed_external FROM net_outages WHERE id=?',
                            (outage_id,)
                        ).fetchone()
                        ext = bool(row[0]) if row else False
                except Exception:
                    pass
                _close_net_outage(outage_id, outage_since or time.time(), ext)
                _net_monitor_state['outage_id']   = None
                _net_monitor_state['outage_since'] = None

        time.sleep(_NET_PROBE_INTERVAL_DOWN if not is_ok else _NET_PROBE_INTERVAL)


def _get_net_outages(days: int = 7) -> list:
    """Return net outages from the last N days, newest first."""
    try:
        cutoff = time.time() - days * 86400
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT id, started_at, ended_at, duration_sec,
                          probe_host, confirmed_external, COALESCE(note,'') as note
                   FROM net_outages
                   WHERE started_at >= ?
                   ORDER BY started_at DESC''',
                (cutoff,)
            ).fetchall()
        result = []
        for row in rows:
            oid, started, ended, dur, host, ext, note = row
            started_str = datetime.fromtimestamp(started).strftime('%Y-%m-%d %H:%M:%S')
            ended_str   = datetime.fromtimestamp(ended).strftime('%Y-%m-%d %H:%M:%S') if ended else None
            if dur is not None:
                if dur < 60:
                    dur_str = f'{dur:.0f}s'
                elif dur < 3600:
                    dur_str = f'{dur/60:.0f}m {int(dur)%60}s'
                else:
                    dur_str = f'{dur/3600:.1f}h'
            else:
                dur_str = 'ongoing'
            result.append({
                'id':                  oid,
                'started_at':          started_str,
                'ended_at':            ended_str,
                'duration_str':        dur_str,
                'is_open':             ended is None,
                'probe_host':          host,
                'confirmed_external':  bool(ext),
                'note':                note or None,
            })
        return result
    except Exception:
        logging.exception('NetMonitor: failed to fetch outages')
        return []


def _get_net_history_by_day(days: int = 90) -> dict:
    """Return {date_str: {outage_count, total_downtime_sec}} for uptime bars."""
    try:
        cutoff = time.time() - days * 86400
        with _db_connect() as conn:
            rows = conn.execute(
                """SELECT date(datetime(started_at, 'unixepoch', 'localtime')) as day,
                          COUNT(*) as outage_count,
                          SUM(COALESCE(duration_sec, 0)) as total_down
                   FROM net_outages
                   WHERE started_at >= ?
                   GROUP BY day""",
                (cutoff,)
            ).fetchall()
        return {r[0]: {'outage_count': r[1], 'total_downtime_sec': r[2] or 0}
                for r in rows}
    except Exception:
        return {}


def _get_recent_incidents(limit: int = 20) -> list:
    """Return the most recent incidents from incident_log, newest first.

    Each row: { id, started_at, resolved_at, severity, cause, detail,
                duration_str, is_open }
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT id, started_at, resolved_at, severity, cause, detail
                   FROM incident_log
                   ORDER BY id DESC
                   LIMIT ?''',
                (limit,)
            ).fetchall()
    except Exception:
        return []

    result = []
    for row in rows:
        inc_id, started_at, resolved_at, severity, cause, detail = row
        is_open = resolved_at is None
        if is_open:
            duration_str = 'ongoing'
        else:
            try:
                fmt = '%Y-%m-%d %H:%M:%S'
                s = datetime.strptime(started_at[:19], fmt)
                e = datetime.strptime(resolved_at[:19], fmt)
                secs = int((e - s).total_seconds())
                if secs < 60:
                    duration_str = f'{secs}s'
                elif secs < 3600:
                    duration_str = f'{secs // 60}m {secs % 60}s'
                else:
                    duration_str = f'{secs // 3600}h {(secs % 3600) // 60}m'
            except Exception:
                duration_str = '?'
        result.append({
            'id': inc_id,
            'started_at': started_at,
            'resolved_at': resolved_at,
            'severity': severity,
            'cause': cause,
            'detail': detail,
            'duration_str': duration_str,
            'is_open': is_open,
        })
    return result


def _get_message_board(limit: int = 10) -> list:
    """Return the most recent message-board posts, newest first.

    Each row: { id, posted_at, level, title, body }
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT id, posted_at, level, title, body
                   FROM message_board
                   ORDER BY id DESC
                   LIMIT ?''',
                (limit,)
            ).fetchall()
        return [
            {'id': r[0], 'posted_at': r[1], 'level': r[2], 'title': r[3], 'body': r[4]}
            for r in rows
        ]
    except Exception:
        return []


def _get_status_history(days: int = 90) -> list:
    """Return one aggregated row per day for the last `days` days.

    Each row: { date, status ('ok'|'degraded'|'down'|'no_data'),
                uptime_pct, sample_count, causes, http_down_n, https_down_n, db_down_n,
                mem_max, disk_max }
    Days are in descending order (today first).
    causes is a deduplicated list of non-null cause strings recorded that day.
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                """SELECT date(sampled_at, 'localtime') as day,
                          COUNT(*) as n,
                          SUM(CASE WHEN status='ok'   THEN 1 ELSE 0 END) as ok_n,
                          SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) as down_n,
                          SUM(CASE WHEN http_up=0  THEN 1 ELSE 0 END) as http_down_n,
                          SUM(CASE WHEN https_up=0 THEN 1 ELSE 0 END) as https_down_n,
                          SUM(CASE WHEN db_ok=0    THEN 1 ELSE 0 END) as db_down_n,
                          MAX(mem_pct)  as mem_max,
                          MAX(disk_pct) as disk_max
                   FROM status_snapshots
                   WHERE sampled_at >= datetime('now', ? || ' days')
                   GROUP BY day
                   ORDER BY day DESC""",
                (f'-{days}',)
            ).fetchall()
            # Fetch distinct non-null causes per day (newest first within the day)
            cause_rows = conn.execute(
                """SELECT date(sampled_at, 'localtime') as day, cause
                   FROM status_snapshots
                   WHERE cause IS NOT NULL
                     AND sampled_at >= datetime('now', ? || ' days')
                   ORDER BY sampled_at DESC""",
                (f'-{days}',)
            ).fetchall()
    except Exception:
        return []

    # Build deduplicated cause lists per day (preserve insertion order, newest first)
    causes_by_day: dict[str, list[str]] = {}
    for day, cause in cause_rows:
        seen = causes_by_day.setdefault(day, [])
        if cause not in seen:
            seen.append(cause)

    by_day = {r[0]: r for r in rows}
    result = []
    today = datetime.now().date()
    for i in range(days):
        d = (today - timedelta(days=i)).isoformat()
        if d in by_day:
            _, n, ok_n, down_n, http_down_n, https_down_n, db_down_n, mem_max, disk_max = by_day[d]
            pct = round(ok_n / n * 100, 1) if n else 0
            if down_n == n:
                st = 'down'
            elif down_n > 0 or ok_n < n:
                st = 'degraded'
            else:
                st = 'ok'
            result.append({
                'date': d, 'status': st, 'uptime_pct': pct, 'sample_count': n,
                'causes': causes_by_day.get(d, []),
                'http_down_n': http_down_n or 0,
                'https_down_n': https_down_n or 0,
                'db_down_n': db_down_n or 0,
                'mem_max': mem_max or 0,
                'disk_max': disk_max or 0,
            })
        else:
            result.append({
                'date': d, 'status': 'no_data', 'uptime_pct': None, 'sample_count': 0,
                'causes': [], 'http_down_n': 0, 'https_down_n': 0, 'db_down_n': 0,
                'mem_max': 0, 'disk_max': 0,
            })
    return result


# ==============================================================================
# --- SHARE LINK HELPERS ---
# ==============================================================================

def _create_share(user_id: int, path: str, is_dir: bool, require_account: bool,
                  track_stats: bool, allow_anon_upload: bool, allow_auth_upload: bool,
                  expires_at=None, allow_preview: bool = False, allow_cdn_embed: bool = False) -> str:
    """Mint a new public share token and store it. Returns the raw token.
    expires_at: ISO datetime string or None for no expiry.
    """
    raw = secrets.token_urlsafe(24)
    with _db_connect() as conn:
        conn.execute(
            """INSERT INTO shared_links
               (token, owner_id, path, is_dir, require_account, track_stats,
                allow_anon_upload, allow_auth_upload, allow_preview, allow_cdn_embed,
                created_at, expires_at, access_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,0)""",
            (raw, user_id, path, 1 if is_dir else 0,
             1 if require_account else 0, 1 if track_stats else 0,
             1 if allow_anon_upload else 0, 1 if allow_auth_upload else 0,
             1 if allow_preview else 0, 1 if allow_cdn_embed else 0,
             expires_at)
        )
        conn.commit()
    return raw


def _get_shares_for_user(user_id: int) -> list:
    with _db_connect() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """SELECT token, path, is_dir, require_account, track_stats,
                      allow_anon_upload, allow_auth_upload, allow_preview, allow_cdn_embed,
                      created_at, expires_at, access_count
               FROM shared_links WHERE owner_id = ? ORDER BY created_at DESC""",
            (user_id,)
        )
        return [dict(r) for r in cur.fetchall()]


def _get_share_raw(token: str) -> dict | None:
    """Return share row regardless of expiry, or None if token never existed."""
    with _db_connect() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM shared_links WHERE token = ?", (token,))
        r = cur.fetchone()
        return dict(r) if r else None


def _parse_expiry(value: str):
    """Parse expiry string in any format the UI might send (ISO or DD.MM.YYYY)."""
    if not value:
        return None
    for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d.%m.%Y'):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.strip())
    except Exception:
        return None


def _is_share_expired(share: dict) -> bool:
    """Return True if the share has a past expiry date."""
    val = share.get('expires_at')
    if not val:
        return False
    exp = _parse_expiry(val)
    if exp is None:
        return False
    now = datetime.now(exp.tzinfo) if exp.tzinfo else datetime.now()
    return now > exp


def _get_share(token: str) -> dict | None:
    """Return share metadata if token exists and has not expired; else None."""
    share = _get_share_raw(token)
    if not share:
        return None
    if _is_share_expired(share):
        return None
    return share


def _update_share(token: str, owner_id: int, fields: dict):
    allowed = {'require_account', 'track_stats', 'allow_anon_upload', 'allow_auth_upload',
               'allow_preview', 'allow_cdn_embed', 'expires_at'}
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
    with _db_connect() as conn:
        cur = conn.execute(
            f"UPDATE shared_links SET {', '.join(parts)} WHERE token = ? AND owner_id = ?", vals
        )
        conn.commit()
        return cur.rowcount > 0


def _delete_share(token: str, owner_id: int) -> bool:
    with _db_connect() as conn:
        cur = conn.execute(
            "DELETE FROM shared_links WHERE token = ? AND owner_id = ?", (token, owner_id)
        )
        conn.commit()
        return cur.rowcount > 0


def _log_share_access(token: str, user_id, action: str = 'view'):
    try:
        with _db_connect() as conn:
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
    with _db_connect() as conn:
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
    with _db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT protected FROM protected_files WHERE relative_path = ?", (relative_path,))
        r = cursor.fetchone()
        return bool(r and r[0])


def _check_token_for_file(relative_path, token):
    """Checks whether the provided token (plain) matches the stored hash for the file."""
    if not token:
        return False
    h = hashlib.sha256(token.encode('utf-8')).hexdigest()
    with _db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT token_hash FROM protected_files WHERE relative_path = ? AND protected = 1", (relative_path,))
        r = cursor.fetchone()
        if not r or not r[0]:
            return False
        return h == r[0]


def _mark_file_protected(relative_path, created_by=None):
    """Marks a file as protected in the DB. Does not generate a token (token can be generated by admin CLI)."""
    with _db_connect() as conn:
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
    with _db_connect() as conn:
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
    with _db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT id, bytes_confirmed, user_id FROM download_tokens
               WHERE token_hash = ? AND relative_path = ? AND expires_at > CURRENT_TIMESTAMP""",
            (token_hash, relative_path)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {"id": row[0], "bytes_confirmed": row[1], "user_id": row[2]}


def _update_token_progress(token_id: int, bytes_confirmed: int):
    """Update the bytes_confirmed counter for a download token.

    Called after each successful chunk so that if the connection drops the
    client (and server) both know the safe resume offset.
    """
    try:
        with _db_connect() as conn:
            conn.execute(
                "UPDATE download_tokens SET bytes_confirmed = ? WHERE id = ?",
                (bytes_confirmed, token_id)
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to update download token progress")


def _purge_expired_download_tokens():
    """Remove expired download tokens. Call periodically to keep the table small.

    Returns True on success, False on failure (so the caller can back off).
    """
    try:
        with _db_connect() as conn:
            conn.execute(
                "DELETE FROM download_tokens WHERE expires_at <= CURRENT_TIMESTAMP"
            )
            conn.commit()
        return True
    except Exception:
        logging.exception("Failed to purge expired download tokens")
        return False


# ==============================================================================
# --- AUTHENTICATION & USER MANAGEMENT ---
# ==============================================================================

def _sha256_hash(password: str, salt: str) -> tuple[str, str]:
    """Legacy SHA-256 hash — used only during the bcrypt migration path."""
    salted = (salt + password).encode('utf-8')
    return hashlib.sha256(salted).hexdigest(), salt

def hash_password(password: str, salt=None) -> tuple[str, str]:
    """Hash a password with bcrypt.

    The ``salt`` parameter is accepted for call-site compatibility with the
    old SHA-256 path but is ignored — bcrypt embeds its own random salt.
    Returns ``(hashed, '')`` so callers that unpack two values still work;
    the empty string signals "no external salt".
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    return hashed.decode('utf-8'), ''

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

    # Try to load icon.svg and convert it to a transparent PNG for embedding.
    # Gmail blocks SVG entirely; only raster formats work.
    # We use wand to rasterise at high resolution then crop to content so the
    # transparent background is preserved (no white box on mobile).
    icon_path = os.path.join(SERVE_DIRECTORY, 'fluxdrop_pp', 'icon.svg')
    icon_cid = 'fluxdrop_icon'
    icon_data = None  # will hold transparent PNG bytes if conversion succeeds
    try:
        from wand.image import Image as WandImage
        from wand.color import Color
        with WandImage(filename=icon_path, resolution=192) as img:
            img.background_color = Color('transparent')
            img.alpha_channel = 'set'
            img.format = 'png'
            img.trim()           # remove any whitespace border
            img.resize(64, 64)   # small — same height as the title text
            icon_data = img.make_blob()
    except Exception as _e:
        logging.warning(f"Could not rasterise icon.svg to PNG for email: {_e}")

    if icon_data:
        # Inline next to title, same height — mirrors the site header
        icon_img = f'<img src="cid:{icon_cid}" alt="" width="32" height="32" style="vertical-align:middle;margin-right:6px;display:inline-block">'
    else:
        icon_img = ''

    html_body = _render_snippet('email_verification.html',
        icon_img=icon_img,
        username=username,
        verification_link=verification_link,
    )

    # Build a multipart/related message so the icon CID attachment is recognised
    msg = MIMEMultipart('related')
    msg['Subject'] = subject
    msg['From'] = SMTP_SENDER_EMAIL
    msg['To'] = email

    # Wrap HTML in multipart/alternative (text fallback + HTML)
    alt = MIMEMultipart('alternative')
    alt.attach(MIMEText(
        f"Hello {username},\n\nVerify your FluxDrop account: {verification_link}\n\nThis link expires in 1 hour.",
        'plain'
    ))
    alt.attach(MIMEText(html_body, 'html'))
    msg.attach(alt)

    # Attach the icon inline — Content-Disposition must be inline (not attachment)
    # and X-Attachment-Id must match the CID so Gmail does not show it as a file.
    if icon_data:
        img_part = MIMEImage(icon_data, _subtype='png')
        img_part.add_header('Content-ID', f'<{icon_cid}>')
        img_part.add_header('Content-Disposition', 'inline', filename='icon.png')
        img_part.add_header('X-Attachment-Id', icon_cid)
        msg.attach(img_part)

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
# --- STATUS PAGE (/status) ---
# ==============================================================================

def _fmt_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def _disk_indicator(pct: float) -> str:
    if pct >= 90: return 'crit'
    if pct >= 75: return 'warn'
    return 'ok'

def _build_status_page() -> str:
    """Collect all system metrics and render the status HTML page."""
    import ssl as _ssl

    now = datetime.now()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')

    # ── server uptime ──
    srv_uptime_secs = int(time.time() - _SERVER_START_TIME)
    srv_h = srv_uptime_secs // 3600
    srv_m = (srv_uptime_secs % 3600) // 60
    srv_uptime_h = str(srv_h)
    srv_start_str = datetime.fromtimestamp(_SERVER_START_TIME).strftime('%Y-%m-%d %H:%M')

    # ── system uptime (from /proc/uptime) ──
    try:
        with open('/proc/uptime') as f:
            sys_uptime_secs = int(float(f.read().split()[0]))
    except Exception:
        sys_uptime_secs = 0
    sys_h = sys_uptime_secs // 3600
    sys_uptime_h = str(sys_h)
    sys_d = sys_h // 24
    sys_uptime_str = f"{sys_d}d {sys_h % 24}h {(sys_uptime_secs % 3600) // 60}m"

    # ── disk stats ──
    def _diskinfo(path: str) -> dict:
        try:
            st = os.statvfs(path)
            total = st.f_frsize * st.f_blocks
            avail = st.f_frsize * st.f_bavail
            used  = total - avail
            pct   = round(used / total * 100, 1) if total else 0
            return {
                'total': _fmt_bytes(total), 'used': _fmt_bytes(used),
                'avail': _fmt_bytes(avail), 'pct': pct,
                'ind':   _disk_indicator(pct),
            }
        except Exception:
            return {'total':'N/A','used':'N/A','avail':'N/A','pct':0,'ind':'warn'}

    cdn_disk  = _diskinfo(SERVE_ROOT)
    root_disk = _diskinfo('/')
    tmp_disk  = _diskinfo('/tmp')

    # ── cpu load ──
    try:
        with open('/proc/loadavg') as f:
            parts = f.read().split()
        loads = [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        loads = [0.0, 0.0, 0.0]

    # get CPU count for normalising load to %
    try:
        cpu_count = os.cpu_count() or 1
    except Exception:
        cpu_count = 1

    load_labels = ['1 min', '5 min', '15 min']
    cpu_bars_html = ''
    for label, load in zip(load_labels, loads):
        pct = min(round(load / cpu_count * 100), 100)
        cpu_bars_html += (
            f'<div class="cpu-row">'
            f'<div class="cpu-label">{label}</div>'
            f'<div class="cpu-track"><div class="cpu-fill" style="width:{pct}%"></div></div>'
            f'<div class="cpu-pct">{load:.2f}</div>'
            f'</div>'
        )

    # ── memory (/proc/meminfo) ──
    mem = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':', 1)
                mem[k.strip()] = int(v.strip().split()[0]) * 1024  # kB → bytes
    except Exception:
        pass

    mem_total_b = mem.get('MemTotal', 0)
    mem_avail_b = mem.get('MemAvailable', 0)
    mem_used_b  = mem_total_b - mem_avail_b
    mem_pct     = round(mem_used_b / mem_total_b * 100) if mem_total_b else 0
    mem_total   = _fmt_bytes(mem_total_b)
    mem_used    = _fmt_bytes(mem_used_b)
    mem_avail   = _fmt_bytes(mem_avail_b)

    swap_total_b = mem.get('SwapTotal', 0)
    swap_free_b  = mem.get('SwapFree', 0)
    swap_used_b  = swap_total_b - swap_free_b
    swap_pct     = round(swap_used_b / swap_total_b * 100) if swap_total_b else 0
    swap_total   = _fmt_bytes(swap_total_b)
    swap_used    = _fmt_bytes(swap_used_b)

    # ── network (first non-lo interface from /proc/net/dev) ──
    net_rx_b = net_tx_b = 0
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                line = line.strip()
                if ':' not in line:
                    continue
                iface, data = line.split(':', 1)
                iface = iface.strip()
                if iface == 'lo':
                    continue
                nums = data.split()
                net_rx_b += int(nums[0])
                net_tx_b += int(nums[8])
    except Exception:
        pass
    net_rx = _fmt_bytes(net_rx_b)
    net_tx = _fmt_bytes(net_tx_b)

    # ── DB stats ──
    user_count = active_sessions = active_shares = expired_shares = total_share_views = 0
    db_status = 'ok'; db_ind = 'ok'
    try:
        with _db_connect() as conn:
            user_count       = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            active_sessions  = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP"
            ).fetchone()[0]
            active_shares    = conn.execute(
                "SELECT COUNT(*) FROM shared_links WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
            ).fetchone()[0]
            expired_shares   = conn.execute(
                "SELECT COUNT(*) FROM shared_links WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP"
            ).fetchone()[0]
            total_share_views = conn.execute(
                "SELECT COALESCE(SUM(access_count),0) FROM shared_links"
            ).fetchone()[0]
    except Exception:
        db_status = 'degraded'; db_ind = 'warn'

    db_size_str = 'N/A'
    try:
        db_size_str = _fmt_bytes(os.path.getsize(DB_FILE))
    except Exception:
        pass

    # ── file counts ──
    def _count_dir(path: str):
        count = size = 0
        try:
            for root, _, files in os.walk(path):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        size += os.path.getsize(fp)
                        count += 1
                    except Exception:
                        pass
        except Exception:
            pass
        return count, size

    fluxdrop_dir = os.path.join(SERVE_ROOT, 'FluxDrop')
    catbox_dir   = os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR)
    fluxdrop_files, fluxdrop_size = _count_dir(fluxdrop_dir)
    catbox_files,   catbox_size   = _count_dir(catbox_dir)
    fluxdrop_size_str = _fmt_bytes(fluxdrop_size)
    catbox_size_str   = _fmt_bytes(catbox_size)

    # ── TLS cert expiry ──
    ssl_status = 'ok'; ssl_ind = 'ok'; ssl_detail = 'valid'
    try:
        import datetime as _dt
        # get_server_certificate fetches PEM without verifying trust chain — works for self-signed certs
        pem = _ssl.get_server_certificate(('127.0.0.1', HTTPS_PORT), timeout=2)
        der = _ssl.PEM_cert_to_DER_cert(pem)
        from cryptography import x509 as _x509
        cert_obj  = _x509.load_der_x509_certificate(der)
        exp_dt    = cert_obj.not_valid_after_utc.replace(tzinfo=None)
        days_left = (exp_dt - _dt.datetime.utcnow()).days
        ssl_detail = f"expires in {days_left}d ({exp_dt.strftime('%Y-%m-%d')})"
        if days_left < 7:
            ssl_status = 'critical'; ssl_ind = 'crit'
        elif days_left < 30:
            ssl_status = 'expiring'; ssl_ind = 'warn'
    except Exception as _tls_err:
        logging.warning(f"TLS cert check failed: {_tls_err}")
        ssl_detail = 'check unavailable'
        ssl_ind = 'info'; ssl_status = 'info'

    # ── port liveness ──
    import socket as _sock2
    def _port_open(port: int) -> bool:
        try:
            with _sock2.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except Exception:
            return False

    http_up  = _port_open(HTTP_PORT)
    https_up = _port_open(HTTPS_PORT)
    http_ind    = 'ok'   if http_up  else 'crit'
    https_ind   = 'ok'   if https_up else 'crit'
    http_status = 'operational' if http_up  else 'down'
    https_status= 'operational' if https_up else 'down'

    # ── uptime history bars (from DB — real per-day aggregates) ──────────
    total_days = 90
    history = _get_status_history(total_days)   # newest-first list of dicts
    net_day_hist = _get_net_history_by_day(total_days)  # {date_str: {outage_count, total_downtime_sec}}

    # Overall uptime % = ok samples / total samples (time-accurate, not day-granular)
    total_samples = sum(h['sample_count'] for h in history if h['status'] != 'no_data')
    if total_samples:
        ok_samples = sum(
            round(h['uptime_pct'] / 100 * h['sample_count'])
            for h in history
            if h['status'] != 'no_data' and h['uptime_pct'] is not None
        )
        uptime_pct = round(ok_samples / total_samples * 100, 2)
    else:
        # Fall back to process uptime proxy if we have no history yet
        days_up = min(int(srv_uptime_secs / 86400), total_days)
        uptime_pct = round(days_up / total_days * 100, 2) if days_up > 0 else round(
            srv_uptime_secs / (total_days * 86400) * 100, 2)
        uptime_pct = min(uptime_pct, 100.0)

    # Build bars — history[0] = today (rightmost bar)
    # Each bar is a column of 3 .uptime-seg divs: HTTP (top), HTTPS (middle), DB (bottom).
    # Segment colour: green=no outages, yellow=partial, red=all-samples-down, grey=no data.
    TITLE = {'ok': 'Operational', 'degraded': 'Degraded', 'down': 'Down', 'no_data': 'No data'}
    bars = []
    import html as _html_mod, json as _json_mod

    def _seg_class(down_n: int, total_n: int) -> str:
        if not total_n:       return 'nodata'
        if down_n == 0:       return 'ok'
        if down_n >= total_n: return 'down'
        return 'partial'

    for h in reversed(history):   # oldest → newest = left → right
        st = h['status']
        causes_json = _html_mod.escape(_json_mod.dumps(h.get('causes', []), ensure_ascii=False))
        if st == 'no_data':
            bars.append(
                f'<div class="uptime-bar" title="{h["date"]}: No data" '
                f'data-date="{h["date"]}" data-status="no_data" '
                f'data-uptime="" data-samples="0" '
                f'data-http-down="0" data-https-down="0" data-db-down="0" '
                f'data-mem-max="0" data-disk-max="0" data-causes="{causes_json}" '
                f'data-net-outages="0" data-net-downtime="0">'
                f'<div class="uptime-seg nodata"></div>'
                f'<div class="uptime-seg nodata"></div>'
                f'<div class="uptime-seg nodata"></div>'
                f'<div class="uptime-seg net-nodata"></div>'
                f'</div>'
            )
        else:
            n         = h['sample_count'] or 0
            http_cls  = _seg_class(h.get('http_down_n',  0), n)
            https_cls = _seg_class(h.get('https_down_n', 0), n)
            db_cls    = _seg_class(h.get('db_down_n',    0), n)
            pct_str   = f" ({h['uptime_pct']}%)" if h['uptime_pct'] is not None else ''
            title     = (f"{h['date']}: {TITLE[st]}{pct_str} · "
                         f"HTTP:{http_cls} HTTPS:{https_cls} DB:{db_cls}")
            _nd       = net_day_hist.get(h['date'], {})
            net_outs  = _nd.get('outage_count', 0) or 0
            net_down  = _nd.get('total_downtime_sec', 0) or 0
            if not _nd and n == 0: net_cls = 'net-nodata'
            elif not _nd:          net_cls = 'net-ok'
            elif net_outs == 0:    net_cls = 'net-ok'
            elif net_down >= 300: net_cls = 'net-down'
            else:                 net_cls = 'net-partial'
            net_title = f'{net_outs} outage(s), {net_down}s total' if net_outs else 'ok'
            bars.append(
                f'<div class="uptime-bar" title="{title}" '
                f'data-date="{h["date"]}" data-status="{st}" '
                f'data-uptime="{h["uptime_pct"] or ""}" data-samples="{n}" '
                f'data-http-down="{h.get("http_down_n", 0)}" '
                f'data-https-down="{h.get("https_down_n", 0)}" '
                f'data-db-down="{h.get("db_down_n", 0)}" '
                f'data-mem-max="{h.get("mem_max", 0)}" '
                f'data-disk-max="{h.get("disk_max", 0)}" '
                f'data-causes="{causes_json}" '
                f'data-net-outages="{net_outs}" data-net-downtime="{net_down}">'
                f'<div class="uptime-seg {http_cls}" title="HTTP: {http_cls}"></div>'
                f'<div class="uptime-seg {https_cls}" title="HTTPS: {https_cls}"></div>'
                f'<div class="uptime-seg {db_cls}" title="DB: {db_cls}"></div>'
                f'<div class="uptime-seg {net_cls}" title="NET: {net_title}"></div>'
                f'</div>'
            )
    uptime_bars_html = '\n'.join(bars)

    # ── overall status ──
    with _net_state_lock:
        _cur_net_outage = _net_monitor_state['outage_id'] is not None
    if not http_up or not https_up or db_ind == 'warn':
        overall_class = 'crit'; overall_text = 'Partial Outage'
    elif cdn_disk['ind'] == 'crit' or root_disk['ind'] == 'crit':
        overall_class = 'crit'; overall_text = 'Critical'
    elif ssl_ind == 'crit':
        overall_class = 'crit'; overall_text = 'TLS Certificate Critical'
    elif _cur_net_outage or ssl_ind == 'warn':
        overall_class = 'warn'; overall_text = 'Degraded'
    else:
        overall_class = 'ok'; overall_text = 'All Systems Operational'

    sessions_color = 'blue' if active_sessions > 0 else ''

    # ── incidents & message board ──
    incidents     = _get_recent_incidents(20)
    board_posts   = _get_message_board(10)

    SEV_IND  = {'critical': 'crit', 'degraded': 'warn'}
    SEV_LABEL = {'critical': 'Major Outage', 'degraded': 'Degraded'}

    def _esc(s: str) -> str:
        import html as _html
        return _html.escape(str(s)) if s else ''

    # Build incident rows HTML
    incident_rows_html = ''
    if incidents:
        for inc in incidents:
            ind   = 'crit' if inc['is_open'] else SEV_IND.get(inc['severity'], 'warn')
            badge_text = 'ONGOING' if inc['is_open'] else 'RESOLVED'
            badge_ind  = 'crit'   if inc['is_open'] else 'ok'
            cause_esc = _esc(inc['cause'])
            detail_esc = _esc(inc['detail'] or '')
            started_esc = _esc(inc['started_at'][:16])
            duration_esc = _esc(inc['duration_str'])
            detail_block = (
                f'<div style="font-size:10px;color:var(--muted);margin-top:4px;font-family:var(--mono)">'
                f'{detail_esc}</div>'
            ) if detail_esc else ''
            incident_rows_html += (
                f'<div class="svc-row">'
                f'  <div class="svc-indicator {ind}"></div>'
                f'  <div class="svc-name" style="flex:1">'
                f'    <div>{cause_esc}</div>'
                f'    {detail_block}'
                f'    <div style="font-size:10px;color:var(--muted);margin-top:2px">started {started_esc} · duration {duration_esc}</div>'
                f'  </div>'
                f'  <div class="svc-badge {badge_ind}">{badge_text}</div>'
                f'</div>'
            )
    else:
        incident_rows_html = (
            '<div style="padding:20px 24px;font-size:12px;color:var(--muted)">No incidents recorded yet.</div>'
        )

    # Build message board HTML
    BOARD_IND = {'info': 'info', 'warning': 'warn', 'critical': 'crit', 'ok': 'ok'}
    board_rows_html = ''
    if board_posts:
        for post in board_posts:
            ind = BOARD_IND.get(post['level'], 'info')
            title_esc = _esc(post['title'])
            body_esc  = _esc(post['body'] or '')
            date_esc  = _esc(post['posted_at'][:16])
            body_block = (
                f'<div style="font-size:11px;color:var(--muted);margin-top:4px">{body_esc}</div>'
            ) if body_esc else ''
            board_rows_html += (
                f'<div class="svc-row">'
                f'  <div class="svc-indicator {ind}"></div>'
                f'  <div class="svc-name" style="flex:1">'
                f'    <div>{title_esc}</div>'
                f'    {body_block}'
                f'    <div style="font-size:10px;color:var(--muted);margin-top:2px">{date_esc}</div>'
                f'  </div>'
                f'  <div class="svc-badge {ind}">{post["level"].upper()}</div>'
                f'</div>'
            )
    else:
        board_rows_html = (
            '<div style="padding:20px 24px;font-size:12px;color:var(--muted)">No announcements.</div>'
        )

    return _render_snippet('status_page.html',
        PUBLIC_DOMAIN=PUBLIC_DOMAIN,
        now_str=now_str,
        overall_class=overall_class,
        overall_text=overall_text,
        # system
        sys_uptime_h=sys_uptime_h,
        sys_uptime_str=sys_uptime_str,
        srv_uptime_h=str(srv_h),
        srv_start_str=srv_start_str,
        # db stats
        user_count=user_count,
        active_sessions=active_sessions,
        sessions_color=sessions_color,
        fluxdrop_files=fluxdrop_files,
        fluxdrop_size_str=fluxdrop_size_str,
        catbox_files=catbox_files,
        catbox_size_str=catbox_size_str,
        active_shares=active_shares,
        expired_shares=expired_shares,
        total_share_views=total_share_views,
        # storage
        cdndisk_avail=cdn_disk['avail'], cdndisk_total=cdn_disk['total'],
        cdndisk_used=cdn_disk['used'],   cdndisk_pct=cdn_disk['pct'],
        cdndisk_ind=cdn_disk['ind'],
        rootdisk_avail=root_disk['avail'], rootdisk_total=root_disk['total'],
        rootdisk_used=root_disk['used'],   rootdisk_pct=root_disk['pct'],
        rootdisk_ind=root_disk['ind'],
        tmpdisk_avail=tmp_disk['avail'], tmpdisk_total=tmp_disk['total'],
        tmpdisk_used=tmp_disk['used'],   tmpdisk_pct=tmp_disk['pct'],
        tmpdisk_ind=tmp_disk['ind'],
        # cpu / mem
        cpu_bars_html=cpu_bars_html,
        mem_pct=mem_pct, mem_total=mem_total, mem_used=mem_used, mem_avail=mem_avail,
        swap_pct=swap_pct, swap_total=swap_total, swap_used=swap_used,
        # services
        HTTP_PORT=HTTP_PORT, HTTPS_PORT=HTTPS_PORT,
        http_ind=http_ind, http_status=http_status,
        https_ind=https_ind, https_status=https_status,
        db_ind=db_ind, db_status=db_status, db_size_str=db_size_str,
        ssl_ind=ssl_ind, ssl_status=ssl_status, ssl_detail=ssl_detail,
        # uptime
        uptime_pct=uptime_pct,
        uptime_bars_html=uptime_bars_html,
        # network
        net_rx=net_rx, net_tx=net_tx,
        # incidents & board
        incident_rows_html=incident_rows_html,
        board_rows_html=board_rows_html,
    )

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
    # Chunked resumable upload API:
    #   POST /api/v1/upload_session/init
    #   POST /api/v1/upload_session/<token>/chunk/<index>
    #   POST /api/v1/upload_session/<token>/complete
    #   GET  /api/v1/upload_session/<token>/status
    upload_session_init_pattern     = re.compile(r'^/api/(v[1-3])/upload_session/init$')
    upload_session_config_pattern   = re.compile(r'^/api/(v[1-3])/upload_session/config$')
    upload_speed_probe_pattern      = re.compile(r'^/api/(v[1-3])/upload_session/speed_probe$')
    upload_session_chunk_pattern    = re.compile(r'^/api/(v[1-3])/upload_session/([A-Za-z0-9_\-]+)/chunk/(\d+)$')
    upload_session_complete_pattern = re.compile(r'^/api/(v[1-3])/upload_session/([A-Za-z0-9_\-]+)/complete$')
    upload_session_status_pattern   = re.compile(r'^/api/(v[1-3])/upload_session/([A-Za-z0-9_\-]+)/status$')
    upload_session_cancel_pattern   = re.compile(r'^/api/(v[1-3])/upload_session/([A-Za-z0-9_\-]+)/cancel$')
    board_list_pattern  = re.compile(r'^/api/(v[1-3])/board$')
    board_item_pattern  = re.compile(r'^/api/(v[1-3])/board/(\d+)$')
    incident_pattern    = re.compile(r'^/api/(v[1-3])/incident$')

    def __init__(self, *args, **kwargs):
        # This is crucial for SimpleHTTPRequestHandler to serve files from the correct directory
        super().__init__(*args, directory=SERVE_ROOT, **kwargs)

    # --- Response Helpers ---
    @staticmethod
    def _content_disposition(filename: str) -> str:
        """RFC 5987/8187 Content-Disposition that handles any filename (Cyrillic, spaces, etc.)."""
        try:
            filename.encode('latin-1')
            return f'attachment; filename="{filename}"'
        except (UnicodeEncodeError, UnicodeDecodeError):
            from urllib.parse import quote as _q
            ascii_fallback = filename.encode('ascii', errors='replace').decode('ascii').replace('"', '_')
            return f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{_q(filename, safe="")}'

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
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type, Range, X-Chunk-SHA256, X-Anon-Device-Token')
        self.send_header('Access-Control-Max-Age', '86400')

    def _send_response(self, status_code, content, content_type='application/json'):
        # Append charset for text responses so browsers don't guess the encoding
        if content_type.startswith('text/') and 'charset' not in content_type:
            content_type = content_type + '; charset=utf-8'
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self._send_cors_headers()
            # Security headers (audit items #7, #10)
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'SAMEORIGIN')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
            # Client closed the connection before we finished writing
            # (e.g. after a 460 chunk-hash mismatch). Not an error on our side.
            pass

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

        with _db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP", (token,))
            result = cursor.fetchone()
            if result:
                logging.info(f"Token auth success for user_id '{result[0]}'")
                return result[0] # Return user_id

        logging.warning(f"Token auth failed for token '{token[:8]}…'")
        return None

    def _check_admin_auth(self) -> "dict | None":
        """Validate Bearer token and require is_admin=1. Sends 401/403 on failure."""
        auth_header = self.headers.get('Authorization')
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
        if not token:
            self._send_response(401, json.dumps({'error': 'Authentication required.'}), 'application/json')
            return None
        with _db_connect() as conn:
            row = conn.execute(
                '''SELECT u.id, u.is_admin FROM sessions s
                   JOIN users u ON u.id = s.user_id
                   WHERE s.session_token = ? AND s.expires_at > CURRENT_TIMESTAMP''',
                (token,)
            ).fetchone()
        if not row:
            self._send_response(401, json.dumps({'error': 'Invalid or expired token.'}), 'application/json')
            return None
        user_id, is_admin = row
        if not is_admin:
            self._send_response(403, json.dumps({'error': 'Admin access required.'}), 'application/json')
            return None
        return {'id': user_id, 'is_admin': True}

    def _handle_status_page(self):
        """GET /status — render the system status page."""
        try:
            html = _build_status_page()
            self._send_response(200, html, 'text/html')
        except Exception:
            logging.exception("Failed to render status page")
            self._send_response(500, '<h1>Status page error</h1>', 'text/html')

    def _handle_status_json(self):
        """GET /api/v1/status.json — lightweight JSON snapshot for AJAX polling.

        Returns current live metrics (no auth required — same info as /status page)
        plus the 90-day daily uptime history from the DB.
        """
        import socket as _s2
        def _port_open(port):
            try:
                with _s2.create_connection(('127.0.0.1', port), timeout=1): return True
            except Exception: return False

        http_up  = _port_open(HTTP_PORT)
        https_up = _port_open(HTTPS_PORT)

        # Memory
        mem_pct = 0
        try:
            mem = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    k, v = line.split(':', 1)
                    mem[k.strip()] = int(v.strip().split()[0]) * 1024
            tot = mem.get('MemTotal', 0)
            avail = mem.get('MemAvailable', 0)
            mem_pct = round((tot - avail) / tot * 100) if tot else 0
        except Exception:
            pass

        # Disk
        disk_pct = 0
        try:
            st = os.statvfs(SERVE_ROOT)
            total = st.f_frsize * st.f_blocks
            avail_b = st.f_frsize * st.f_bavail
            disk_pct = round((total - avail_b) / total * 100) if total else 0
        except Exception:
            pass

        # DB liveness
        db_ok = True
        try:
            with _db_connect() as conn:
                conn.execute("SELECT 1")
        except Exception:
            db_ok = False

        # CPU load
        loads = [0.0, 0.0, 0.0]
        try:
            with open('/proc/loadavg') as f:
                parts = f.read().split()
            loads = [float(parts[0]), float(parts[1]), float(parts[2])]
        except Exception:
            pass

        # Server uptime
        srv_uptime_secs = int(time.time() - _SERVER_START_TIME)

        if http_up and https_up and db_ok:
            overall = 'ok'
        elif not http_up or not https_up:
            overall = 'down'
        else:
            overall = 'degraded'

        history = _get_status_history(90)

        with _net_state_lock:
            _s_net_ok  = _net_monitor_state['ok']
            _s_net_lat = _net_monitor_state['latency_ms']
            _s_outage  = _net_monitor_state['outage_id'] is not None

        payload = {
            'overall': overall,
            'http_up': http_up,
            'https_up': https_up,
            'db_ok': db_ok,
            'mem_pct': mem_pct,
            'disk_pct': disk_pct,
            'cpu_load_1': loads[0],
            'cpu_load_5': loads[1],
            'cpu_load_15': loads[2],
            'srv_uptime_secs': srv_uptime_secs,
            'history': history,
            'incidents': _get_recent_incidents(10),
            'board': _get_message_board(5),
            'net_ok':         _s_net_ok,
            'net_latency_ms': _s_net_lat,
            'net_outage_now': _s_outage,
            'net_outages':    _get_net_outages(days=7),
            'net_day_hist':   _get_net_history_by_day(days=90),
        }
        self._send_response(200, json.dumps(payload))

    def _handle_status_day_json(self, date_str: str) -> None:
        """GET /api/v1/status/day/<YYYY-MM-DD> — all raw samples for one day.

        Returns a list of sample objects sorted oldest-first, each with:
          sampled_at, status, http_up, https_up, db_ok, mem_pct, disk_pct, cause
        No auth required (same visibility as /status).
        """
        import re as _re
        if not _re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
            self._send_response(400, json.dumps({'error': 'invalid date'}), 'application/json')
            return
        try:
            with _db_connect() as conn:
                rows = conn.execute(
                    """SELECT sampled_at, status, http_up, https_up,
                              db_ok, mem_pct, disk_pct, cause, net_ok
                       FROM status_snapshots
                       WHERE date(sampled_at, 'localtime') = ?
                       ORDER BY sampled_at ASC""",
                    (date_str,)
                ).fetchall()
        except Exception:
            self._send_response(500, json.dumps({'error': 'db error'}), 'application/json')
            return

        samples = []
        for r in rows:
            samples.append({
                'sampled_at': r[0],
                'status':     r[1],
                'http_up':    bool(r[2]),
                'https_up':   bool(r[3]),
                'db_ok':      bool(r[4]),
                'mem_pct':    r[5],
                'disk_pct':   r[6],
                'cause':      r[7],
                'net_ok':     bool(r[8]) if r[8] is not None else True,
            })

        # Fetch net outage windows that overlap with this day (localtime)
        # started_at/ended_at are Unix timestamps; convert to localtime ISO strings for the client
        day_start = datetime.strptime(date_str, '%Y-%m-%d')
        day_end   = day_start + timedelta(days=1)
        # time.mktime() treats naive datetime as local time — correct for any timezone/DST
        ts_start = time.mktime(day_start.timetuple())
        ts_end   = time.mktime(day_end.timetuple())
        net_windows = []
        try:
            with _db_connect() as conn2:
                net_rows = conn2.execute(
                    """SELECT started_at, COALESCE(ended_at, ?), duration_sec
                       FROM net_outages
                       WHERE started_at < ? AND (ended_at IS NULL OR ended_at > ?)
                       ORDER BY started_at ASC""",
                    (time.time(), ts_end, ts_start)
                ).fetchall()
            for nr in net_rows:
                net_windows.append({
                    'started_ts':   float(nr[0]),
                    'ended_ts':     float(nr[1]),
                    'duration_sec': nr[2],
                })
        except Exception:
            logging.exception('status/day: failed to fetch net_windows')

        self._send_response(200, json.dumps({'date': date_str, 'samples': samples, 'net_windows': net_windows}), 'application/json')

    def _handle_net_outage_note(self, outage_id: str) -> None:
        """POST /api/v1/net_outage/<id>/note  {"note": "..."}  — admin only."""
        if not _rate_limit(self.client_address[0], "api"):
            self._send_response(429, json.dumps({'error': 'Too many requests.'}), 'application/json')
            return
        user = self._check_admin_auth()
        if not user:
            return
        cl = int(self.headers.get('Content-Length', 0))
        if cl > 4096:
            self._send_response(413, json.dumps({'error': 'Request too large.'}), 'application/json')
            return
        try:
            body = json.loads(self.rfile.read(cl))
            note = str(body.get('note', '') or '').strip() or None
            oid  = int(outage_id)
        except Exception:
            self._send_response(400, json.dumps({'error': 'bad request'}), 'application/json')
            return
        try:
            with _db_connect() as conn:
                conn.execute('UPDATE net_outages SET note=? WHERE id=?', (note, oid))
                conn.commit()
        except Exception:
            self._send_response(500, json.dumps({'error': 'db error'}), 'application/json')
            return
        self._send_response(200, json.dumps({'ok': True, 'id': oid, 'note': note}), 'application/json')

    def _handle_board_post(self) -> None:
        """POST /api/v1/board  {level, title, body}  — admin only."""
        if not _rate_limit(self.client_address[0], 'api'):
            return self._send_response(429, json.dumps({'error': 'Rate limit exceeded.'}))
        user = self._check_admin_auth()
        if not user:
            return
        cl = int(self.headers.get('Content-Length', 0))
        if cl <= 0 or cl > MAX_JSON_BODY:
            return self._send_response(400, json.dumps({'error': 'Invalid body.'}))
        try:
            data = json.loads(self.rfile.read(cl))
        except Exception:
            return self._send_response(400, json.dumps({'error': 'Invalid JSON.'}))
        level = str(data.get('level', 'info'))
        title = str(data.get('title', '')).strip()
        body  = str(data.get('body', '') or '').strip() or None
        if level not in ('info', 'warning', 'critical', 'ok'):
            level = 'info'
        if not title:
            return self._send_response(400, json.dumps({'error': 'title is required.'}))
        if len(title) > 200:
            return self._send_response(400, json.dumps({'error': 'title too long (max 200).'}))
        if body and len(body) > 2000:
            return self._send_response(400, json.dumps({'error': 'body too long (max 2000).'}))
        try:
            with _db_connect() as conn:
                cur = conn.execute(
                    'INSERT INTO message_board (level, title, body) VALUES (?, ?, ?)',
                    (level, title, body)
                )
                conn.commit()
                row_id = cur.lastrowid
            logging.info(f"Board post created by admin {user['id']}: [{level}] {title!r}")
            return self._send_response(200, json.dumps({'ok': True, 'id': row_id}), 'application/json')
        except Exception:
            logging.exception('Failed to create board post')
            return self._send_response(500, json.dumps({'error': 'Internal server error.'}))

    def _handle_board_delete(self, post_id: str) -> None:
        """DELETE /api/v1/board/<id>  — admin only."""
        if not _rate_limit(self.client_address[0], 'api'):
            return self._send_response(429, json.dumps({'error': 'Rate limit exceeded.'}))
        user = self._check_admin_auth()
        if not user:
            return
        try:
            pid = int(post_id)
        except ValueError:
            return self._send_response(400, json.dumps({'error': 'Invalid id.'}))
        try:
            with _db_connect() as conn:
                cur = conn.execute('DELETE FROM message_board WHERE id = ?', (pid,))
                conn.commit()
            if cur.rowcount == 0:
                return self._send_response(404, json.dumps({'error': 'Post not found.'}))
            logging.info(f"Board post {pid} deleted by admin {user['id']}")
            return self._send_response(200, json.dumps({'ok': True}), 'application/json')
        except Exception:
            logging.exception('Failed to delete board post')
            return self._send_response(500, json.dumps({'error': 'Internal server error.'}))

    def _handle_incident_create(self) -> None:
        """POST /api/v1/incident  {cause, started_at, ended_at?, severity}  — admin only.

        Inserts a manual entry into the incidents table so planned maintenance
        and missed outages appear in the incident log on the status page.
        started_at / ended_at are local-time strings (YYYY-MM-DDTHH:MM) from
        the browser datetime-local input — stored as-is (treated as local by
        the existing incident rendering logic).
        """
        if not _rate_limit(self.client_address[0], 'api'):
            return self._send_response(429, json.dumps({'error': 'Rate limit exceeded.'}))
        user = self._check_admin_auth()
        if not user:
            return
        cl = int(self.headers.get('Content-Length', 0))
        if cl <= 0 or cl > MAX_JSON_BODY:
            return self._send_response(400, json.dumps({'error': 'Invalid body.'}))
        try:
            data = json.loads(self.rfile.read(cl))
        except Exception:
            return self._send_response(400, json.dumps({'error': 'Invalid JSON.'}))
        cause    = str(data.get('cause', '')).strip()
        started  = str(data.get('started_at', '')).strip()
        ended    = str(data.get('ended_at', '') or '').strip() or None
        severity = str(data.get('severity', 'degraded'))
        if not cause:
            return self._send_response(400, json.dumps({'error': 'cause is required.'}))
        if not started:
            return self._send_response(400, json.dumps({'error': 'started_at is required.'}))
        if severity not in ('degraded', 'critical'):
            severity = 'degraded'
        # Normalise datetime-local T separator to space for DB consistency
        started = started.replace('T', ' ')
        if ended:
            ended = ended.replace('T', ' ')
        try:
            with _db_connect() as conn:
                # Reuse the incident_log table (same schema used by the automatic monitor)
                cur = conn.execute(
                    '''INSERT INTO incident_log (cause, started_at, resolved_at, severity, detail)
                       VALUES (?, ?, ?, ?, ?)''',
                    (cause, started, ended, severity, '(manual entry)')
                )
                conn.commit()
                inc_id = cur.lastrowid
            logging.info(
                f"Manual incident created by admin {user['id']}: "
                f"[{severity}] {cause!r} {started}–{ended or 'open'}"
            )
            return self._send_response(200, json.dumps({'ok': True, 'id': inc_id}), 'application/json')
        except Exception:
            logging.exception('Failed to create manual incident')
            return self._send_response(500, json.dumps({'error': 'Internal server error.'}))

    # --- Chunked / Resumable Upload API ---


    def _check_upload_session_auth(self, session: dict) -> tuple[bool, str]:
        """Verify the caller is allowed to interact with this upload session.

        Rules:
          • owner_type == 'user' or 'catbox'  → must present a valid session token
            whose user_id matches session['owner_ref'].
          • owner_type == 'share' (anon path)  → session['anon_device_token'] must be
            present and must match the X-Anon-Device-Token request header.

        Returns (ok: bool, reason: str).
        """
        owner_type = session.get('owner_type')
        if owner_type in ('user', 'catbox'):
            user_id = self._check_token_auth()
            if user_id is None:
                return False, 'Unauthorized: valid session token required.'
            if str(user_id) != str(session.get('owner_ref')):
                return False, 'Forbidden: session token does not match upload owner.'
            return True, ''
        elif owner_type == 'share':
            expected = session.get('anon_device_token')
            if not expected:
                # Should not happen, but treat as a server-side bug
                return False, 'Upload session has no device token (internal error).'
            provided = self.headers.get('X-Anon-Device-Token', '').strip()
            if not provided:
                return False, 'Unauthorized: X-Anon-Device-Token header required for anonymous uploads.'
            if not secrets.compare_digest(expected, provided):
                return False, 'Forbidden: device token mismatch.'
            return True, ''
        return False, f'Unknown owner_type: {owner_type}'

    def handle_upload_session_config(self):
        """GET /api/v1/upload_session/config
        Returns server-side upload configuration so clients can compute
        total_chunks correctly before calling /init.  No auth required —
        these are non-sensitive server constants, equivalent to advertising
        API limits in a public spec.
        """
        return self._send_response(200, json.dumps({
            'chunk_size':     UPLOAD_CHUNK_SIZE,
            'session_ttl':    UPLOAD_SESSION_TTL,
            'max_chunk_size': UPLOAD_CHUNK_SIZE * 2,  # mirrors the 413 guard in handle_upload_session_chunk
        }))

    def handle_upload_speed_probe(self):
        """POST /api/v1/upload_session/speed_probe
        Accepts an arbitrary binary payload (up to 2 MB) and immediately
        discards it, returning the number of bytes received.  Used by the
        client to measure real upload bandwidth before the first chunk so
        the ETA seed is accurate rather than a hardcoded guess.
        No auth required — payload is discarded, no storage is touched.
        """
        MAX_PROBE = 2 * 1024 * 1024  # 2 MB hard cap
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length < 0 or content_length > MAX_PROBE:
            return self._send_response(400, json.dumps({'error': 'Probe payload must be 1 B – 2 MB.'}))
        # Read and immediately discard — we only care about the timing
        _ = self.rfile.read(content_length)
        return self._send_response(200, json.dumps({'bytes_received': content_length}))

    def handle_upload_session_init(self):
        """POST /api/v1/upload_session/init
        Body JSON:
          filename      — original filename (required)
          dest_path     — server-side destination relative to owner's root (required)
          total_size    — total file size in bytes (required)
          total_chunks  — number of chunks the client will send (required)
          sha256        — optional whole-file SHA-256 hex for final verification
          owner_type    — 'user' | 'share' | 'catbox'
          share_token   — required when owner_type == 'share'

        Auth rules:
          • owner_type 'user'/'catbox' → valid Bearer session token required (registered users only).
          • owner_type 'share'         → share must have allow_anon_upload OR (allow_auth_upload
            AND a valid session token). The server mints an anon_device_token returned to the
            caller; the client must store it and send it as X-Anon-Device-Token on every subsequent
            chunk/complete/status call.  Cross-device resume is intentionally not supported for
            anonymous uploads because the token cannot be transferred.

        Returns JSON: { upload_token, chunk_size, total_chunks [, anon_device_token] }
        """
        user_id = self._check_token_auth()
        try:
            length = int(self.headers.get('Content-Length', 0))
            data   = json.loads(self.rfile.read(length))
        except Exception:
            return self._send_response(400, json.dumps({'error': 'Invalid JSON body.'}))

        filename     = data.get('filename', '').strip()
        dest_rel     = data.get('dest_path', '').strip()
        total_size   = int(data.get('total_size', -1))
        total_chunks = int(data.get('total_chunks', -1))
        sha256_final = data.get('sha256') or None
        owner_type   = data.get('owner_type', 'user')
        share_token  = data.get('share_token', '')

        if not filename or not dest_rel or total_chunks < 1:
            return self._send_response(400, json.dumps({'error': 'filename, dest_path, total_chunks required.'}))

        anon_device_token: str | None = None

        # Resolve absolute dest_path and owner_ref
        if owner_type == 'user':
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Unauthorized: registered users only.'}))
            base_fs = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
            dest_path = os.path.normpath(os.path.join(base_fs, dest_rel.lstrip('/')))
            if not os.path.realpath(dest_path).startswith(os.path.realpath(base_fs)):
                return self._send_response(400, json.dumps({'error': 'Invalid dest_path.'}))
            owner_ref = str(user_id)

        elif owner_type == 'share':
            share = _get_share(share_token)
            if not share or not share['is_dir']:
                return self._send_response(404, json.dumps({'error': 'Share not found.'}))
            # Determine whether this caller is allowed to upload to this share
            anon_ok = bool(share['allow_anon_upload'])
            auth_ok = bool(share['allow_auth_upload']) and user_id is not None
            if not anon_ok and not auth_ok:
                return self._send_response(403, json.dumps({'error': 'Uploads not permitted on this share.'}))
            owner_id_s = share['owner_id']
            base_path_str = share['path']
            if base_path_str.startswith('/cdn'):
                base_fs = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, base_path_str[len('/cdn'):].lstrip('/')))
            else:
                base_fs = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(owner_id_s), base_path_str.lstrip('/')))
            dest_path = os.path.normpath(os.path.join(base_fs, dest_rel.lstrip('/')))
            if not os.path.realpath(dest_path).startswith(os.path.realpath(base_fs)):
                return self._send_response(400, json.dumps({'error': 'Invalid dest_path.'}))
            owner_ref = share_token
            # Always mint a device token for share uploads; the client stores it locally.
            # For authenticated visitors it still acts as the binding token — keeps the
            # logic uniform and avoids leaking which device a session belongs to.
            anon_device_token = secrets.token_urlsafe(32)

        elif owner_type == 'catbox':
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Unauthorized: registered users only.'}))
            file_ext  = os.path.splitext(filename)[1]
            rand_name = secrets.token_urlsafe(6).lower().replace('-','').replace('_','')
            dest_path = os.path.normpath(os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR, rand_name + file_ext))
            owner_ref = str(user_id)
        else:
            return self._send_response(400, json.dumps({'error': f'Unknown owner_type: {owner_type}'}))

        try:
            session = _upload_init(
                filename=os.path.basename(filename),
                dest_path=dest_path,
                total_size=total_size,
                total_chunks=total_chunks,
                sha256_final=sha256_final,
                owner_type=owner_type,
                owner_ref=owner_ref,
                anon_device_token=anon_device_token,
            )
            logging.info(f'Upload session init: token={session["upload_token"][:12]}… file={filename} chunks={total_chunks} owner={owner_type}')
            resp: dict = {
                'upload_token': session['upload_token'],
                'chunk_size':   session['chunk_size'],
                'total_chunks': total_chunks,
            }
            if anon_device_token:
                resp['anon_device_token'] = anon_device_token
            return self._send_response(200, json.dumps(resp))
        except Exception as e:
            logging.exception('Failed to init upload session')
            return self._send_response(500, json.dumps({'error': str(e)}))

    def handle_upload_session_chunk(self, upload_token: str, chunk_index: int):
        """POST /api/v1/upload_session/<token>/chunk/<index>
        Body: raw binary chunk data.
        Headers: Content-Length (required), X-Chunk-SHA256 (optional per-chunk hash).
        Auth: Bearer session token (registered users) or X-Anon-Device-Token (share anon uploads).
        Returns JSON: { chunks_received, missing_chunks }
        """
        session = _upload_get(upload_token)
        if not session:
            return self._send_response(404, json.dumps({'error': 'Upload session not found.'}))
        if session['completed']:
            return self._send_response(409, json.dumps({'error': 'Session already completed.'}))

        ok, reason = self._check_upload_session_auth(session)
        if not ok:
            return self._send_response(403, json.dumps({'error': reason}))

        # Validate chunk index
        if session['total_chunks'] > 0 and chunk_index >= session['total_chunks']:
            return self._send_response(400, json.dumps({'error': f'chunk_index {chunk_index} out of range.'}))

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length <= 0:
            return self._send_response(400, json.dumps({'error': 'Content-Length required.'}))
        if content_length > UPLOAD_CHUNK_SIZE * 2:
            return self._send_response(413, json.dumps({'error': 'Chunk too large.'}))

        # Read raw chunk directly from socket — no /tmp involved
        data = self.rfile.read(content_length)

        # Optional per-chunk SHA-256 verification
        expected_sha = self.headers.get('X-Chunk-SHA256', '').strip().lower()
        if expected_sha:
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected_sha:
                return self._send_response(460, json.dumps({
                    'error': 'Chunk SHA-256 mismatch.',
                    'expected': expected_sha, 'actual': actual_sha,
                }))

        try:
            updated = _upload_receive_chunk(upload_token, chunk_index, data)
            status  = _upload_session_status(updated)
            logging.info(f'Chunk received: token={upload_token[:12]}… idx={chunk_index} '
                         f'({len(data)//1024}KB) {len(status["chunks_received"])}/{updated["total_chunks"]}')
            return self._send_response(200, json.dumps(status))
        except KeyError as e:
            # Session disappeared mid-flight — normal when cancel fires concurrently
            logging.info(f'Chunk {chunk_index} for {upload_token[:12]}… dropped: session gone (cancelled)')
            return self._send_response(404, json.dumps({'error': 'Upload session not found (cancelled?)'}))
        except Exception as e:
            logging.exception(f'Failed to receive chunk {chunk_index} for {upload_token[:12]}…')
            return self._send_response(500, json.dumps({'error': str(e)}))

    def handle_upload_session_complete(self, upload_token: str):
        """POST /api/v1/upload_session/<token>/complete
        Assembles all chunks, verifies whole-file SHA-256 if provided, moves to dest_path.
        Auth: Bearer session token (registered users) or X-Anon-Device-Token (share anon uploads).
        Returns JSON: { url, sha256, size }
        """
        session = _upload_get(upload_token)
        if not session:
            return self._send_response(404, json.dumps({'error': 'Upload session not found.'}))
        if session['completed']:
            return self._send_response(409, json.dumps({'error': 'Already completed.'}))

        ok, reason = self._check_upload_session_auth(session)
        if not ok:
            return self._send_response(403, json.dumps({'error': reason}))

        try:
            dest_path = _upload_assemble(upload_token)
        except ValueError as e:
            return self._send_response(422, json.dumps({'error': str(e)}))
        except Exception as e:
            logging.exception('Upload assembly failed')
            return self._send_response(500, json.dumps({'error': str(e)}))

        # Build public URL
        owner_type = session['owner_type']
        if owner_type == 'catbox':
            rel = os.path.relpath(dest_path, SERVE_ROOT).replace(os.sep, '/')
            file_url = f'https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/{rel}'
        elif owner_type == 'share':
            share = _get_share(session['owner_ref'])
            owner_id_s = share['owner_id'] if share else 'unknown'
            rel = os.path.relpath(dest_path, os.path.join(SERVE_ROOT, 'FluxDrop', str(owner_id_s))).replace(os.sep, '/')
            file_url = f'https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/FluxDrop/{owner_id_s}/{rel}'
        else:
            owner_ref = session['owner_ref']
            rel = os.path.relpath(dest_path, os.path.join(SERVE_ROOT, 'FluxDrop', owner_ref)).replace(os.sep, '/')
            file_url = f'https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/FluxDrop/{owner_ref}/{rel}'

        size = os.path.getsize(dest_path)
        with open(dest_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest() if size < 500 * 1024 * 1024 else 'skipped (>500MB)'

        logging.info(f'Upload complete: {dest_path} ({size} bytes) token={upload_token[:12]}…')
        return self._send_response(200, json.dumps({'url': file_url, 'sha256': sha256, 'size': size}))

    def handle_upload_session_cancel(self, upload_token: str):
        """DELETE /api/v1/upload_session/<token>
        Immediately deletes the tmp chunk directory and DB row for an in-progress
        upload session.  Safe to call when the user cancels — avoids waiting 48 h
        for the TTL purge to reclaim the disk space.
        Auth: same rules as chunk upload.
        Returns JSON: { cancelled: true }
        """
        session = _upload_get(upload_token)
        if not session:
            # Already gone — treat as success
            return self._send_response(200, json.dumps({'cancelled': True}))
        if session['completed']:
            return self._send_response(409, json.dumps({'error': 'Session already completed.'}))

        ok, reason = self._check_upload_session_auth(session)
        if not ok:
            return self._send_response(403, json.dumps({'error': reason}))

        try:
            tmp_dir = session['tmp_dir']
            with _db_connect() as conn:
                conn.execute('DELETE FROM upload_sessions WHERE upload_token = ?', (upload_token,))
                conn.commit()
            _release_chunk_lock(upload_token)
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
            logging.info(f'Upload session cancelled and cleaned up: token={upload_token[:12]}…')
            return self._send_response(200, json.dumps({'cancelled': True}))
        except Exception as e:
            logging.exception('Failed to cancel upload session')
            return self._send_response(500, json.dumps({'error': str(e)}))

    def handle_upload_session_status(self, upload_token: str):
        """GET /api/v1/upload_session/<token>/status
        Returns which chunks have been received and which are still missing.
        Auth: Bearer session token (registered users) or X-Anon-Device-Token (share anon uploads).
        Cross-device resume is only supported for registered users (share/anon callers must
        supply the device token they received at init time).
        """
        session = _upload_get(upload_token)
        if not session:
            return self._send_response(404, json.dumps({'error': 'Upload session not found.'}))

        ok, reason = self._check_upload_session_auth(session)
        if not ok:
            return self._send_response(403, json.dumps({'error': reason}))

        return self._send_response(200, json.dumps(_upload_session_status(session)))

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
        with blacklist_lock:
            if self.client_address[0] in current_blacklist:
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))
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
        with blacklist_lock:
            if self.client_address[0] in current_blacklist:
                return self._send_response(403, json.dumps({"error": "Forbidden"}))
        parsed_url = urlparse(self.path)

        # Status page
        if parsed_url.path == '/status':
            return self._handle_status_page()

        # JSON status API (for AJAX updates and external monitoring)
        if parsed_url.path == '/api/v1/status.json':
            return self._handle_status_json()

        # Per-day sample detail for the status modal
        _day_m = re.match(r'^/api/v1/status/day/(\d{4}-\d{2}-\d{2})$', parsed_url.path)
        if _day_m:
            return self._handle_status_day_json(_day_m.group(1))

        # Chunked upload session config (no auth — public server constants)
        if self.upload_session_config_pattern.match(parsed_url.path):
            return self.handle_upload_session_config()

        # Chunked upload session status
        us_status = self.upload_session_status_pattern.match(parsed_url.path)
        if us_status:
            return self.handle_upload_session_status(us_status.group(2))

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
        with blacklist_lock:
            if self.client_address[0] in current_blacklist:
                return self._send_response(403, json.dumps({"error": "Forbidden"}))
        parsed_url = urlparse(self.path)

        # Chunked upload session endpoints (before auth so chunk upload works with upload_token)
        if self.upload_session_init_pattern.match(parsed_url.path):
            return self.handle_upload_session_init()
        if self.upload_speed_probe_pattern.match(parsed_url.path):
            return self.handle_upload_speed_probe()
        us_chunk = self.upload_session_chunk_pattern.match(parsed_url.path)
        if us_chunk:
            return self.handle_upload_session_chunk(us_chunk.group(2), int(us_chunk.group(3)))
        us_complete = self.upload_session_complete_pattern.match(parsed_url.path)
        if us_complete:
            return self.handle_upload_session_complete(us_complete.group(2))

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
                if content_len > MAX_JSON_BODY:
                    return self._send_response(413, json.dumps({"error": "Request body too large."}))
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

        # Public share upload: POST /share/<token>/upload[?subpath=...]
        pub_upload = re.match(r'^/share/([A-Za-z0-9_\-]+)/upload$', parsed_url.path)
        if pub_upload:
            return self.handle_public_share_upload(pub_upload.group(1))

        # Public share mkdir: POST /share/<token>/mkdir
        pub_mkdir = re.match(r'^/share/([A-Za-z0-9_\-]+)/mkdir$', parsed_url.path)
        if pub_mkdir:
            return self.handle_public_share_mkdir(pub_mkdir.group(1))

        # CatBox API
        if parsed_url.path == self.catbox_api_path:
            return self.handle_catbox_api()

        # FluxDrop API
        flux_match = self.fluxdrop_api_pattern.match(parsed_url.path)
        if flux_match:
            return self.handle_fluxdrop_api_post(flux_match)

        # Net outage note
        _note_m = re.match(r'^/api/v1/net_outage/(\d+)/note$', parsed_url.path)
        if _note_m:
            return self._handle_net_outage_note(_note_m.group(1))

        # Admin: message board post
        if parsed_url.path == '/api/v1/board':
            return self._handle_board_post()

        # Admin: manual incident creation
        if parsed_url.path == '/api/v1/incident':
            return self._handle_incident_create()

        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    def do_PATCH(self):
        """Routes PATCH requests (used to update share settings)."""
        with blacklist_lock:
            if self.client_address[0] in current_blacklist:
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))
        parsed_url = urlparse(self.path)
        item_match = self.shares_item_pattern.match(parsed_url.path)
        if item_match:
            return self.handle_share_update(item_match.group(2))
        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    def do_DELETE(self):
        """Routes DELETE requests (used to revoke shares and cancel upload sessions)."""
        with blacklist_lock:
            if self.client_address[0] in current_blacklist:
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))
        parsed_url = urlparse(self.path)
        us_cancel = self.upload_session_cancel_pattern.match(parsed_url.path)
        if us_cancel:
            return self.handle_upload_session_cancel(us_cancel.group(2))
        item_match = self.shares_item_pattern.match(parsed_url.path)
        if item_match:
            return self.handle_share_delete(item_match.group(2))
        # Admin: delete board post
        _board_del = re.match(r'^/api/v1/board/(\d+)$', parsed_url.path)
        if _board_del:
            return self._handle_board_delete(_board_del.group(1))
        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    # --- Auth API Handlers ---
    def handle_auth_register(self, data):
        """Handles user registration."""
        client_ip = self.client_address[0]
        if not _rate_limit(client_ip, "auth"):
            logging.warning(f"Rate limit hit on register from {client_ip}")
            return self._send_response(429, json.dumps({"error": "Too many attempts. Please wait a minute."}))
        username = data.get('username')
        nickname = data.get('nickname')
        email = data.get('email')
        password = data.get('password')

        if not all([username, nickname, email, password]):
            return self._send_response(400, json.dumps({"error": "Missing required fields."}))

        # N12: Enforce maximum field lengths before any expensive hashing
        _MAX_USERNAME = 64
        _MAX_NICKNAME = 64
        _MAX_EMAIL    = 254   # RFC 5321 maximum
        _MAX_PASSWORD = 1024  # bcrypt only uses first 72 bytes; cap well above that
        if (len(username) > _MAX_USERNAME or
                len(nickname) > _MAX_NICKNAME or
                len(email)    > _MAX_EMAIL    or
                len(password) > _MAX_PASSWORD):
            return self._send_response(
                400, json.dumps({'error': 'One or more fields exceed the maximum allowed length.'})
            )
        import re as _re
        if not _re.match(r'^[A-Za-z0-9_\-\.]{3,64}$', username):
            return self._send_response(
                400, json.dumps({'error': 'Username must be 3–64 characters: letters, digits, _ - .'})
            )

        with _db_connect() as conn:
            cursor = conn.cursor()
            # Check against confirmed users first
            cursor.execute("SELECT id FROM users WHERE username = ? OR nickname = ? OR email = ?", (username, nickname, email))
            if cursor.fetchone():
                return self._send_response(409, json.dumps({"error": "Username, nickname, or email already exists."}))
            # Also ensure we don't already have a *non-expired* pending verification for the same details.
            # Expired rows are ignored here; the stale row is overwritten by the DELETE+INSERT below.
            cursor.execute(
                "SELECT id FROM pending_verifications WHERE (username = ? OR nickname = ? OR email = ?) AND expires_at > CURRENT_TIMESTAMP",
                (username, nickname, email)
            )
            if cursor.fetchone():
                return self._send_response(409, json.dumps({"error": "A registration is already pending for that username, nickname or email."}))

        password_hash, salt = hash_password(password)
        verification_token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(hours=1)).isoformat()

        with _db_connect() as conn:
            cursor = conn.cursor()
            try:
                # Purge any expired rows for the same identity before inserting the fresh one
                cursor.execute(
                    "DELETE FROM pending_verifications WHERE (username = ? OR nickname = ? OR email = ?) AND expires_at <= CURRENT_TIMESTAMP",
                    (username, nickname, email)
                )
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

        with _db_connect() as conn:
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
        client_ip = self.client_address[0]
        if not _rate_limit(client_ip, "auth"):
            logging.warning(f"Rate limit hit on login from {client_ip}")
            return self._send_response(429, json.dumps({"error": "Too many login attempts. Please wait a minute."}))
        username = data.get('username')
        password = data.get('password')

        if not all([username, password]):
            return self._send_response(400, json.dumps({"error": "Missing username or password."}))

        with _db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user:
                logging.info(f"Login attempt for unknown user: {username}")
                return self._send_response(401, json.dumps({"error": "Invalid credentials."}))

            user_id, stored_hash, salt = user

            # Transparent bcrypt migration:
            # - New hashes start with '$2b$' (bcrypt). Verify with bcrypt.checkpw.
            # - Old hashes are hex strings (SHA-256). Verify with the legacy path,
            #   then immediately re-hash with bcrypt and update the DB row so the
            #   user migrates silently on their next successful login.
            if stored_hash.startswith('$2b$'):
                # bcrypt path — timing-safe by design
                if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    logging.info(f"Login failed for user_id={user_id} (username={username}): bcrypt mismatch")
                    return self._send_response(401, json.dumps({"error": "Invalid credentials."}))
            else:
                # Legacy SHA-256 path
                legacy_hash, _ = _sha256_hash(password, salt)
                if not secrets.compare_digest(legacy_hash, stored_hash):
                    logging.info(f"Login failed for user_id={user_id} (username={username}): sha256 mismatch")
                    return self._send_response(401, json.dumps({"error": "Invalid credentials."}))
                # Upgrade in place — store bcrypt hash, clear the now-unused salt column
                new_hash, _ = hash_password(password)
                cursor.execute(
                    "UPDATE users SET password_hash=?, salt=? WHERE id=?",
                    (new_hash, '', user_id)
                )
                logging.info(f"Migrated user_id={user_id} from SHA-256 to bcrypt on login")

            # Issue a new session token
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(days=7) # Session expires in 7 days
            cursor.execute(
                "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
                (user_id, session_token, expires_at)
            )
            conn.commit()
            conn.execute("DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP")
            conn.commit()

        return self._send_response(200, json.dumps({"message": "Login successful.", "token": session_token, "username": username}))

    def handle_auth_logout(self):
        """Handles user logout by deleting the session token."""
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return self._send_response(400, json.dumps({"error": "No token provided."}))

        token = auth_header.split(' ', 1)[1]
        with _db_connect() as conn:
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
            allow_preview=bool(data.get("allow_preview", False)),
            allow_cdn_embed=bool(data.get("allow_cdn_embed", False)),
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
            raw = _get_share_raw(token)
            if raw and _is_share_expired(raw):
                return self._send_response(410, self._render_share_expired_page(), "text/html")
            return self._send_response(404, self._render_share_not_found_page(), "text/html")

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
        # Decode percent-encoding so filenames with spaces/non-ASCII resolve on disk.
        if sub_path:
            sub_path = unquote(sub_path)
        if sub_path and sub_path.strip("/"):
            target_fs = os.path.normpath(os.path.join(base_fs, sub_path.lstrip("/")))
        else:
            target_fs = base_fs

        # Security: stay within the shared base
        if not os.path.realpath(target_fs).startswith(os.path.realpath(base_fs)):
            return self._send_response(403, json.dumps({"error": "Forbidden: path outside shared area."}))

        # --- CDN embed / inline serving ---
        # When allow_cdn_embed is set on a single-file share, serve the file
        # with its real MIME type and no Content-Disposition: attachment so
        # browsers (and Discord, Slack, etc.) can embed/preview it directly.
        # The share URL itself acts as a public CDN URL — no auth needed.
        _cdn_embed = bool(share.get("allow_cdn_embed")) and not share.get("is_dir") and os.path.isfile(target_fs)
        # allow_preview: for a ?preview=1 query param on single-file share, or
        # for files inside a folder share that has allow_preview set.
        _preview_mode = (
            _cdn_embed or
            (bool(share.get("allow_preview")) and os.path.isfile(target_fs) and
             parse_qs(parsed_url.query).get("preview", [None])[0] == "1")
        )

        # --- File serving ---
        if os.path.isfile(target_fs):
            # Choose content type and disposition based on mode
            if _preview_mode or _cdn_embed:
                import mimetypes as _mt
                content_type = _mt.guess_type(target_fs)[0] or "application/octet-stream"
                disposition = None  # inline — no Content-Disposition header
                action = "preview" if _preview_mode and not _cdn_embed else "embed"
            else:
                content_type = "application/octet-stream"
                disposition = self._content_disposition(os.path.basename(target_fs))
                action = "download"

            if share["track_stats"]:
                _log_share_access(token, visitor_user_id, action=action)

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
                self.send_header("Content-Type", content_type)
                if disposition:
                    self.send_header("Content-Disposition", disposition)
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
                self.send_header("Content-Type", content_type)
                if disposition:
                    self.send_header("Content-Disposition", disposition)
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
            with _db_connect() as conn:
                r = conn.execute("SELECT nickname FROM users WHERE id = ?", (share["owner_id"],)).fetchone()
                if r: owner_name = r[0]
        except Exception: pass

        sub_path_clean = (sub_path or "").strip("/")
        visitor_user_id = self._check_token_auth()

        # --- Breadcrumb ---
        crumb_parts = sub_path_clean.split("/") if sub_path_clean else []
        crumbs_html = f'<a href="/share/{token}" style="color:#3b82f6;text-decoration:none">Home</a>'
        for i, part in enumerate(crumb_parts):
            crumb_url = "/share/" + token + "/" + "/".join(quote(seg, safe="") for seg in crumb_parts[:i+1])
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
                entry_url = "/share/" + token + "/" + "/".join(quote(seg, safe="") for seg in rel_from_base.split("/"))
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
                    # Preview URL: same as entry_url but with ?preview=1
                    preview_url = entry_url + "?preview=1"
                    allow_prev = bool(share.get("allow_preview"))
                    name_cell = (
                        f'<a href="{preview_url}" onclick="previewShareFile({repr(entry_url)},{repr(name)},event)" '
                        f'style="color:#1e293b;text-decoration:none;cursor:pointer">📄 {name}</a>'
                        if allow_prev else
                        f'<a href="{entry_url}" download style="color:#1e293b;text-decoration:none">📄 {name}</a>'
                    )
                    preview_btn = (
                        f'<a href="{preview_url}" onclick="previewShareFile({repr(entry_url)},{repr(name)},event)" '
                        f'style="background:#8b5cf6;color:white;text-decoration:none;padding:3px 10px;border-radius:5px;font-size:12px;margin-right:4px">👁</a>'
                        if allow_prev else ""
                    )
                    rows += f"""<tr class="entry-row">
                        <td style="padding:8px 12px 8px {12+pad}px">{name_cell}</td>
                        <td style="padding:8px 12px;color:#64748b;font-size:13px">{size_str}</td>
                        <td style="padding:8px 12px;color:#94a3b8;font-size:13px">{mtime}</td>
                        <td style="padding:8px 12px">
                            {preview_btn}<a href="{entry_url}" download
                               style="background:#3b82f6;color:white;text-decoration:none;padding:3px 10px;border-radius:5px;font-size:12px">↓</a>
                        </td>
                    </tr>"""
            return rows

        # If we're looking at a sub-folder page, show only its contents; else show full tree from root
        list_root = target_fs if os.path.isdir(target_fs) else base_fs
        if sub_path_clean and os.path.isdir(target_fs):
            entries_html = build_rows(target_fs, indent=0)
            # Back link
            parent_url = ("/share/" + token + "/" + "/".join(quote(seg, safe="") for seg in crumb_parts[:-1])).rstrip("/") if crumb_parts else f"/share/{token}"
            back_row = f'<tr><td colspan="4" style="padding:6px 12px"><a href="{parent_url}" style="color:#64748b;text-decoration:none;font-size:13px">⬆ Parent folder</a></td></tr>'
            entries_html = back_row + entries_html
        else:
            entries_html = build_rows(base_fs, indent=0)

        if not entries_html:
            entries_html = '<tr><td colspan="4" style="padding:16px;color:#94a3b8;text-align:center">This folder is empty</td></tr>'

        # --- Upload section ---
        upload_section = ""
        if share["allow_anon_upload"] or (share["allow_auth_upload"] and visitor_user_id):
            encoded_subpath = quote(sub_path_clean, safe='/')
            upload_section = f"""
            <div style="margin-top:24px;padding:16px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px">
                <h3 style="margin:0 0 10px;font-size:15px;color:#166534">Upload files to this folder</h3>
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                    <input type="file" id="upload-file" multiple style="font-size:14px">
                    <button onclick="uploadFiles()"
                        style="background:#16a34a;color:white;border:none;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:14px;flex-shrink:0">
                        Upload
                    </button>
                    <button onclick="promptMkdir()"
                        style="background:#0ea5e9;color:white;border:none;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:14px;flex-shrink:0">
                        📁 New Folder
                    </button>
                    <span id="upload-status" style="font-size:13px;color:#166534"></span>
                </div>
                <div id="upload-progress" style="margin-top:8px"></div>
                <script>
                const _UPLOAD_URL = '/share/{token}/upload?subpath={encoded_subpath}';
                const _MKDIR_URL  = '/share/{token}/mkdir';
                const _CURRENT_SUBPATH = {repr(sub_path_clean)};

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
                            const r = await fetch(_UPLOAD_URL, {{method:'POST', body:fd}});
                            if(r.ok) done++; else failed++;
                        }}catch(e){{ failed++; }}
                    }}
                    statusEl.textContent = `Done: ${{done}} uploaded${{failed ? ', '+failed+' failed' : ''}}`;
                    progressEl.textContent = '';
                    if(done > 0) setTimeout(()=>location.reload(), 1200);
                }}

                async function promptMkdir(){{
                    const name = prompt('New folder name:');
                    if(!name || !name.trim()) return;
                    const subpath = _CURRENT_SUBPATH ? _CURRENT_SUBPATH + '/' + name.trim() : name.trim();
                    try{{
                        const r = await fetch(_MKDIR_URL, {{
                            method:'POST',
                            headers:{{'Content-Type':'application/json'}},
                            body: JSON.stringify({{subpath}})
                        }});
                        if(r.ok) location.reload();
                        else {{ const t = await r.text(); alert('Failed: '+t); }}
                    }}catch(e){{ alert('Error: '+e); }}
                }}
                </script>
            </div>"""

        # --- Expiry badge ---
        expiry_badge = ""
        if share.get("expires_at"):
            try:
                exp = _parse_expiry(share["expires_at"])
                if exp is not None:
                    expiry_badge = f'&nbsp;<span style="background:#fef9c3;color:#854d0e;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600">⏰ Expires {exp.strftime("%Y-%m-%d")}</span>'
            except Exception: pass

        folder_name = os.path.basename(base_fs.rstrip("/")) or "Shared Folder"
        current_title = os.path.basename(target_fs.rstrip("/")) if sub_path_clean else folder_name
        share_icon = '📁' if share['is_dir'] else '📄'
        require_account_badge = (
            '&nbsp;<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600">🔒 Account required</span>'
            if share["require_account"] else ''
        )

        return _render_snippet('share_folder_page.html',
            PUBLIC_DOMAIN=PUBLIC_DOMAIN,
            current_title=current_title,
            share_icon=share_icon,
            owner_name=owner_name,
            require_account_badge=require_account_badge,
            expiry_badge=expiry_badge,
            crumbs_html=crumbs_html,
            entries_html=entries_html,
            upload_section=upload_section,
        )

    def _render_share_login_page(self, token):
        cdn_origin = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}"
        share_path = f"/share/{token}"
        return _render_snippet('share_login_page.html',
            PUBLIC_DOMAIN=PUBLIC_DOMAIN,
            cdn_origin=repr(cdn_origin),
            share_path=repr(share_path),
        )

    def _render_share_expired_page(self):
        return _render_snippet('share_expired_page.html',PUBLIC_DOMAIN=PUBLIC_DOMAIN)

    def _render_share_not_found_page(self):
        return _render_snippet('share_not_found_page.html',PUBLIC_DOMAIN=PUBLIC_DOMAIN)

    # --- FluxDrop API Handlers ---

    def handle_public_share_upload(self, token: str):
        """POST /share/<token>/upload[?subpath=<relative>] — upload into a shared folder or subfolder."""
        share = _get_share(token)
        if not share or not share["is_dir"]:
            return self._send_response(404, json.dumps({"error": "Share not found or not a folder."}))

        visitor_user_id = self._check_token_auth()
        if share["allow_anon_upload"]:
            pass
        elif share["allow_auth_upload"] and visitor_user_id:
            pass
        else:
            return self._send_response(403, json.dumps({"error": "Uploads not permitted on this share."}))

        # Resolve base dir
        owner_id = share["owner_id"]
        base_path_str = share["path"]
        if base_path_str.startswith("/cdn"):
            base_dir = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, base_path_str[len("/cdn"):].lstrip("/")))
        else:
            base_dir = os.path.normpath(os.path.join(SERVE_ROOT, "FluxDrop", str(owner_id), base_path_str.lstrip("/")))

        # Resolve subfolder from ?subpath= query param
        parsed_qs = parse_qs(urlparse(self.path).query)
        raw_subpath = unquote(parsed_qs.get("subpath", [""])[0]).strip("/")
        dest_dir = os.path.normpath(os.path.join(base_dir, raw_subpath)) if raw_subpath else base_dir

        if not os.path.realpath(dest_dir).startswith(os.path.realpath(base_dir)):
            return self._send_response(403, json.dumps({"error": "Forbidden: path outside shared area."}))
        if not os.path.isdir(dest_dir):
            return self._send_response(404, json.dumps({"error": "Target subfolder not found on disk."}))

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
            logging.info(f"Share upload: token={token} file='{safe_name}' subpath='{raw_subpath}' user={visitor_user_id}")
            return self._send_response(200, "OK", "text/plain")
        except Exception as e:
            logging.exception("Public share upload failed")
            return self._send_response(500, json.dumps({"error": str(e)}))

    def handle_public_share_mkdir(self, token: str):
        """POST /share/<token>/mkdir — create a subfolder inside a shared folder.
        Body (JSON): { "subpath": "current/sub/NewFolder" }
        """
        share = _get_share(token)
        if not share or not share["is_dir"]:
            return self._send_response(404, json.dumps({"error": "Share not found or not a folder."}))

        visitor_user_id = self._check_token_auth()
        if not (share["allow_anon_upload"] or (share["allow_auth_upload"] and visitor_user_id)):
            return self._send_response(403, json.dumps({"error": "Not permitted."}))

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body)
        except Exception:
            return self._send_response(400, json.dumps({"error": "Invalid JSON."}))

        raw_subpath = data.get("subpath", "").strip().strip("/")
        if not raw_subpath:
            return self._send_response(400, json.dumps({"error": "subpath is required."}))

        owner_id = share["owner_id"]
        base_path_str = share["path"]
        if base_path_str.startswith("/cdn"):
            base_dir = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, base_path_str[len("/cdn"):].lstrip("/")))
        else:
            base_dir = os.path.normpath(os.path.join(SERVE_ROOT, "FluxDrop", str(owner_id), base_path_str.lstrip("/")))

        new_dir = os.path.normpath(os.path.join(base_dir, raw_subpath))
        if not os.path.realpath(new_dir).startswith(os.path.realpath(base_dir)):
            return self._send_response(403, json.dumps({"error": "Forbidden: path outside shared area."}))

        try:
            os.makedirs(new_dir, exist_ok=True)
            logging.info(f"Share mkdir: token={token} dir='{raw_subpath}' user={visitor_user_id}")
            return self._send_response(200, json.dumps({"ok": True}))
        except Exception as e:
            logging.exception("Public share mkdir failed")
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
        _, command, path_segment = match.groups()
        relative_path = unquote(path_segment if path_segment else '')

        # --- Auth gate ---
        # For download requests that carry a ?dl_token= we can skip the
        # session-token check: the dl_token itself proves prior authorisation
        # (it was minted via an authenticated POST /api/v1/download_token).
        # This allows <img>, <video>, <audio> tags to load files without the
        # browser sending an Authorization header (which it never does for
        # media elements).
        user_id = self._check_token_auth()

        if not user_id and command == 'download':
            # Pre-validate the dl_token to extract the owning user_id.
            # Full token validation (and 403 on bad token) happens below as before.
            parsed_qs_early = parse_qs(urlparse(self.path).query)
            dl_token_early = parsed_qs_early.get('dl_token', [None])[0]
            if dl_token_early:
                # We don't know the canonical path yet for CDN files, but we
                # can do a loose lookup by token hash alone to get the user_id.
                import hashlib as _hl
                th = _hl.sha256(dl_token_early.encode()).hexdigest()
                try:
                    with _db_connect() as _conn:
                        row = _conn.execute(
                            "SELECT user_id FROM download_tokens WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP",
                            (th,)
                        ).fetchone()
                        if row:
                            user_id = row[0]
                except Exception:
                    pass

        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))

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
                    with _db_connect() as conn2:
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
            if dl_token is None:
                return self._send_response(403, json.dumps({
                    "error": "Forbidden: a valid download token is required.",
                    "hint": "POST /api/v1/download_token with your session token to mint one."
                }))
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
                    self.send_header('Content-Disposition', self._content_disposition(os.path.basename(base_path)))
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
                    self.send_header('Content-Disposition', self._content_disposition(os.path.basename(base_path)))
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
                filename = os.path.basename(file_item.filename or "")

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
                    written = 0
                    while True:
                        chunk = file_item.stream.read(2 * 1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_UPLOAD_BYTES:
                            os.unlink(save_path)
                            return self._send_response(413, json.dumps({"error": "File too large."}))
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
    """Background thread: purge expired/used download tokens every 5 minutes.

    Uses exponential backoff (up to 1 hour) when the DB is unreachable, so
    the log is not flooded with errors every 5 minutes during a prolonged
    outage (e.g. the media drive being unmounted). Resets to the normal
    5-minute interval as soon as a purge succeeds.
    """
    NORMAL_INTERVAL = 300    # 5 minutes
    MAX_INTERVAL    = 3600   # 1 hour
    interval = NORMAL_INTERVAL
    while True:
        time.sleep(interval)
        success = _purge_expired_download_tokens()
        _purge_abandoned_upload_sessions()  # also clean up stale chunked uploads

        # N5: Purge expired pending_verifications rows (1-hour TTL, never bulk-cleared before)
        try:
            with _db_connect() as conn:
                conn.execute("DELETE FROM pending_verifications WHERE expires_at <= CURRENT_TIMESTAMP")
                conn.commit()
        except Exception:
            logging.exception('TokenPurge: failed to purge pending_verifications')

        # N6: Prune net_outages (keep 180 days) and incident_log (keep newest 200 rows)
        try:
            with _db_connect() as conn:
                conn.execute(
                    "DELETE FROM net_outages WHERE started_at < ?",
                    (time.time() - 180 * 86400,)
                )
                conn.execute(
                    '''DELETE FROM incident_log WHERE id NOT IN (
                           SELECT id FROM incident_log ORDER BY id DESC LIMIT 200
                       )'''
                )
                conn.commit()
        except Exception:
            logging.exception('TokenPurge: failed to prune net_outages/incident_log')

        # ── Record a status snapshot for uptime history ──────────────────
        try:
            import socket as _ss
            def _p(port):
                try:
                    with _ss.create_connection(('127.0.0.1', port), timeout=1): return True
                except Exception: return False
            _http  = _p(HTTP_PORT)
            _https = _p(HTTPS_PORT)
            _db_ok = True
            try:
                with _db_connect() as _c: _c.execute("SELECT 1")
            except Exception:
                _db_ok = False
            _mpct = 0
            try:
                _m = {}
                with open('/proc/meminfo') as _f:
                    for _l in _f:
                        _k, _v = _l.split(':', 1)
                        _m[_k.strip()] = int(_v.strip().split()[0]) * 1024
                _t = _m.get('MemTotal', 0)
                _mpct = round((_t - _m.get('MemAvailable', 0)) / _t * 100) if _t else 0
            except Exception: pass
            _dpct = 0
            try:
                _st = os.statvfs(SERVE_ROOT)
                _tt = _st.f_frsize * _st.f_blocks
                _dpct = round((_tt - _st.f_frsize * _st.f_bavail) / _tt * 100) if _tt else 0
            except Exception: pass
            with _net_state_lock:
                _net_ok  = _net_monitor_state['ok']
                _net_lat = _net_monitor_state['latency_ms']
            _record_status_snapshot(_http, _https, _db_ok, _mpct, _dpct,
                                    net_ok=_net_ok, latency_ms=_net_lat)
        except Exception:
            logging.exception('Status snapshot failed')

        if success:
            interval = NORMAL_INTERVAL
        else:
            interval = min(interval * 2, MAX_INTERVAL)
            logging.warning(
                f"TokenPurge: DB unavailable, next retry in {interval // 60} min."
            )


if __name__ == '__main__':
    # --- Pre-flight Checks & Setup ---
    init_db() # Initialize the database

    # N1 fix: load blacklist and start refresh thread (was never started in CDN)
    load_blacklist_safely(BLACKLIST_FILE)
    _bl_thread = threading.Thread(
        target=update_blacklist,
        args=(BLACKLIST_FILE, 60, stop_update_event),
        name='BlacklistRefresh',
        daemon=True,
    )
    _bl_thread.start()

    # Create necessary directories
    for dir_path in [SERVE_ROOT, os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR), UPLOAD_TMP_DIR]:
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

    net_mon_thread = threading.Thread(target=_net_monitor_worker, name="NetMonitor", daemon=True)
    net_mon_thread.start()

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
