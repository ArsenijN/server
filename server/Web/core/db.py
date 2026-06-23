import os, sqlite3, threading, logging, time
from contextlib import contextmanager
from config import DB_FILE


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
        # In _init_db(), add these to the users table migration block:
        _admin_cols = {
            'is_admin':    'INTEGER DEFAULT 0',
            'quota_bytes': 'INTEGER DEFAULT NULL',  # NULL = use dynamic default
            'quota_override': 'INTEGER DEFAULT 0',  # 1 = never auto-adjust this user
        }
        for _col, _def in _admin_cols.items():
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {_col} {_def}")
            except Exception:
                pass  # already exists
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
        # Writes on every outage and internet connection recovery.
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
        # IP Beacon — device registration and IP tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS beacon_devices (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                primary_token TEXT    NOT NULL UNIQUE,
                label         TEXT    NOT NULL DEFAULT '',
                ip            TEXT    NOT NULL DEFAULT '',
                user_agent    TEXT    NOT NULL DEFAULT '',
                last_seen     REAL    NOT NULL DEFAULT 0,
                created_at    REAL    NOT NULL DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS beacon_read_tokens (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                read_token    TEXT    NOT NULL UNIQUE,
                device_id     INTEGER NOT NULL REFERENCES beacon_devices(id) ON DELETE CASCADE,
                created_at    REAL    NOT NULL DEFAULT 0
            )
        ''')
        # Trash bin — soft-deleted files/folders.
        # original_path : user-relative path before deletion (e.g. /docs/report.pdf)
        # trash_path    : absolute path to the moved file inside the trash dir
        # deleted_at    : unix timestamp of deletion
        # size_bytes    : pre-computed size (so quota math doesn't need a walk)
        # is_dir        : whether the entry was a directory
        # retention_days: effective retention at deletion time (30 normal / 7 reduced)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trash_items (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_path   TEXT    NOT NULL,
                trash_path      TEXT    NOT NULL UNIQUE,
                deleted_at      REAL    NOT NULL DEFAULT 0,
                size_bytes      INTEGER NOT NULL DEFAULT 0,
                is_dir          INTEGER NOT NULL DEFAULT 0,
                retention_days  INTEGER NOT NULL DEFAULT 30
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS upload_notifications (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                type        TEXT    NOT NULL DEFAULT 'webhook',   -- 'webhook' | 'email'
                target      TEXT    NOT NULL,                     -- URL or email address
                secret      TEXT    DEFAULT NULL,                 -- HMAC secret for webhooks
                enabled     INTEGER NOT NULL DEFAULT 1,
                created_at  REAL    NOT NULL DEFAULT 0
            )
        ''')
        # Policy acceptance tracking
        # Stores which version of TOS and PP each user has agreed to.
        # On login/page-load the client calls GET /api/v1/policy/status to
        # learn the current required versions and which ones the user has
        # already accepted.  POST /api/v1/policy/accept records a new acceptance.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policy_acceptances (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                policy_type TEXT    NOT NULL,   -- 'tos' | 'pp'
                version     TEXT    NOT NULL,   -- e.g. '0.0.1'
                accepted_at REAL    NOT NULL DEFAULT 0,
                UNIQUE(user_id, policy_type, version)
            )
        ''')
        # CRC32 checksums for user files.
        # Used by the ZIP-meta builder (avoids re-scanning on every archive request)
        # and by the background integrity checker.
        #
        # relative_path : path relative to the user's FluxDrop root (e.g. /docs/f.txt)
        # user_id       : owner (NULL for CDN/shared files without a named owner)
        # crc32         : unsigned 32-bit CRC32 stored as INTEGER
        # file_size     : byte size at scan time (detect truncation)
        # mtime_ns      : st_mtime_ns at scan time — checksum is stale when this changes
        # computed_at   : unix timestamp of last successful scan
        # scan_source   : 'upload' | 'on_demand' | 'background'
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_checksums (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                relative_path TEXT    NOT NULL,
                user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
                crc32         INTEGER NOT NULL,
                file_size     INTEGER NOT NULL,
                mtime_ns      INTEGER NOT NULL,
                computed_at   REAL    NOT NULL DEFAULT 0,
                scan_source   TEXT    NOT NULL DEFAULT 'background',
                sha256        TEXT    DEFAULT NULL,
                UNIQUE(relative_path, user_id)
            )
        ''')
        # On-demand checksum computation jobs.
        # Allows the frontend to trigger hash computation and poll for status.
        # status: 'pending' | 'running' | 'done' | 'error'
        # algos : comma-separated algorithm list, e.g. 'crc32,sha256'
        # Rows survive server restarts — 'running' entries are reset to 'error'
        # at startup; 'pending' entries are re-queued by the job worker.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS checksum_jobs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                relative_path TEXT    NOT NULL,
                user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
                algos         TEXT    NOT NULL DEFAULT 'crc32,sha256',
                status        TEXT    NOT NULL DEFAULT 'pending',
                created_at    REAL    NOT NULL DEFAULT 0,
                started_at    REAL    DEFAULT NULL,
                finished_at   REAL    DEFAULT NULL,
                error_msg     TEXT    DEFAULT NULL
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
        _add_column_if_missing('beacon_read_tokens', 'last_used', 'REAL DEFAULT NULL')
        _add_column_if_missing('upload_sessions', 'strategy',
                               "TEXT NOT NULL DEFAULT 'buffer'")
        _add_column_if_missing('upload_sessions', 'upload_status',
                               "TEXT NOT NULL DEFAULT 'pending'")
        # Profile picture: stored as a compressed blob directly in the DB.
        # Tunable constants live in server_cdn.py (AVATAR_MAX_DIM, AVATAR_MAX_BYTES).
        _add_column_if_missing('users', 'avatar_data', 'BLOB DEFAULT NULL')
        _add_column_if_missing('users', 'avatar_mime', 'TEXT DEFAULT NULL')
        _add_column_if_missing('file_checksums', 'sha256', 'TEXT DEFAULT NULL')
        try:
            conn.execute(
                '''CREATE INDEX IF NOT EXISTS idx_upload_sessions_dest_status
                   ON upload_sessions (dest_path, upload_status, completed)'''
            )
        except Exception:
            pass
        try:
            conn.execute(
                '''CREATE INDEX IF NOT EXISTS idx_file_checksums_path_user
                   ON file_checksums (relative_path, user_id)'''
            )
        except Exception:
            pass
        conn.commit()

    logging.info("Database initialized successfully.")

# ── CRC32 checksum helpers ────────────────────────────────────────────────────

def checksum_get(relative_path: str, user_id) -> dict | None:
    """Return the stored checksum row for (relative_path, user_id), or None.
    user_id may be an int or None (for CDN/share files without an owner)."""
    with _db_connect() as conn:
        row = conn.execute(
            '''SELECT crc32, file_size, mtime_ns, computed_at, scan_source, sha256
               FROM file_checksums
               WHERE relative_path = ?
                 AND (user_id IS ? OR user_id = ?)''',
            (relative_path, user_id, user_id)
        ).fetchone()
    if not row:
        return None
    return {
        'crc32':       row[0],
        'file_size':   row[1],
        'mtime_ns':    row[2],
        'computed_at': row[3],
        'scan_source': row[4],
        'sha256':      row[5],
    }


def checksum_put(relative_path: str, user_id, crc32: int,
                 file_size: int, mtime_ns: int,
                 scan_source: str = 'background',
                 sha256: 'str | None' = None) -> None:
    """Upsert a checksum record.  Overwrites any existing row for the same
    (relative_path, user_id) pair.  sha256 is stored when provided."""
    import time as _t
    with _db_connect() as conn:
        conn.execute(
            '''INSERT INTO file_checksums
                   (relative_path, user_id, crc32, file_size,
                    mtime_ns, computed_at, scan_source, sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(relative_path, user_id)
               DO UPDATE SET
                   crc32       = excluded.crc32,
                   file_size   = excluded.file_size,
                   mtime_ns    = excluded.mtime_ns,
                   computed_at = excluded.computed_at,
                   scan_source = excluded.scan_source,
                   sha256      = excluded.sha256''',
            (relative_path, user_id, crc32, file_size,
             mtime_ns, _t.time(), scan_source, sha256)
        )
        conn.commit()


def checksum_delete(relative_path: str, user_id) -> None:
    """Remove a checksum record (call after file deletion or rename)."""
    with _db_connect() as conn:
        conn.execute(
            '''DELETE FROM file_checksums
               WHERE relative_path = ?
                 AND (user_id IS ? OR user_id = ?)''',
            (relative_path, user_id, user_id)
        )
        conn.commit()


def checksum_is_fresh(row: dict, abs_path: str) -> bool:
    """Return True if the stored checksum is still valid for abs_path.
    Checks both st_size and st_mtime_ns — both must match for the checksum
    to be considered trustworthy."""
    try:
        st = os.stat(abs_path)
        return (st.st_size == row['file_size'] and
                int(st.st_mtime_ns) == row['mtime_ns'])
    except OSError:
        return False


def checksum_set_sha256(relative_path: str, user_id, sha256: str) -> None:
    """Set (or update) the sha256 field on an existing checksum row without
    touching other fields.  No-op when no row exists for this file."""
    with _db_connect() as conn:
        conn.execute(
            '''UPDATE file_checksums SET sha256 = ?
               WHERE relative_path = ?
                 AND (user_id IS ? OR user_id = ?)''',
            (sha256, relative_path, user_id, user_id)
        )
        conn.commit()


# ── On-demand checksum job helpers ────────────────────────────────────────────
# Jobs are persisted in the DB so the frontend can poll status across page
# reloads.  The actual computation is done by a worker thread in upload.py.

def checksum_job_create(relative_path: str, user_id,
                        algos: str = 'crc32,sha256') -> 'tuple[int, bool]':
    """Create a new on-demand checksum job if no active job exists.
    Returns (job_id, is_new).  When a pending/running job already exists for
    the same (path, user_id) pair, returns that job's id with is_new=False."""
    import time as _t
    with _db_connect() as conn:
        existing = conn.execute(
            '''SELECT id FROM checksum_jobs
               WHERE relative_path = ? AND (user_id IS ? OR user_id = ?)
                 AND status IN ('pending', 'running')
               LIMIT 1''',
            (relative_path, user_id, user_id)
        ).fetchone()
        if existing:
            return existing[0], False
        result = conn.execute(
            '''INSERT INTO checksum_jobs
                   (relative_path, user_id, algos, status, created_at)
               VALUES (?, ?, ?, 'pending', ?)''',
            (relative_path, user_id, algos, _t.time())
        )
        conn.commit()
        return result.lastrowid, True


def checksum_job_get_latest(relative_path: str, user_id) -> 'dict | None':
    """Return the most recent job row for this file (any status), or None."""
    with _db_connect() as conn:
        row = conn.execute(
            '''SELECT id, algos, status, created_at, started_at, finished_at, error_msg
               FROM checksum_jobs
               WHERE relative_path = ? AND (user_id IS ? OR user_id = ?)
               ORDER BY id DESC LIMIT 1''',
            (relative_path, user_id, user_id)
        ).fetchone()
    if not row:
        return None
    return {
        'id':          row[0],
        'algos':       row[1],
        'status':      row[2],
        'created_at':  row[3],
        'started_at':  row[4],
        'finished_at': row[5],
        'error_msg':   row[6],
    }


def checksum_job_update_status(job_id: int, status: str,
                                error_msg: 'str | None' = None) -> None:
    """Update a job's status, stamping started_at / finished_at as appropriate."""
    import time as _t
    now = _t.time()
    with _db_connect() as conn:
        if status == 'running':
            conn.execute(
                'UPDATE checksum_jobs SET status = ?, started_at = ? WHERE id = ?',
                (status, now, job_id)
            )
        elif status in ('done', 'error'):
            conn.execute(
                '''UPDATE checksum_jobs
                   SET status = ?, finished_at = ?, error_msg = ?
                   WHERE id = ?''',
                (status, now, error_msg, job_id)
            )
        else:
            conn.execute(
                'UPDATE checksum_jobs SET status = ? WHERE id = ?',
                (status, job_id)
            )
        conn.commit()


def checksum_jobs_reset_stale() -> int:
    """Reset any 'running' jobs left from a previous server process to 'error'.
    Call once at startup, before the worker thread begins.
    Returns the number of rows reset."""
    with _db_connect() as conn:
        result = conn.execute(
            '''UPDATE checksum_jobs
               SET status    = 'error',
                   error_msg = 'Interrupted by server restart — click Recalculate',
                   finished_at = strftime('%s', 'now')
               WHERE status = 'running' '''
        )
        conn.commit()
        return result.rowcount


def checksum_jobs_get_pending() -> list:
    """Return all pending jobs for re-queuing on startup."""
    with _db_connect() as conn:
        rows = conn.execute(
            '''SELECT id, relative_path, user_id, algos
               FROM checksum_jobs WHERE status = 'pending'
               ORDER BY id'''
        ).fetchall()
    return [{'id': r[0], 'relative_path': r[1], 'user_id': r[2], 'algos': r[3]}
            for r in rows]


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

# In-process assembly progress tracker.
# Written by _upload_assemble while it hashes/copies; read by the
# /assembly_progress polling endpoint.  Entries are cleaned up on
# completion or error so the dict stays small.
# Format: token -> {'bytes_hashed': int, 'total_bytes': int, 'done': bool, 'error': str|None}
_assembly_progress: dict = {}
_assembly_progress_lock = threading.Lock()

def _assembly_progress_set(token: str, bytes_hashed: int, total_bytes: int,
                            done: bool = False, error: str | None = None) -> None:
    with _assembly_progress_lock:
        _assembly_progress[token] = {
            'bytes_hashed': bytes_hashed,
            'total_bytes':  total_bytes,
            'done':         done,
            'error':        error,
        }

def _assembly_progress_get(token: str) -> dict | None:
    with _assembly_progress_lock:
        return _assembly_progress.get(token)

def _assembly_progress_clear(token: str) -> None:
    with _assembly_progress_lock:
        _assembly_progress.pop(token, None)
