#!/usr/bin/env python3
# =============================================================================
# MODULE INDEX
# Functions and classes are split across core/ modules.
# When asking for help, attach server_cdn.py + the relevant module(s) below.
#
# core/db.py
#   _db_connect()                  — SQLite context manager (WAL, 15s timeout)
#   init_db()                      — create/migrate all tables on startup
#   _get_chunk_lock(token)         — per-upload serialisation lock
#   _release_chunk_lock(token)     — release after assembly or purge
#   _assembly_progress_{set,get,clear}(token, ...) — in-process progress tracker
#
# core/rate_limit.py
#   _rate_limit(ip, bucket, max_hits) → bool  — sliding-window throttle
#
# core/notifications.py
#   _fire_upload_notification(user_id, path, message)  — webhook/email on upload
#
# core/auth.py
#   hash_password(password) → (hash, '')
#   send_verification_email(email, token, username)
#   _mint_download_token(relative_path, user_id) → raw_token
#   _validate_download_token(relative_path, raw_token) → dict | None
#   _update_token_progress(token_id, bytes_confirmed)
#   _purge_expired_download_tokens()
#
# core/upload.py
#   _upload_init(...)  → session dict
#   _upload_get(token) → session dict | None
#   _upload_receive_chunk(token, index, data, expected_size) → session dict
#   _upload_assemble(token) → (dest_path, sha256_hex)
#   _upload_session_status(session) → dict
#   _purge_abandoned_upload_sessions()
#
# core/shares.py
#   _create_share(...) → token
#   _get_shares_for_user(user_id)
#   _get_share(token) → dict | None        — respects expiry
#   _get_share_raw(token) → dict | None    — ignores expiry
#   _update_share(token, owner_id, fields)
#   _delete_share(token, owner_id)
#   _log_share_access(token, user_id, action)
#   _get_share_stats(token, owner_id)
#
# core/trash.py
#   _move_to_trash(user_id, fs_path, original_path) → metadata dict
#   _trash_list(user_id)
#   _trash_restore(user_id, item_id) → original_path
#   _trash_delete_permanent(user_id, item_id)
#   _trash_purge_expired() → purge_count
#   _trash_size_used(user_id) → bytes
#
# core/quota.py
#   _compute_dynamic_quota() → bytes
#   _quota_updater_thread(interval_seconds)  — background daemon
#
# core/net_monitor.py
#   _net_monitor_worker()     — background daemon
#   _net_monitor_state        — shared dict {ok, latency_ms, outage_id, outage_since}
#   _net_state_lock           — lock for reading _net_monitor_state
#   _get_net_outages(days)
#   _get_net_history_by_day(days)
#
# core/status.py
#   _build_status_page() → HTML string
#   _record_status_snapshot(http_up, https_up, db_ok, mem_pct, disk_pct, ...)
#   _get_recent_incidents(limit)
#   _get_message_board(limit)
#   _get_status_history(days)
#
# core/snippets.py
#   _render_snippet(filename, **kwargs) → str   — safe {PLACEHOLDER} substitution
#
# core/meta.py
#   SERVER_VERSION      — string read from VERSION file
#   _SERVER_START_TIME  — float unix timestamp of process start
# =============================================================================
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
import sqlite3
from werkzeug.formparser import parse_form_data # For parsing multipart/form-data (cgi deprecated in Python 3.13+)
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, quote, urlparse, parse_qs
import gzip as _gzip_mod
import datetime as _dt
import zlib     as _zl
import tarfile as _tf
import io as _io
import hashlib as _hl
import re as _re
import zipfile as _zf
import struct  as _st
import time as _time
import urllib.parse as _up
from shared import CustomLogger, current_blacklist, blacklist_lock, load_blacklist_safely, update_blacklist, stop_update_event
from config import SERVE_DIRECTORY, DB_FILE, CERT_FILE, KEY_FILE, LOG_FILE_CDN, CDN_UPLOAD_DIR, BLACKLIST_FILE, PUBLIC_DOMAIN as _CONFIG_PUBLIC_DOMAIN
from config import SERVE_ROOT, HTTP_PORT, HTTPS_PORT, CATBOX_UPLOAD_DIR, HOST, SECRETS_DIR

# Plain-HTTP loopback port used by server_https proxy to avoid double-TLS.
# Bound to 127.0.0.1 only — never reachable from outside the machine.
CDN_INTERNAL_PORT = int(os.getenv('CDN_INTERNAL_PORT', '64799'))
import socket as _socket
import mimetypes

# Importing core modules
from core.db import _db_connect, init_db, _get_chunk_lock, _release_chunk_lock, \
                    _assembly_progress_set, _assembly_progress_get, _assembly_progress_clear, \
                    checksum_get, checksum_put, checksum_is_fresh, \
                    checksum_job_create, checksum_job_get_latest, checksum_job_update_status, \
                    checksum_jobs_reset_stale, checksum_jobs_get_pending
from core.rate_limit import _rate_limit
from core.notifications import _fire_upload_notification
from core.upload import MAX_JSON_BODY, UPLOAD_CHUNK_SIZE, UPLOAD_SESSION_TTL, _upload_init, _upload_get, _upload_receive_chunk, \
    _upload_session_status, _upload_assemble, MAX_SHARE_UPLOAD_BYTES, MAX_UPLOAD_BYTES, _purge_abandoned_upload_sessions, UPLOAD_TMP_DIR, \
    _cancel_upload_session, compute_and_store_crc32, dispatch_checksum_job
from core.shares import _get_share, _get_shares_for_user, _create_share, _update_share, _delete_share, _get_share_stats, _get_share_raw, \
    _is_share_expired, _log_share_access, _parse_expiry
from core.trash import _trash_size_used, _trash_list, _trash_retention_days, _move_to_trash, _trash_restore, _trash_delete_permanent, \
    _trash_purge_expired, _user_trash_root
from core.net_monitor import _get_net_history_by_day, _net_state_lock, _net_monitor_state, _get_net_outages, _net_monitor_worker, _reconcile_open_outages
from core.status import _build_status_page, _get_status_history, _get_recent_incidents, _get_message_board, _record_status_snapshot
from core.quota import _compute_dynamic_quota, _quota_updater_thread
from core.auth import _hash_session_token, _prepare_password, hash_password, send_verification_email, _sha256_hash, _validate_download_token, \
    _mint_download_token, _purge_expired_download_tokens, DOWNLOAD_TOKEN_TTL_SECONDS, _update_token_progress
from core.meta import _SERVER_START_TIME, SERVER_VERSION
from config import DEBUG_LOGGING
from core.snippets import _render_snippet

# Content-types that benefit from gzip (text-based, not already compressed).
# Binary / already-compressed types are explicitly excluded so we never waste
# CPU inflating data that can't shrink further.
_GZIP_COMPRESSIBLE = frozenset({
    'application/json',
    'text/html',
    'text/plain',
    'text/css',
    'application/javascript',
    'text/javascript',
    'application/xml',
    'text/xml',
    'text/csv',
})
# Files larger than this are not gzip-buffered in _send_response to avoid
# holding a potentially huge compressed blob in RAM.  The streaming download
# handler has its own logic.
_GZIP_MAX_INLINE   = 16 * 1024 * 1024   # 16 MB
_GZIP_MIN_SIZE     = 512                # below this the header overhead isn't worth it

# ==============================================================================
# --- CONFIGURATION ---
# ==============================================================================
# --- Server Settings ---
ALLOWED_ORIGINS = {
    'arseniusgen.uk.to',
    'www.arseniusgen.uk.to',
    'arsenius-gen.uk.to',
    'arsenius_gen.uk.to',
    # New domains (2025-06)
    'arseniusgen.dev',
    'www.arseniusgen.dev',
    'fluxdrop.me',
    'www.fluxdrop.me',
    '134.249.151.95',
    # 'localhost' removed — allows any page on the visitor's machine to make
    # credentialed cross-origin requests to the server. Not needed in production.
}

# Public domain and serve root
PUBLIC_DOMAIN = os.getenv('PUBLIC_DOMAIN', _CONFIG_PUBLIC_DOMAIN)

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

# Path to the versions file — same directory as the policies folder
_POLICY_VERSIONS_FILE = os.getenv('POLICY_VERSIONS_FILE', str(os.path.dirname(os.path.abspath(__file__)) + 'policies\\versions.json'))

# ── Resumable ZIP session registry ────────────────────────────────────────────
# Maps session_id (uuid) → {
#   'files':    [(abs_path, arcname_bytes, file_size, crc32, dos_time, dos_date,
#                 lf_offset, data_offset, data_end, dd_end), ...],
#   'cd_entries': [bytes, ...],   # pre-built central-directory entry bytes
#   'total_size': int,            # exact Content-Length
#   'filename':   str,
#   'missing':    [str, ...],
#   'expires':    float,
#   'user_id':    str,
# }
# Sessions are built once (pre-walk + CRC32 scan) and stream directly to wire
# on each GET.  Range requests seek into the virtual stream using the offset
# table — no temp files, no /tmp usage.
import uuid as _uuid_mod
_zip_sessions: dict = {}
_zip_sessions_lock  = threading.Lock()
ZIP_SESSION_TTL     = int(os.getenv('ZIP_SESSION_TTL', str(20 * 60)))   # 20 min

# ── Async ZIP job registry ────────────────────────────────────────────────────
# zip_meta kicks off a background scan and returns a job_id immediately.
# The client polls /api/v1/zip_status/<job_id> every second until status='ready'.
# Job states: 'scanning' → 'ready' | 'error'
# Once ready the job entry also carries the full session payload (same keys as
# _zip_sessions) so zip_stream can serve it directly.
_zip_jobs: dict        = {}
_zip_jobs_lock         = threading.Lock()
ZIP_JOB_TTL            = int(os.getenv('ZIP_JOB_TTL', str(30 * 60)))    # 30 min

def _zip_sessions_cleanup():
    while True:
        time.sleep(60)
        now = time.time()
        with _zip_sessions_lock:
            expired = [k for k, v in _zip_sessions.items() if v['expires'] < now]
            for k in expired:
                del _zip_sessions[k]
        with _zip_jobs_lock:
            expired_jobs = [k for k, v in _zip_jobs.items() if v.get('expires', 0) < now]
            for k in expired_jobs:
                del _zip_jobs[k]
        if expired or expired_jobs:
            logging.debug('ZIP cleanup: sessions=%d jobs=%d evicted',
                          len(expired), len(expired_jobs))

threading.Thread(target=_zip_sessions_cleanup, daemon=True, name='ZipSessionCleanup').start()


# ── Background CRC32 integrity scanner ───────────────────────────────────────
# Runs daily inside the maintenance window (23:00–04:00 EEST = 20:00–01:00 UTC).
# Walks every user's FluxDrop directory and hashes any file that has no stored
# checksum or whose mtime/size has changed since the last scan.
# Throttled to ~5 MB/s by default — adjustable via BG_SCAN_RATE_BYTES env var.

_BG_SCAN_READ_BUF     = int(os.getenv('BG_SCAN_READ_BUF',   str(2 * 1024 * 1024)))
_BG_SCAN_RATE_BYTES_S = int(os.getenv('BG_SCAN_RATE_BYTES',  str(5 * 1024 * 1024)))
_BG_SCAN_WINDOW_START = int(os.getenv('BG_SCAN_START_UTC',  '20'))  # 23:00 EEST
_BG_SCAN_WINDOW_END   = int(os.getenv('BG_SCAN_END_UTC',     '1'))  # 04:00 EEST


_MAINTENANCE_LOG = os.getenv(
    'MAINTENANCE_LOG',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'maintenance.log')
)

def _mlog(fh, msg: str) -> None:
    """Write a timestamped line to the open maintenance log file handle."""
    ts = _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    fh.write(f'[{ts}] {msg}\n')
    fh.flush()


def _bg_crc32_scanner():

    def _in_window() -> bool:
        h = _dt.datetime.now(_dt.timezone.utc).hour
        # Window crosses midnight (20 … 23 … 0)
        if _BG_SCAN_WINDOW_START > _BG_SCAN_WINDOW_END:
            return h >= _BG_SCAN_WINDOW_START or h < _BG_SCAN_WINDOW_END
        return _BG_SCAN_WINDOW_START <= h < _BG_SCAN_WINDOW_END

    time.sleep(300)          # let the server finish starting up

    while True:
        while not _in_window():
            time.sleep(60)

        run_start    = _dt.datetime.now(_dt.timezone.utc)
        run_start_ts = time.time()
        scanned = skipped = errors = 0
        bytes_read = 0
        done       = False

        # Open maintenance log (append mode — one file, runs accumulate)
        try:
            mlog_fh = open(_MAINTENANCE_LOG, 'a', encoding='utf-8')
        except OSError as e:
            logging.error('BG CRC32 scanner: cannot open maintenance log %r: %s',
                          _MAINTENANCE_LOG, e)
            mlog_fh = None

        def _ml(msg: str) -> None:
            if mlog_fh:
                _mlog(mlog_fh, msg)
            logging.info('BG CRC32: %s', msg)

        SEP = '=' * 72
        _ml(SEP)
        _ml('MAINTENANCE WINDOW STARTED')
        _ml(f'Window : {_BG_SCAN_WINDOW_START:02d}:00–{_BG_SCAN_WINDOW_END:02d}:00 UTC')
        _ml(f'Rate   : {_BG_SCAN_RATE_BYTES_S // 1024} KB/s  |  read buf: {_BG_SCAN_READ_BUF // 1024} KB')
        _ml(SEP)

        try:
            user_root = os.path.join(SERVE_ROOT, 'FluxDrop')
            if not os.path.isdir(user_root):
                _ml(f'ERROR  : {user_root!r} not found — aborting scan')
                time.sleep(3600)
                if mlog_fh:
                    mlog_fh.close()
                continue

            for user_entry in os.scandir(user_root):
                if done:
                    break
                if not user_entry.is_dir():
                    continue
                try:
                    uid = int(user_entry.name)
                except ValueError:
                    continue

                user_scanned = user_skipped = user_errors = 0
                _ml(f'USER   : id={uid}  path={user_entry.path!r}')

                for dirpath, _dirs, filenames in os.walk(user_entry.path):
                    if not _in_window():
                        _ml('WINDOW : maintenance window ended mid-scan — stopping early')
                        done = True; break
                    for fname in sorted(filenames):
                        if not _in_window():
                            _ml('WINDOW : maintenance window ended mid-scan — stopping early')
                            done = True; break
                        abs_path = os.path.join(dirpath, fname)
                        rel_path = ('/' +
                            os.path.relpath(abs_path, user_entry.path)
                               .replace(os.sep, '/'))
                        try:
                            st = os.stat(abs_path)
                        except OSError:
                            continue
                        stored = checksum_get(rel_path, uid)
                        if stored and checksum_is_fresh(stored, abs_path) and stored.get('sha256'):
                            skipped += 1; user_skipped += 1
                            continue
                        # Compute CRC-32 + SHA-256 in a single read pass
                        crc = 0; h256 = _hl.sha256(); read_b = 0
                        try:
                            with open(abs_path, 'rb') as fh:
                                while True:
                                    chunk = fh.read(_BG_SCAN_READ_BUF)
                                    if not chunk: break
                                    crc    = _zl.crc32(chunk, crc) & 0xFFFF_FFFF
                                    h256.update(chunk)
                                    read_b += len(chunk)
                            sha256_hex = h256.hexdigest()
                            checksum_put(rel_path, uid, crc, st.st_size,
                                         int(st.st_mtime_ns), 'background',
                                         sha256=sha256_hex)
                            scanned    += 1; user_scanned += 1
                            bytes_read += read_b
                            _ml(f'  HASH : {rel_path}  crc={crc:08x}  sha256={sha256_hex[:16]}…  size={st.st_size}')
                            # Rate-limit
                            if _BG_SCAN_RATE_BYTES_S > 0:
                                elapsed = time.time() - run_start_ts + 0.001
                                budget  = elapsed * _BG_SCAN_RATE_BYTES_S
                                if bytes_read > budget:
                                    time.sleep(
                                        (bytes_read - budget) / _BG_SCAN_RATE_BYTES_S
                                    )
                        except OSError as e:
                            logging.debug('BG CRC32: error %r: %s', abs_path, e)
                            _ml(f'  ERROR: {rel_path}  {e}')
                            errors += 1; user_errors += 1

                _ml(f'  DONE  user={uid}: hashed={user_scanned} '
                    f'skipped={user_skipped} errors={user_errors}')

        except Exception as e:
            logging.error('BG CRC32 scanner: unexpected error: %s', e)
            _ml(f'FATAL  : unexpected exception: {e}')

        elapsed_s = time.time() - run_start_ts
        _ml(SEP)
        _ml('SUMMARY')
        _ml(f'  Started  : {run_start.strftime("%Y-%m-%d %H:%M:%S UTC")}')
        _ml(f'  Elapsed  : {int(elapsed_s // 60)}m {int(elapsed_s % 60)}s')
        _ml(f'  Hashed   : {scanned} file(s)  ({bytes_read / 1024 / 1024:.1f} MB read)')
        _ml(f'  Skipped  : {skipped} file(s)  (checksum already fresh)')
        _ml(f'  Errors   : {errors}')
        _ml(f'  Complete : {"NO — window closed early" if done else "YES"}')
        _ml(SEP + '\n')

        if mlog_fh:
            try:
                mlog_fh.close()
            except OSError:
                pass

        time.sleep(20 * 3600)   # earliest next scan in 20 h


threading.Thread(target=_bg_crc32_scanner, daemon=True, name='CRC32BgScanner').start()


def _zip_build_job(job_id: str, base_fs: str, folder_name: str, user_id) -> None:
    """Background thread: build a ZIP session for job_id.
    Updates _zip_jobs[job_id] with progress, then sets status='ready' or 'error'.
    """
    import struct as _st
    import zlib   as _zl

    def _upd(**kw):
        with _zip_jobs_lock:
            if job_id in _zip_jobs:
                _zip_jobs[job_id].update(kw)

    try:
        # Pre-walk
        raw_files = []
        missing   = []
        for dirpath, _dirs, filenames in os.walk(base_fs):
            for fname in sorted(filenames):
                if fname in ('.placeholder', '.create_marker'):
                    continue
                abs_path = os.path.join(dirpath, fname)
                arcname  = os.path.relpath(abs_path, base_fs).replace(os.sep, '/')
                try:
                    st      = os.stat(abs_path)
                    lt      = time.localtime(st.st_mtime)
                    dos_t   = (lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec >> 1)
                    dos_d   = ((lt.tm_year - 1980) << 9) | (lt.tm_mon << 5) | lt.tm_mday
                    raw_files.append((abs_path, arcname, arcname.encode('utf-8'),
                                      st.st_size, dos_t, dos_d))
                except OSError:
                    missing.append(arcname)
        _upd(total=len(raw_files))

        # CRC32 scan (checksum cache + on-demand)
        _is_share  = user_id == 'share' or user_id is None
        _cs_uid    = None if _is_share else int(user_id)
        _cs_root   = None if _is_share else os.path.normpath(
            os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id))
        )
        scanned        = []
        actual_missing = []
        needs_hashing  = False
        for i, (abs_path, arcname, arcname_bytes, fsz, dos_t, dos_d) in enumerate(raw_files):
            crc = None
            # Key must match what the background scanner stored:
            # relative to the user root, not to base_fs.
            if _cs_root:
                cs_key = '/' + os.path.relpath(abs_path, _cs_root).replace(os.sep, '/')
            else:
                cs_key = '/' + arcname if not arcname.startswith('/') else arcname
            stored = checksum_get(cs_key, _cs_uid)
            if stored and checksum_is_fresh(stored, abs_path):
                crc = stored['crc32']
                fsz = stored['file_size']
            if crc is None:
                needs_hashing = True
                try:
                    crc = compute_and_store_crc32(abs_path, cs_key, _cs_uid, 'on_demand')
                    fsz = os.stat(abs_path).st_size
                except OSError:
                    logging.warning('zip_build: CRC failed %r', abs_path)
                    actual_missing.append(arcname); crc = 0; fsz = 0
            scanned.append((abs_path, arcname, arcname_bytes, fsz, crc, dos_t, dos_d))
            _upd(progress=i + 1)

        # Build offset table and pre-render headers
        LFH_SIG            = b'PK\x03\x04'
        CDH_SIG            = b'PK\x01\x02'
        EOCD_SIG           = b'PK\x05\x06'
        ZIP64_EOCD_SIG     = b'PK\x06\x06'
        ZIP64_EOCD_LOCATOR = b'PK\x06\x07'
        FLAG_NONE = 0; METHOD_STORED = 0; UINT32_MAX = 0xFFFF_FFFF; UINT16_MAX = 0xFFFF
        FLAG_UTF8 = 0x0800   # ← add this
        offset = 0; files_built = []
        for abs_path, arcname, arcname_bytes, fsz, crc, dos_t, dos_d in scanned:
            fn_len      = len(arcname_bytes)
            lf_offset   = offset
            z64_lfh     = _st.pack('<HH QQ', 0x0001, 16, fsz, fsz)
            flag        = FLAG_UTF8 if any(b > 127 for b in arcname_bytes) else FLAG_NONE

            lfh         = _st.pack('<4sHHHHHIIIHH',
                LFH_SIG, 45, flag, METHOD_STORED, dos_t, dos_d,   # FLAG_NONE → flag
                crc, UINT32_MAX, UINT32_MAX, fn_len, len(z64_lfh),
            ) + arcname_bytes + z64_lfh
            offset     += len(lfh); data_offset = offset; offset += fsz
            z64_cdh     = _st.pack('<HH QQQ', 0x0001, 24, fsz, fsz, lf_offset)
            cdh         = _st.pack('<4sHHHHHHIIIHHHHHII',
                CDH_SIG, 45, 45, flag, METHOD_STORED, dos_t, dos_d, crc,  # FLAG_NONE → flag
                UINT32_MAX, UINT32_MAX, fn_len, len(z64_cdh), 0, 0, 0, 0, UINT32_MAX,
            ) + arcname_bytes + z64_cdh
            files_built.append({
                'abs_path': abs_path, 'arcname_bytes': arcname_bytes,
                'size': fsz, 'crc': crc, 'lf_offset': lf_offset,
                'data_offset': data_offset, 'lfh': lfh, 'cdh': cdh,
            })
        cd_start   = offset
        cd_bytes   = b''.join(e['cdh'] for e in files_built)
        offset    += len(cd_bytes); n = len(files_built); cd_size = len(cd_bytes)
        zip64_eocd = _st.pack('<4s Q HHII QQ QQ',
            ZIP64_EOCD_SIG, 44, 45, 45, 0, 0, n, n, cd_size, cd_start)
        zip64_loc  = _st.pack('<4s I Q I', ZIP64_EOCD_LOCATOR, 0, offset, 1)
        offset    += len(zip64_eocd) + len(zip64_loc)
        eocd       = _st.pack('<4s HH HH II H',
            EOCD_SIG, 0, 0,
            min(n, UINT16_MAX), min(n, UINT16_MAX),
            min(cd_size, UINT32_MAX), min(cd_start, UINT32_MAX), 0)
        offset    += len(eocd)

        all_missing = missing + actual_missing
        filename    = folder_name + '.zip'
        session_id  = str(_uuid_mod.uuid4())
        session     = {
            'files': files_built, 'cd_bytes': cd_bytes,
            'zip64_eocd': zip64_eocd, 'zip64_loc': zip64_loc, 'eocd': eocd,
            'cd_start': cd_start, 'total_size': offset,
            'filename': filename, 'missing': all_missing,
            'expires': time.time() + ZIP_SESSION_TTL, 'user_id': user_id,
        }
        with _zip_sessions_lock:
            _zip_sessions[session_id] = session

        logging.info(
            'zip_build: %s — %d files, %d bytes, %d missing, '
            'needs_hashing=%s session=%s\u2026',
            filename, len(files_built), offset, len(all_missing),
            needs_hashing, session_id[:8],
        )
        _upd(status='ready', session=session_id, filename=filename,
             size=offset, missing=all_missing, needs_hashing=needs_hashing,
             expires=time.time() + ZIP_JOB_TTL)

    except Exception as e:
        logging.error('zip_build job %s failed: %s', job_id[:8], e)
        _upd(status='error', error=str(e))



def _get_policy_versions() -> dict:
    try:
        with open(_POLICY_VERSIONS_FILE, encoding='utf-8') as f:
            data = json.load(f)

        def _pick(val):
            # New multi-language shape: {"eng": "1.0", "ukr": "0.0.0"}
            # Old flat shape: "1.0"
            if isinstance(val, dict):
                return str(val.get('eng') or next(iter(val.values()), '0.0.0'))
            return str(val) if val else '0.0.0'

        return {
            'tos': _pick(data.get('tos', '0.0.0')),
            'pp':  _pick(data.get('pp',  '0.0.0')),
        }
    except FileNotFoundError:
        logging.warning(f'policies/versions.json not found — defaulting to 0.0.0. Got the file place value: {_POLICY_VERSIONS_FILE}')
        return {'tos': '0.0.0', 'pp': '0.0.0'}
    except Exception:
        logging.exception('Failed to read policies/versions.json — defaulting to 0.0.0')
        return {'tos': '0.0.0', 'pp': '0.0.0'}

# ==============================================================================
# --- LOGGER SETUP (use shared CustomLogger) ---
# ==============================================================================
# Redirect print/stdout/stderr to our CustomLogger which writes to the log file
sys.stdout = CustomLogger(LOG_FILE)
sys.stderr = sys.stdout
# Do NOT use StreamHandler(sys.stderr) here — CustomLogger already writes to
# the file internally. A StreamHandler pointing back at CustomLogger would
# cause every logging.* call to hit the file twice.
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s')

# ==============================================================================
# --- TRASH BIN HELPERS ---
# ==============================================================================


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

def _pending_dest_paths(user_id: int) -> set:
    """Return the set of dest_path values for in-progress direct-write sessions
    owned by *user_id*.  These files are pre-allocated but not yet complete and
    must not appear in directory listings.

    The index on (dest_path, upload_status, completed) makes this fast.
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                """SELECT dest_path FROM upload_sessions
                WHERE owner_ref = ? AND owner_type = 'user'
                    AND strategy = 'direct' AND completed = 0""",
                (str(user_id),)
            ).fetchall()
        return {r[0] for r in rows}
    except Exception:
        logging.exception('_pending_dest_paths failed')
        return set()

# ==============================================================================
# --- MAIN REQUEST HANDLER ---
# ==============================================================================
class _FastThreadingHTTPServer(ThreadingHTTPServer):
    # 512 KB write buffer — reduces syscall count for large file transfers.
    # Raised from 256 KB: at 10 MB/s a 256 KB buffer flushes every ~25 ms;
    # at 512 KB every ~50 ms, which is still well within any keepalive window.
    wbufsize = 512 * 1024
    # Keep-alive: allow the OS to reuse address immediately on restart
    allow_reuse_address = True

    def server_bind(self):
        # 4 MB TCP send buffer: gives the kernel room to pipeline chunks
        # without blocking the Python write loop waiting for ACKs.
        self.socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, 4 * 1024 * 1024)
        super().server_bind()


class AuthHandler(SimpleHTTPRequestHandler):
    server_version = "FluxDrop/4.0-Auth"

    # Idle-connection timeout — same reasoning as server_https.py RequestHandler.
    # Without this, zombie TCP connections (client gone but socket still open)
    # hold OS threads indefinitely, exhausting the thread pool over days.
    timeout = 45  # seconds

    # Route all HTTP access/error log lines through the logging module instead
    # of writing directly to sys.stderr (BaseHTTPRequestHandler's default).
    # This eliminates duplicate log lines that appear when both the HTTP and
    # HTTPS server threads share the same root logger handler — the base class
    # wrote to stderr once per request, and logging.basicConfig wrote the same
    # line again via its StreamHandler(sys.stderr).
    def log_message(self, fmt, *args):
        if not DEBUG_LOGGING:
            msg = fmt % args
            # In production, skip routine static-file GETs to reduce log I/O
            if not any(x in msg for x in ('/api/', '/auth/', '/share/', '/healthz')):
                return
        logging.info('%s - %s', self.address_string(), fmt % args)

    def log_error(self, fmt, *args):
        logging.warning('%s - %s', self.address_string(), fmt % args)

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
    zip_pattern          = re.compile(r'^/api/(v[1-3])/zip(/.*)?$')
    zip_meta_pattern     = re.compile(r'^/api/(v[1-3])/zip_meta(/.*)?$')
    zip_status_pattern   = re.compile(r'^/api/(v[1-3])/zip_status/([0-9a-f\-]{36})$')
    zip_stream_pattern   = re.compile(r'^/api/(v[1-3])/zip_stream/([0-9a-f\-]{36})$')
    foldersize_pattern   = re.compile(r'^/api/(v[1-3])/foldersize(/.*)?$')
    archive_tree_pattern = re.compile(r'^/api/(v[1-3])/archive_tree(/.*)?$')
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
    upload_session_assemble_progress_pattern = re.compile(r'^/api/(v[1-3])/upload_session/([A-Za-z0-9_\-]+)/assembly_progress$')
    board_list_pattern  = re.compile(r'^/api/(v[1-3])/board$')
    board_item_pattern  = re.compile(r'^/api/(v[1-3])/board/(\d+)$')
    incident_pattern    = re.compile(r'^/api/(v[1-3])/incident$')
    trash_list_pattern   = re.compile(r'^/api/(v[1-3])/trash$')
    trash_item_pattern   = re.compile(r'^/api/(v[1-3])/trash/(\d+)$')
    trash_restore_pattern= re.compile(r'^/api/(v[1-3])/trash/(\d+)/restore$')
    batch_tar_pattern = re.compile(r'^/api/(v[1-3])/upload_session/batch_tar$')
    
    # ── P2: Force HTTPS for sensitive paths ──────────────────────────────────
    # NOTE: _redirect_to_https_if_needed is defined ONCE below (~line 1099).
    # A second definition here was previously silently overwriting the lower one
    # (Python uses the last binding in a class body) and both had the Host-header
    # bug that produced Location: https://127.0.0.1:<port>/...
    # The canonical definition below always uses PUBLIC_DOMAIN.
    _HTTPS_ONLY_PREFIXES = ('/auth/', '/api/')

    def handle_batch_tar_upload(self):
        """POST /api/v1/upload_session/batch_tar

        Accepts an uncompressed tar stream (Content-Type: application/x-tar)
        and extracts each entry directly to the user\'s FluxDrop directory.
        No temporary archive file is written — entries land on disk as they
        stream in, keeping memory usage O(largest_single_file).

        Query / JSON body parameters
        ----------------------------
        dest_path  : destination folder relative to the user\'s root (required)
        mode       : \'write\'  — always overwrite existing files (default)
                     \'skip\'   — skip files that already exist on disk
                     \'sync\'   — overwrite only when the on-disk size differs
                                from the tar entry size; skip identical ones
        sha256_manifest : optional JSON object {arcname: sha256_hex, ...}
                         if provided, each extracted file is verified after write

        The server streams a newline-delimited JSON (NDJSON) progress log as it
        works, one object per line:
            {"type":"progress","done":N,"total":-1,"name":"path/to/file"}
            {"type":"skipped","name":"path/to/file","reason":"exists"}
            {"type":"done","extracted":N,"skipped":N,"errors":N}
            {"type":"error","name":"path/to/file","msg":"..."}

        Notification
        ------------
        On completion a notification is fired (see _fire_upload_notification).
        """
        import tarfile as _tf
        import io as _io

        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))

        # --- Parse parameters from query string or a leading JSON preamble ---
        parsed_qs = parse_qs(urlparse(self.path).query)
        dest_rel  = unquote(parsed_qs.get("dest_path", [""])[0]).strip("/")
        mode      = parsed_qs.get("mode", ["write"])[0].lower()
        if mode not in ("write", "skip", "sync"):
            mode = "write"

        sha256_manifest: dict = {}
        manifest_raw = parsed_qs.get("sha256_manifest", [None])[0]
        if manifest_raw:
            try:
                sha256_manifest = json.loads(manifest_raw)
            except Exception:
                pass

        # Resolve destination
        user_root = os.path.normpath(os.path.join(SERVE_ROOT, "FluxDrop", str(user_id)))
        dest_fs   = os.path.normpath(os.path.join(user_root, dest_rel)) if dest_rel else user_root
        if not os.path.realpath(dest_fs).startswith(os.path.realpath(user_root)):
            return self._send_response(400, json.dumps({"error": "Invalid dest_path."}))
        os.makedirs(dest_fs, exist_ok=True)

        # Quota check (rough: compare current usage vs quota before we start)
        try:
            with _db_connect() as _qc:
                _qrow = _qc.execute("SELECT quota_bytes FROM users WHERE id=?", (user_id,)).fetchone()
            _quota = (_qrow[0] if _qrow and _qrow[0] else _compute_dynamic_quota())
            _usage = _get_user_disk_usage(user_id)
            if _usage >= _quota:
                return self._send_response(507, json.dumps({"error": "Storage quota exceeded."}))
        except Exception:
            logging.exception("batch_tar: quota check failed")

        content_length = int(self.headers.get("Content-Length", -1))

        # Stream the tar directly from the socket
        # tarfile.open() with fileobj=self.rfile and mode=\'r|\'  (pipe mode)
        # reads sequentially without seeking — perfect for streaming.
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def _emit(obj: dict):
            line = (json.dumps(obj) + "\\n").encode()
            try:
                # HTTP/1.1 chunked encoding
                self.wfile.write(f"{len(line):x}\\r\\n".encode())
                self.wfile.write(line)
                self.wfile.write(b"\\r\\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        extracted = skipped = errors = 0
        READ_BUF = 4 * 1024 * 1024

        try:
            tf = _tf.open(fileobj=self.rfile, mode="r|")  # pipe (streaming) mode
            for member in tf:
                name = member.name
                # Security: prevent path traversal
                safe_name = os.path.normpath(name).lstrip("/")
                if safe_name.startswith(".."):
                    _emit({"type": "error", "name": name, "msg": "path traversal rejected"})
                    errors += 1
                    tf.members = []  # skip remaining data for this entry
                    continue

                dest_file = os.path.normpath(os.path.join(dest_fs, safe_name))
                if not os.path.realpath(dest_file).startswith(os.path.realpath(dest_fs)):
                    _emit({"type": "error", "name": name, "msg": "outside dest_path"})
                    errors += 1
                    tf.members = []
                    continue

                if member.isdir():
                    os.makedirs(dest_file, exist_ok=True)
                    continue

                if not member.isfile():
                    continue  # skip symlinks, devices, etc.

                # --- Merge mode logic ---
                if mode == "skip" and os.path.exists(dest_file):
                    _emit({"type": "skipped", "name": safe_name, "reason": "exists"})
                    skipped += 1
                    tf.members = []  # must consume the entry data
                    f_obj = tf.extractfile(member)
                    if f_obj:
                        while f_obj.read(READ_BUF):
                            pass
                    continue

                if mode == "sync" and os.path.exists(dest_file):
                    try:
                        on_disk_size = os.path.getsize(dest_file)
                    except OSError:
                        on_disk_size = -1
                    if on_disk_size == member.size:
                        _emit({"type": "skipped", "name": safe_name, "reason": "same_size"})
                        skipped += 1
                        f_obj = tf.extractfile(member)
                        if f_obj:
                            while f_obj.read(READ_BUF):
                                pass
                        continue

                # --- Extract ---
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                f_obj = tf.extractfile(member)
                if f_obj is None:
                    continue  # empty regular file in some tar dialects
                try:
                    hasher = None
                    expected_sha = sha256_manifest.get(name) or sha256_manifest.get(safe_name)
                    if expected_sha:
                        import hashlib as _hl
                        try:
                            hasher = _hl.sha256(usedforsecurity=False)
                        except TypeError:
                            hasher = _hl.sha256()

                    with open(dest_file, "wb") as out:
                        while True:
                            chunk = f_obj.read(READ_BUF)
                            if not chunk:
                                break
                            out.write(chunk)
                            if hasher:
                                hasher.update(chunk)

                    if hasher:
                        actual = hasher.hexdigest()
                        if actual.lower() != expected_sha.lower():
                            os.remove(dest_file)
                            _emit({"type": "error", "name": safe_name,
                                   "msg": f"sha256 mismatch: expected {expected_sha[:12]}… got {actual[:12]}…"})
                            errors += 1
                            extracted -= 1  # will be corrected below
                            continue

                    extracted += 1
                    _emit({"type": "progress", "done": extracted + skipped,
                           "total": -1, "name": safe_name})
                except Exception as exc:
                    logging.exception(f"batch_tar: failed to extract {name}")
                    _emit({"type": "error", "name": safe_name, "msg": str(exc)})
                    errors += 1
                    try:
                        os.remove(dest_file)
                    except OSError:
                        pass

            tf.close()
        except Exception as exc:
            logging.exception("batch_tar: tar streaming failed")
            _emit({"type": "error", "name": "", "msg": f"tar read error: {exc}"})
            errors += 1

        _emit({"type": "done", "extracted": extracted,
               "skipped": skipped, "errors": errors})

        # Fire notification
        _fire_upload_notification(user_id, dest_rel or "/",
            f"Batch upload complete: {extracted} files extracted, "
            f"{skipped} skipped, {errors} errors."
        )

        # Terminate chunked response
        try:
            self.wfile.write(b"0\\r\\n\\r\\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

        logging.info(
            f"batch_tar: user={user_id} dest={dest_rel!r} mode={mode} "
            f"extracted={extracted} skipped={skipped} errors={errors}"
        )

    def _handle_notifications_list(self):
        """GET /api/v1/notifications — list the caller\'s notification subscriptions."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        try:
            with _db_connect() as conn:
                rows = conn.execute(
                    "SELECT id, type, target, enabled, created_at "
                    "FROM upload_notifications WHERE user_id=? ORDER BY id DESC",
                    (user_id,)
                ).fetchall()
            result = [
                {"id": r[0], "type": r[1],
                 "target": r[2], "enabled": bool(r[3]), "created_at": r[4]}
                for r in rows
            ]
            return self._send_response(200, json.dumps({"notifications": result}))
        except Exception as exc:
            logging.exception("notifications_list failed")
            return self._send_response(500, json.dumps({"error": str(exc)}))

    def _handle_notifications_subscribe(self):
        """POST /api/v1/notifications
        Body JSON: { type: "webhook"|"email", target: "<url_or_email>", secret?: "..." }
        Creates a new subscription.  Max 10 per user.
        """
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > MAX_JSON_BODY:
                return self._send_response(400, json.dumps({"error": "Invalid body."}))
            data = json.loads(self.rfile.read(length))
        except Exception:
            return self._send_response(400, json.dumps({"error": "Invalid JSON."}))

        notif_type = str(data.get("type", "")).strip()
        target     = str(data.get("target", "")).strip()
        secret     = str(data.get("secret", "") or "").strip() or None

        if notif_type not in ("webhook", "email"):
            return self._send_response(400, json.dumps({"error": "type must be 'webhook' or 'email'."}))
        if not target:
            return self._send_response(400, json.dumps({"error": "target is required."}))
        if len(target) > 512:
            return self._send_response(400, json.dumps({"error": "target too long."}))
        if notif_type == "webhook" and not target.startswith(("http://", "https://")):
            return self._send_response(400, json.dumps({"error": "Webhook target must be an http/https URL."}))

        try:
            with _db_connect() as conn:
                count = conn.execute(
                    "SELECT COUNT(*) FROM upload_notifications WHERE user_id=?", (user_id,)
                ).fetchone()[0]
                if count >= 10:
                    return self._send_response(409, json.dumps({"error": "Max 10 notification subscriptions per user."}))
                cur = conn.execute(
                    "INSERT INTO upload_notifications (user_id, type, target, secret, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (user_id, notif_type, target, secret, time.time())
                )
                conn.commit()
                new_id = cur.lastrowid
            return self._send_response(201, json.dumps({"id": new_id, "type": notif_type, "target": target}))
        except Exception as exc:
            logging.exception("notifications_subscribe failed")
            return self._send_response(500, json.dumps({"error": str(exc)}))

    def _handle_notifications_delete(self, notif_id: int):
        """DELETE /api/v1/notifications/<id> — remove a subscription."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({"error": "Unauthorized"}))
        try:
            with _db_connect() as conn:
                cur = conn.execute(
                    "DELETE FROM upload_notifications WHERE id=? AND user_id=?",
                    (notif_id, user_id)
                )
                conn.commit()
            if cur.rowcount == 0:
                return self._send_response(404, json.dumps({"error": "Not found."}))
            return self._send_response(200, json.dumps({"ok": True}))
        except Exception as exc:
            logging.exception("notifications_delete failed")
            return self._send_response(500, json.dumps({"error": str(exc)}))

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

    # Paths that carry credentials and must never be served over plain HTTP (B7)
    _HTTPS_ONLY_PREFIXES = ('/auth/', '/api/')

    def _redirect_to_https_if_needed(self) -> bool:
        """308-redirect auth/API paths from HTTP to HTTPS.

        ALWAYS uses PUBLIC_DOMAIN for the Location header.
        Never uses the Host request header — when requests arrive through the
        loopback proxy (server_http.py → CDN port), the Host header contains
        127.0.0.1 which would produce Location: https://127.0.0.1:<port>/...
        and break every login/API call.

        308 preserves the original HTTP method (POST stays POST, unlike 301).
        Returns True when a redirect was sent — caller must return immediately.
        No-ops when the socket is already TLS.
        """
        if isinstance(self.server.socket, ssl.SSLSocket):
            return False  # already on HTTPS, nothing to do
        parsed = urlparse(self.path)
        if any(parsed.path.startswith(p) for p in self._HTTPS_ONLY_PREFIXES):
            # Build the redirect URL from PUBLIC_DOMAIN, never from the Host header.
            # Omit the port when it's the standard HTTPS port (443) so the URL
            # stays clean; include it otherwise (e.g. 64800 for direct-CDN access).
            port_suffix = f':{HTTPS_PORT}' if HTTPS_PORT != 443 else ''
            location = f'https://{PUBLIC_DOMAIN}{port_suffix}{self.path}'
            self.send_response(308)
            self._send_cors_headers()
            self.send_header('Location', location)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return True
        return False

    # ── P3: Universal security headers ───────────────────────────────────────
    def end_headers(self):
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if isinstance(self.server.socket, ssl.SSLSocket):
            self.send_header('Strict-Transport-Security',
                            'max-age=300; includeSubDomains')
        # P7: Content-Security-Policy
        # 'unsafe-inline' is needed because the share snippet pages use inline <script>/<style>.
        # Remove it once those are moved to external files.
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        super().end_headers()

    def _send_response(self, status_code, content, content_type='application/json'):
        """Send an HTTP response, transparently gzip-encoding when the client
        supports it and the payload is a compressible type ≤ _GZIP_MAX_INLINE.

        *content* may be a ``str`` (encoded to UTF-8 here) or ``bytes``.
        Gzip is opt-in via the client's ``Accept-Encoding: gzip`` header so
        existing callers without that header continue to receive plain text —
        no breaking change.
        """
        # Append charset for text responses so browsers don't guess the encoding
        if content_type.startswith('text/') and 'charset' not in content_type:
            content_type = content_type + '; charset=utf-8'

        if isinstance(content, str):
            body = content.encode('utf-8')
        else:
            body = content  # already bytes (e.g. pre-read file data)

        # Determine whether we can gzip this response.
        # Strip the charset suffix for the MIME lookup.
        mime_base = content_type.split(';')[0].strip()
        accept_enc = self.headers.get('Accept-Encoding', '')
        can_gzip = (
            'gzip' in accept_enc
            and mime_base in _GZIP_COMPRESSIBLE
            and _GZIP_MIN_SIZE <= len(body) <= _GZIP_MAX_INLINE
        )

        if can_gzip:
            try:
                body = _gzip_mod.compress(body, compresslevel=6)
                use_gzip = True
            except Exception:
                use_gzip = False
        else:
            use_gzip = False

        try:
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            if use_gzip:
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Vary', 'Accept-Encoding')
            self._send_cors_headers()
            # Security headers (X-Frame-Options, HSTS, CSP, etc.) are sent
            # automatically by the end_headers() override — no duplicates needed here.
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
            # Client closed the connection before we finished writing.
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
            cursor.execute(
                "SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP",
                (_hash_session_token(token),)    # ← P1: compare hash, not raw
            )
            result = cursor.fetchone()
            if result:
                logging.debug(f"Token auth success for user_id '{result[0]}'")
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
                (_hash_session_token(token),)   # ← P1: hash before comparing, same as _check_token_auth
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
            'server_version': SERVER_VERSION,
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
            if length <= 0 or length > MAX_JSON_BODY:
                return self._send_response(400, json.dumps({'error': 'Invalid or missing request body.'}))
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

        if not filename or not dest_rel or total_chunks < 0:
            return self._send_response(400, json.dumps({'error': 'filename, dest_path, total_chunks required.'}))
            # total_chunks == 0 is valid for zero-byte files; we special-case assembly below.

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

            _user_quota_row = None
            with _db_connect() as conn:
                _user_quota_row = conn.execute(
                    'SELECT quota_bytes FROM users WHERE id = ?', (user_id,)
                ).fetchone()
            _quota = (_user_quota_row[0] if _user_quota_row and _user_quota_row[0] else _compute_dynamic_quota())
            _usage = _get_user_disk_usage(user_id)
            if _usage >= _quota:
                return self._send_response(507, json.dumps({
                    'error': f'Storage quota exceeded ({_usage // (1024**2)} MB used of {_quota // (1024**2)} MB). '
                             f'Existing files are kept. New uploads are paused until quota increases.'
                }))

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

        # ── Filesystem conflict guard ─────────────────────────────────────────
        # Catch the two common name-collision errors before any disk allocation:
        #
        #   [Errno 21] Is a directory  — dest_path already exists as a dir.
        #     A file cannot be written where a directory lives.
        #
        #   [Errno 20] Not a directory — a parent path component is a plain
        #     file, so os.makedirs() cannot create the subtree beneath it.
        #
        # Both conditions are user-facing errors (409 Conflict), not server faults.
        if os.path.isdir(dest_path):
            return self._send_response(409, json.dumps({
                'error': (
                    f'"{os.path.basename(dest_path)}" is a folder — '
                    f'cannot upload a file with the same name. '
                    f'Rename or delete the existing folder first.'
                )
            }))

        # Walk parent directories up to (but not including) the user root
        # to detect any ancestor that is a regular file.
        try:
            _parent = os.path.dirname(dest_path)
            # base_fs is only defined for owner_type 'user'/'share' branches above;
            # fall back gracefully for other types.
            _stop = locals().get('base_fs', SERVE_ROOT)
            while _parent and os.path.normpath(_parent) != os.path.normpath(_stop):
                if os.path.isfile(_parent):
                    return self._send_response(409, json.dumps({
                        'error': (
                            f'"{os.path.basename(_parent)}" is a file — '
                            f'cannot create a folder with the same name. '
                            f'Rename or delete the existing file first.'
                        )
                    }))
                _parent = os.path.dirname(_parent)
        except Exception:
            pass   # non-fatal: let _upload_init surface the OS error below

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
        except ValueError as e:
            # ValueError is raised by _upload_init for quota overrun and by
            # the NotADirectoryError handler in _upload_init for path conflicts.
            # Both are client-side problems → 409 Conflict (not 500).
            logging.warning(f'Upload session init rejected: {e}')
            return self._send_response(409, json.dumps({'error': str(e)}))
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
        if content_length < 0:
            return self._send_response(400, json.dumps({'error': 'Content-Length required.'}))
        if content_length == 0:
            # Zero-byte chunk — valid only when the whole file is 0 bytes.
            # Write an empty chunk file so the session can be assembled normally.
            pass
        elif content_length > UPLOAD_CHUNK_SIZE * 2:
            return self._send_response(413, json.dumps({'error': 'Chunk too large.'}))

        if content_length > UPLOAD_CHUNK_SIZE * 2:
            return self._send_response(413, json.dumps({'error': 'Chunk too large.'}))

        # Read raw chunk directly from socket — no /tmp involved
        try:
            self.connection.settimeout(120)   # 2-minute hard deadline per chunk
            data = self.rfile.read(content_length)
            self.connection.settimeout(None)
        except (TimeoutError, OSError) as e:
            logging.warning(f'Chunk {chunk_index} read timeout/error: {e}')
            return self._send_response(408, json.dumps({'error': 'Chunk read timed out. Please retry.'}))

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
            updated = _upload_receive_chunk(upload_token, chunk_index, data,
                                            expected_size=content_length)
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
            # _upload_assemble now returns (dest_path, sha256_hex) — the hash is
            # computed inline during the streaming copy so we never re-read the file.
            dest_path, assembly_sha256 = _upload_assemble(upload_token)
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
        # Re-use the SHA-256 already computed during assembly — no second file read.
        sha256 = assembly_sha256

        logging.info(f'Upload complete: {dest_path} ({size} bytes) sha256={sha256[:12]}… token={upload_token[:12]}…')
        _fire_upload_notification(
            int(session['owner_ref']) if session['owner_type'] == 'user' else 0,
            rel,
            f"Upload of '{session['filename']}' ({size} bytes) completed."
        )
        return self._send_response(200, json.dumps({'url': file_url, 'sha256': sha256, 'size': size}))

    def handle_upload_session_cancel(self, upload_token: str):
        """DELETE /api/v1/upload_session/<token>
        Immediately cancels an in-progress upload session and cleans up:
          - 'buffer' strategy: deletes the tmp chunk directory.
          - 'direct' strategy: deletes the partial pre-allocated destination file.
        Auth: same rules as chunk upload.
        Returns JSON: { cancelled: true }
        """
        session = _upload_get(upload_token)
        if not session:
            return self._send_response(200, json.dumps({'cancelled': True}))
        if session['completed']:
            return self._send_response(409, json.dumps({'error': 'Session already completed.'}))
 
        ok, reason = self._check_upload_session_auth(session)
        if not ok:
            return self._send_response(403, json.dumps({'error': reason}))
 
        try:
            _cancel_upload_session(upload_token)
            logging.info(f'Upload session cancelled: token={upload_token[:12]}… '
                         f'strategy={session.get("strategy","buffer")}')
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

    def handle_upload_session_assembly_progress(self, upload_token: str):
        """GET /api/v1/upload_session/<token>/assembly_progress
        Returns in-process assembly/hashing progress so the client can show
        a real ETA during the 'Verifying…' phase.

        Response JSON:
          { bytes_hashed, total_bytes, pct, eta_seconds, done, error }

        The entry exists only while _upload_assemble() is running in another
        thread (triggered by /complete).  If the entry is absent the assembly
        either hasn't started yet or has already finished and been cleared.
        """
        session = _upload_get(upload_token)
        if not session:
            return self._send_response(404, json.dumps({'error': 'Upload session not found.'}))

        ok, reason = self._check_upload_session_auth(session)
        if not ok:
            return self._send_response(403, json.dumps({'error': reason}))

        prog = _assembly_progress_get(upload_token)
        if prog is None:
            # Not in progress — either not started or already cleaned up
            return self._send_response(200, json.dumps({
                'bytes_hashed': 0, 'total_bytes': session['total_size'],
                'pct': 0, 'eta_seconds': None, 'done': bool(session['completed']),
                'error': None,
            }))

        total   = prog['total_bytes'] or session['total_size'] or 1
        hashed  = prog['bytes_hashed']
        pct     = round(hashed / total * 100, 1) if total > 0 else 0
        return self._send_response(200, json.dumps({
            'bytes_hashed': hashed,
            'total_bytes':  total,
            'pct':          pct,
            'eta_seconds':  None,   # server doesn't track its own speed; client computes ETA
            'done':         prog['done'],
            'error':        prog['error'],
        }))

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
        # Ensure CORS and Accept-Ranges headers are present on HEAD responses.
        # patched_end_headers delegates to self.end_headers (the class override)
        # so X-Frame-Options, HSTS, and CSP are included — previously it called
        # super().end_headers() directly, bypassing all security headers.
        def patched_end_headers():
            self.send_header('Accept-Ranges', 'bytes')
            self._send_cors_headers()
            AuthHandler.end_headers(self)   # go through our override, not the base class

        old_end_headers = self.end_headers
        self.end_headers = patched_end_headers
        try:
            return super().do_HEAD()
        finally:
            self.end_headers = old_end_headers

    # ── IP Beacon handlers ────────────────────────────────────────────────────

    def _handle_beacon_register(self):
        """POST /beacon/register  — register a new device, return both tokens."""
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length) if length else b''
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        label         = str(data.get('label', '')).strip()[:120]
        primary_token = secrets.token_urlsafe(32)
        read_token    = secrets.token_urlsafe(24)
        now           = time.time()
        with _db_connect() as conn:
            cur = conn.execute(
                "INSERT INTO beacon_devices (primary_token, label, created_at, last_seen) VALUES (?,?,?,?)",
                (primary_token, label, now, now)
            )
            conn.execute(
                "INSERT INTO beacon_read_tokens (read_token, device_id, created_at) VALUES (?,?,?)",
                (read_token, cur.lastrowid, now)
            )
            conn.commit()
        return self._send_response(200, json.dumps({
            'primary_token': primary_token,
            'read_token':    read_token,
            'label':         label,
        }), 'application/json')

    def _handle_beacon_ping(self):
        """POST /beacon/ping  — update IP for a registered device (auth: Bearer primary_token)."""
        auth  = self.headers.get('Authorization', '')
        token = auth.removeprefix('Bearer ').strip()
        if not token:
            return self._send_response(401, json.dumps({'error': 'Missing token'}), 'application/json')
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length) if length else b''
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        forwarded = self.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        ip  = forwarded or self.client_address[0]
        ua  = self.headers.get('User-Agent', '')[:256]
        now = time.time()
        with _db_connect() as conn:
            row = conn.execute(
                "SELECT id FROM beacon_devices WHERE primary_token = ?", (token,)
            ).fetchone()
            if not row:
                return self._send_response(403, json.dumps({'error': 'Unknown token'}), 'application/json')
            updates = {'ip': ip, 'user_agent': ua, 'last_seen': now}
            if data.get('label') and str(data['label']).strip():
                updates['label'] = str(data['label']).strip()[:120]
            set_clause = ', '.join(f"{k} = ?" for k in updates)
            conn.execute(
                f"UPDATE beacon_devices SET {set_clause} WHERE id = ?",
                (*updates.values(), row[0])
            )
            conn.commit()
        return self._send_response(200, json.dumps({'ok': True, 'ip': ip}), 'application/json')

    def _handle_beacon_lookup(self):
        """GET /beacon/lookup?token=<primary_or_read_token>  — look up device info."""
        qs    = parse_qs(urlparse(self.path).query)
        token = (qs.get('token') or [''])[0].strip()
        if not token:
            return self._send_response(400, json.dumps({'error': 'token required'}), 'application/json')
        with _db_connect() as conn:
            row = conn.execute(
                "SELECT id, label, ip, user_agent, last_seen, created_at, primary_token "
                "FROM beacon_devices WHERE primary_token = ?", (token,)
            ).fetchone()
            is_owner = row is not None
            if not row:
                row = conn.execute(
                    """SELECT d.id, d.label, d.ip, d.user_agent, d.last_seen,
                              d.created_at, d.primary_token
                       FROM beacon_devices d
                       JOIN beacon_read_tokens r ON r.device_id = d.id
                       WHERE r.read_token = ?""", (token,)
                ).fetchone()
                if row:
                    # Keep the token alive — update last_used so the purge
                    # job doesn't evict it while it's still being polled.
                    conn.execute(
                        'UPDATE beacon_read_tokens SET last_used = ? WHERE read_token = ?',
                        (time.time(), token)
                    )
                    conn.commit()
            if not row:
                return self._send_response(404, json.dumps({'error': 'Token not found'}), 'application/json')
            payload = {
                'label':      row[1],
                'ip':         row[2],
                'user_agent': row[3],
                'last_seen':  row[4],
                'created_at': row[5],
                'online':     (time.time() - row[4]) < 180,
            }
            if is_owner:
                read_tokens = [r[0] for r in conn.execute(
                    "SELECT read_token FROM beacon_read_tokens WHERE device_id = ?", (row[0],)
                ).fetchall()]
                payload['read_tokens']    = read_tokens
                payload['primary_token']  = row[6]
        return self._send_response(200, json.dumps(payload), 'application/json')

    def _handle_beacon_ui(self):
        """GET /beacon/ui  — serve the IP Beacon lookup page.

        No server-side session gate: the page is self-contained JS that reads
        the FluxDrop token from localStorage and calls the API directly.
        Blocking the page load with a 401 just breaks direct navigation; the
        JS already shows the register/lookup UI to everyone and only calls
        session-gated endpoints (e.g. /beacon/register) when a token is
        present in localStorage.
        """
        return self._send_response(
            200,
            _render_snippet('ip_lookup.html', PUBLIC_DOMAIN=PUBLIC_DOMAIN),
            'text/html'
        )

    def _handle_beacon_new_read_token(self):
        """POST /beacon/read_token  — mint a new read token (auth: Bearer primary_token)."""
        auth  = self.headers.get('Authorization', '')
        token = auth.removeprefix('Bearer ').strip()
        if not token:
            return self._send_response(401, json.dumps({'error': 'Missing token'}), 'application/json')
        now = time.time()
        with _db_connect() as conn:
            row = conn.execute(
                "SELECT id FROM beacon_devices WHERE primary_token = ?", (token,)
            ).fetchone()
            if not row:
                return self._send_response(403, json.dumps({'error': 'Unknown token'}), 'application/json')
            new_rt = secrets.token_urlsafe(24)
            conn.execute(
                "INSERT INTO beacon_read_tokens (read_token, device_id, created_at) VALUES (?,?,?)",
                (new_rt, row[0], now)
            )
            conn.commit()
        return self._send_response(200, json.dumps({'read_token': new_rt}), 'application/json')

    def do_GET(self):
        """Routes GET requests to the appropriate handler or serves static files."""
        # Just in case: add the function
        if self._redirect_to_https_if_needed():   # ← P2
            return

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

        # Assembly progress (polled by the client during the 'Verifying…' phase)
        us_ap = self.upload_session_assemble_progress_pattern.match(parsed_url.path)
        if us_ap:
            return self.handle_upload_session_assembly_progress(us_ap.group(2))

        # Folder download as ZIP (streaming, STORE compression)
        _zip_m = self.zip_pattern.match(parsed_url.path)
        if _zip_m:
            return self._handle_zip(_zip_m.group(2) or '/')
        _zip_meta_m = self.zip_meta_pattern.match(parsed_url.path)
        if _zip_meta_m:
            return self._handle_zip_meta(_zip_meta_m.group(2) or '/')
        _zip_status_m = self.zip_status_pattern.match(parsed_url.path)
        if _zip_status_m:
            return self._handle_zip_status(_zip_status_m.group(2))
        _zip_stream_m = self.zip_stream_pattern.match(parsed_url.path)
        if _zip_stream_m:
            return self._handle_zip_stream(_zip_stream_m.group(2))

        # Archive file-tree listing (no full download — reads ZIP central dir only)
        _at_m = self.archive_tree_pattern.match(parsed_url.path)
        if _at_m:
            return self._handle_archive_tree(_at_m.group(2) or '/')

        # Lazy folder size computation
        _fs_m = self.foldersize_pattern.match(parsed_url.path)
        if _fs_m:
            return self._handle_foldersize(_fs_m.group(2) or '/')

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

        # Bare /share or /share/ with no token → friendly error page
        if parsed_url.path in ('/share', '/share/'):
            return self._send_response(404, self._render_share_not_found_page(), 'text/html')

        # Public share page / file access
        pub_match = self.public_share_pattern.match(parsed_url.path)
        if pub_match:
            return self.handle_public_share(pub_match.group(1), pub_match.group(2), parsed_url)

        # Trash bin list
        if self.trash_list_pattern.match(parsed_url.path):
            return self._handle_trash_list()

        # GET /api/v1/trash/<id>/file  — stream trashed file for preview
        trash_item_pattern_preview = re.match(r'^/api/v\d/trash/(\d+)/file$', parsed_url.path)
        if trash_item_pattern_preview:
            return self._handle_trash_file_stream(int(trash_item_pattern_preview.group(1)))

        # GET /api/v1/trash/<id>/list  — list contents of a trashed folder
        trash_folder_list_m = re.match(r'^/api/v\d/trash/(\d+)/list$', parsed_url.path)
        if trash_folder_list_m:
            return self._handle_trash_folder_list(int(trash_folder_list_m.group(1)))

        # GET /api/v1/space_analyze  — top files/folders by size for the space analyzer UI
        if parsed_url.path in ('/api/v1/space_analyze', '/api/v2/space_analyze'):
            return self._handle_space_analyze(parsed_url)

        # FluxDrop API calls
        flux_match = self.fluxdrop_api_pattern.match(parsed_url.path)
        if flux_match:
            return self.handle_fluxdrop_api_get(flux_match)
        
        # User profile / quota info
        if parsed_url.path == '/api/v1/me':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required.'}))
            with _db_connect() as conn:
                row = conn.execute(
                    'SELECT id, username, nickname, email, is_admin, quota_bytes, quota_override, created_at FROM users WHERE id = ?',
                    (user_id,)
                ).fetchone()
            if not row:
                return self._send_response(404, json.dumps({'error': 'User not found.'}))
            uid, uname, nick, email, adm, quota, qover, created = row
            eff_quota = quota if quota else _compute_dynamic_quota()
            usage = _get_user_disk_usage(uid)
            trash_bytes = _trash_size_used(uid)
            return self._send_response(200, json.dumps({
                'id': uid, 'username': uname, 'nickname': nick, 'email': email,
                'is_admin': bool(adm), 'quota_bytes': eff_quota,
                'quota_override': bool(qover), 'usage_bytes': usage,
                'trash_bytes': trash_bytes,
                'created_at': created,
            }))
        
        if parsed_url.path == '/api/v1/policy/status':
            return self._handle_policy_status()

        # ── Avatar serve: GET /api/v1/avatar/<user_id> ───────────────────────
        # Public: no auth required so avatars load in the login screen too.
        # Returns the stored AVIF/WebP blob or 404 with a JSON body if absent.
        _avatar_m = re.match(r'^/api/v[1-3]/avatar/(\d+)$', parsed_url.path)
        if _avatar_m:
            _av_uid = int(_avatar_m.group(1))
            with _db_connect() as _av_conn:
                _av_row = _av_conn.execute(
                    'SELECT avatar_data, avatar_mime FROM users WHERE id = ?', (_av_uid,)
                ).fetchone()
            if not _av_row or not _av_row[0]:
                return self._send_response(404, json.dumps({'error': 'No avatar'}))
            _av_data, _av_mime = _av_row
            self.send_response(200)
            self.send_header('Content-Type', _av_mime or 'image/avif')
            self.send_header('Content-Length', str(len(_av_data)))
            self.send_header('Cache-Control', 'max-age=86400')
            self._send_cors_headers()
            super(AuthHandler, self).end_headers()
            self.wfile.write(_av_data)
            return

        # ── File info + checksum: GET /api/v1/fileinfo/<path> ────────────────
        # Returns cached CRC-32 (hex), SHA-256 (hex), size, mtime, MIME, and
        # current checksum job status for the requested file.
        # Auth required (user can only query their own files).
        # Checksums are served from the DB cache — no blocking computation.
        # The client triggers on-demand computation via POST /api/v1/checksums/compute
        # and polls this endpoint until the job finishes.
        if parsed_url.path.startswith('/api/v1/fileinfo/') or parsed_url.path == '/api/v1/fileinfo':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required'}))
            # Strip the /api/v1/fileinfo prefix to get the relative file path,
            # then URL-decode so spaces (%20) and non-ASCII (%D1%86…) resolve correctly.
            rel = _up.unquote(parsed_url.path[len('/api/v1/fileinfo'):])
            if not rel or rel == '/':
                return self._send_response(400, json.dumps({'error': 'path required'}))

            # Resolve to an absolute filesystem path (mirrors the download handler)
            if rel.startswith('/cdn'):
                abs_path = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, rel[len('/cdn'):].lstrip('/')))
                cs_key   = rel        # checksum key is the CDN-relative path
                cs_uid   = 0          # CDN checksums stored under uid 0
                # Bounds check — never escape CDN upload dir
                if not abs_path.startswith(os.path.normpath(CDN_UPLOAD_DIR) + os.sep):
                    return self._send_response(403, json.dumps({'error': 'Forbidden'}))
            else:
                user_dir = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
                abs_path = os.path.normpath(os.path.join(user_dir, rel.lstrip('/')))
                cs_key   = rel
                cs_uid   = user_id
                # Bounds check — never escape user's own directory
                if not abs_path.startswith(user_dir + os.sep):
                    return self._send_response(403, json.dumps({'error': 'Forbidden'}))

            # Safety: never escape the storage root
            if os.path.isdir(abs_path):
                return self._send_response(400, json.dumps({'error': 'path is a directory'}))
            if not os.path.isfile(abs_path):
                return self._send_response(404, json.dumps({'error': 'File not found'}))

            try:
                st = os.stat(abs_path)
            except OSError as _oe:
                return self._send_response(404, json.dumps({'error': str(_oe)}))

            # Return cached checksums — no blocking computation.
            crc32_hex  = None
            sha256_hex = None
            try:
                stored = checksum_get(cs_key, cs_uid)
                if stored and checksum_is_fresh(stored, abs_path):
                    crc32_hex  = format(stored['crc32'], '08x') if stored['crc32'] is not None else None
                    sha256_hex = stored.get('sha256')
            except Exception:
                logging.exception('fileinfo: checksum lookup failed for %r', abs_path)

            # Latest job for this file — lets the client show a "Calculating…"
            # indicator and poll until done.
            job_info = None
            try:
                job = checksum_job_get_latest(cs_key, cs_uid)
                if job:
                    job_info = {
                        'id':     job['id'],
                        'status': job['status'],
                        'algos':  job['algos'],
                        'error':  job['error_msg'],
                    }
            except Exception:
                logging.exception('fileinfo: job lookup failed for %r', abs_path)

            mime_guess, _ = mimetypes.guess_type(abs_path)

            payload = {
                'name':   os.path.basename(abs_path),
                'size':   st.st_size,
                'mtime':  datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds'),
                'crc32':  crc32_hex,
                'sha256': sha256_hex,
                'mime':   mime_guess,
                'job':    job_info,
            }
            return self._send_response(200, json.dumps(payload))

        if parsed_url.path == '/api/v1/admin/users':
            admin = self._check_admin_auth()
            if not admin: return
            with _db_connect() as conn:
                rows = conn.execute(
                    'SELECT id, username, nickname, email, is_admin, quota_bytes, quota_override, created_at FROM users ORDER BY id'
                ).fetchall()
            out = []
            for r in rows:
                uid, uname, nick, email, adm, quota, qover, created = r
                eff_quota = quota if quota else _compute_dynamic_quota()
                out.append({'id': uid, 'username': uname, 'nickname': nick, 'email': email,
                            'is_admin': bool(adm), 'quota_bytes': eff_quota, 'quota_override': bool(qover),
                            'usage_bytes': _get_user_disk_usage(uid), 'created_at': created})
            return self._send_response(200, json.dumps({'users': out}))

        # Beacon IP lookup (JSON API)
        if parsed_url.path == '/beacon/lookup':
            return self._handle_beacon_lookup()

        # Beacon UI (session-gated HTML page)
        if parsed_url.path == '/beacon/ui':
            return self._handle_beacon_ui()

        if parsed_url.path == '/api/v1/notifications':
            return self._handle_notifications_list()

        # For any other GET request, assume it's a static file.
        # Policy files (versions.json and *.md under /policies/) must never be
        # cached — the SW and browser must always fetch the current version so
        # that policy-version checks and document rendering are never stale.
        parsed_static = urlparse(self.path)
        static_path   = parsed_static.path.rstrip('/')
        if static_path.endswith('policies/versions.json') or \
                re.search(r'/policies/[^/]+/[^/]+/[^/]+\.md$', static_path):
            def patched_end_headers_nocache():
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Accept-Ranges', 'bytes')
                self._send_cors_headers()
                super(AuthHandler, self).end_headers()
            old_end_headers = self.end_headers
            self.end_headers = patched_end_headers_nocache
            try:
                return super().do_GET()
            finally:
                self.end_headers = old_end_headers

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
        if self._redirect_to_https_if_needed():   # ← P2
            return

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

        # Policy acceptance
        if parsed_url.path == '/api/v1/policy/accept':
            return self._handle_policy_accept()

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

        # Batch tar streaming upload
        if self.batch_tar_pattern.match(parsed_url.path):
            return self.handle_batch_tar_upload()

        # FluxDrop API
        flux_match = self.fluxdrop_api_pattern.match(parsed_url.path)
        if flux_match:
            return self.handle_fluxdrop_api_post(flux_match)

        # Trash bin: move to trash
        if self.trash_list_pattern.match(parsed_url.path):
            return self._handle_trash_move()

        # Trash bin: restore item
        _tr_restore = self.trash_restore_pattern.match(parsed_url.path)
        if _tr_restore:
            return self._handle_trash_restore(int(_tr_restore.group(2)))

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

        # Beacon IP tracking endpoints
        if parsed_url.path == '/beacon/register':
            return self._handle_beacon_register()
        if parsed_url.path == '/beacon/ping':
            return self._handle_beacon_ping()
        if parsed_url.path == '/beacon/read_token':
            return self._handle_beacon_new_read_token()

        if parsed_url.path == '/api/v1/notifications':
            return self._handle_notifications_subscribe()

        # ── Avatar upload: POST /api/v1/me/avatar ────────────────────────────
        # Accepts multipart/form-data with a single field named "avatar".
        # Converts the image to AVIF (falls back to WebP/JPEG if Pillow lacks
        # AVIF support), then caps to AVATAR_MAX_DIM × AVATAR_MAX_DIM px and
        # AVATAR_MAX_BYTES.  Stores the blob directly in the DB (users table).
        #
        # Tunable constants (change here only — values propagated everywhere):
        AVATAR_MAX_DIM   = 1024   # px — longest edge after resize
        AVATAR_MAX_BYTES = 50 * 1024   # 50 kB — hard limit after encode
        if parsed_url.path == '/api/v1/me/avatar':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required'}))
            ct = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in ct:
                return self._send_response(400, json.dumps({'error': 'multipart/form-data required'}))
            try:
                from io import BytesIO as _BytesIO
                cl = int(self.headers.get('Content-Length', 0))
                raw_body = self.rfile.read(cl)
                environ = {
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': ct,
                    'CONTENT_LENGTH': str(cl),
                    'wsgi.input': _BytesIO(raw_body),  # required by werkzeug
                }
                from werkzeug.formparser import parse_form_data as _pfd
                _stream, _form, _files = _pfd(environ)
                av_file = _files.get('avatar')
                if not av_file:
                    return self._send_response(400, json.dumps({'error': "Field 'avatar' missing"}))
                img_bytes = av_file.read()
            except Exception as _ae:
                return self._send_response(400, json.dumps({'error': f'Upload parse error: {_ae}'}))
            try:
                from PIL import Image as _PILImage
                import io as _io2
                img = _PILImage.open(_io2.BytesIO(img_bytes))
                img = img.convert('RGBA')
                # Resize so the longest edge ≤ AVATAR_MAX_DIM
                w, h = img.size
                if max(w, h) > AVATAR_MAX_DIM:
                    ratio = AVATAR_MAX_DIM / max(w, h)
                    img = img.resize((int(w * ratio), int(h * ratio)), _PILImage.LANCZOS)
                # Try AVIF first (Pillow ≥ 9.1 with libavif)
                for fmt, mime, kwargs in [
                    ('AVIF', 'image/avif', {'quality': 70}),
                    ('WEBP', 'image/webp', {'quality': 80, 'method': 4}),
                    ('JPEG', 'image/jpeg', {'quality': 82}),
                ]:
                    try:
                        buf = _io2.BytesIO()
                        out_img = img if fmt != 'JPEG' else img.convert('RGB')
                        out_img.save(buf, format=fmt, **kwargs)
                        encoded = buf.getvalue()
                        if len(encoded) <= AVATAR_MAX_BYTES:
                            out_mime = mime
                            out_bytes = encoded
                            break
                        # Over limit — try harder compression
                        q = kwargs.get('quality', 80) - 20
                        if q < 20:
                            continue
                        buf = _io2.BytesIO()
                        out_img.save(buf, format=fmt, quality=q)
                        encoded = buf.getvalue()
                        if len(encoded) <= AVATAR_MAX_BYTES:
                            out_mime = mime
                            out_bytes = encoded
                            break
                    except Exception:
                        continue
                else:
                    return self._send_response(413, json.dumps({
                        'error': f'Avatar too large after compression (limit {AVATAR_MAX_BYTES // 1024} kB). '
                                 'Please use a smaller source image.'
                    }))
            except ImportError:
                return self._send_response(500, json.dumps({
                    'error': 'Pillow not installed — avatar upload requires Pillow (pip install Pillow).'
                }))
            except Exception as _pe:
                return self._send_response(400, json.dumps({'error': f'Image processing failed: {_pe}'}))
            with _db_connect() as conn:
                conn.execute(
                    'UPDATE users SET avatar_data = ?, avatar_mime = ? WHERE id = ?',
                    (out_bytes, out_mime, user_id)
                )
                conn.commit()
            return self._send_response(200, json.dumps({
                'ok': True, 'mime': out_mime, 'size_bytes': len(out_bytes)
            }))

        # ── On-demand checksum computation ───────────────────────────────────
        # POST /api/v1/checksums/compute
        # Body: {"path": "/foo/bar.txt", "algos": ["crc32", "sha256"]}
        # Creates a persistent job, enqueues it to the background worker.
        # Returns: {"job_id": N, "status": "pending", "algos": "crc32,sha256"}
        if parsed_url.path == '/api/v1/checksums/compute':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required'}))
            try:
                cl = int(self.headers.get('Content-Length', 0))
                if cl <= 0 or cl > MAX_JSON_BODY:
                    raise ValueError('bad Content-Length')
                data = json.loads(self.rfile.read(cl))
            except Exception:
                return self._send_response(400, json.dumps({'error': 'Invalid JSON body'}))

            file_path  = data.get('path', '')
            algos_raw  = data.get('algos', ['crc32', 'sha256'])
            valid_set  = {'crc32', 'sha256'}
            algos_list = [a for a in algos_raw if isinstance(a, str) and a in valid_set]
            if not file_path or not algos_list:
                return self._send_response(400, json.dumps({'error': 'path and algos are required'}))

            # Resolve path (mirrors the fileinfo GET handler)
            if file_path.startswith('/cdn'):
                abs_path = os.path.normpath(
                    os.path.join(CDN_UPLOAD_DIR, file_path[len('/cdn'):].lstrip('/')))
                cs_key  = file_path
                cs_uid  = 0
                if not abs_path.startswith(os.path.normpath(CDN_UPLOAD_DIR) + os.sep):
                    return self._send_response(403, json.dumps({'error': 'Forbidden'}))
            else:
                user_dir = os.path.normpath(
                    os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
                abs_path = os.path.normpath(
                    os.path.join(user_dir, file_path.lstrip('/')))
                cs_key  = file_path
                cs_uid  = user_id
                if not abs_path.startswith(user_dir + os.sep):
                    return self._send_response(403, json.dumps({'error': 'Forbidden'}))

            if not os.path.isfile(abs_path):
                return self._send_response(404, json.dumps({'error': 'File not found'}))

            algos_str      = ','.join(sorted(algos_list))
            job_id, is_new = checksum_job_create(cs_key, cs_uid, algos_str)
            if is_new:
                dispatch_checksum_job(job_id, abs_path, cs_key, cs_uid, algos_str)

            return self._send_response(200, json.dumps({
                'job_id': job_id,
                'status': 'pending',
                'algos':  algos_str,
            }))

        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    def do_PATCH(self):
        """Routes PATCH requests (used to update share settings)."""
        if self._redirect_to_https_if_needed():   # ← P2
            return

        with blacklist_lock:
            if self.client_address[0] in current_blacklist:
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))
        parsed_url = urlparse(self.path)
        item_match = self.shares_item_pattern.match(parsed_url.path)
        if item_match:
            return self.handle_share_update(item_match.group(2))
        # User self-update: PATCH /api/v1/me  {nickname?, email?}
        if parsed_url.path == '/api/v1/me':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required.'}))
            try:
                length = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(length))
            except Exception:
                return self._send_response(400, json.dumps({'error': 'Invalid JSON.'}))
            allowed = {'nickname', 'email'}
            updates = {k: v for k, v in data.items() if k in allowed and isinstance(v, str) and v.strip()}
            if not updates:
                return self._send_response(400, json.dumps({'error': 'Nothing to update. Allowed fields: nickname, email.'}))
            parts = ', '.join(f'{k} = ?' for k in updates)
            vals  = [v.strip() for v in updates.values()] + [user_id]
            with _db_connect() as conn:
                conn.execute(f'UPDATE users SET {parts} WHERE id = ?', vals)
                conn.commit()
            return self._send_response(200, json.dumps({'message': 'Profile updated.'}))

        # Password change: PATCH /api/v1/me/password  {current_password, new_password}
        if parsed_url.path == '/api/v1/me/password':
            # P4a: rate-limit — same bucket as login to prevent brute-forcing current_password
            client_ip = self.client_address[0]
            if not _rate_limit(client_ip, "auth"):
                return self._send_response(429, json.dumps({'error': 'Too many attempts. Please wait.'}))

            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required'}))
            try:
                # P4b: body size cap (mirrors the A4 fix already applied to upload_session_init)
                length = int(self.headers.get('Content-Length', 0))
                if length <= 0 or length > MAX_JSON_BODY:
                    return self._send_response(400, json.dumps({'error': 'Invalid or missing request body.'}))
                data = json.loads(self.rfile.read(length))
            except Exception:
                return self._send_response(400, json.dumps({'error': 'Invalid JSON.'}))
            cur_pw  = data.get('current_password', '')
            new_pw  = data.get('new_password', '')
            if not cur_pw or not new_pw:
                return self._send_response(400, json.dumps({'error': 'current_password and new_password required.'}))
            if len(new_pw) < 8:
                return self._send_response(400, json.dumps({'error': 'New password must be at least 8 characters.'}))
            if len(new_pw) > 1024:
                return self._send_response(400, json.dumps({'error': 'New password too long.'}))
            with _db_connect() as conn:
                row = conn.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,)).fetchone()
                if not row:
                    return self._send_response(404, json.dumps({'error': 'User not found.'}))
                stored_hash = row[0]
                if not bcrypt.checkpw(_prepare_password(cur_pw), stored_hash.encode('utf-8')):  # ← P6
                    return self._send_response(401, json.dumps({'error': 'Current password is incorrect.'}))
                new_hash, _ = hash_password(new_pw)
                conn.execute('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?', (new_hash, '', user_id))
                # Invalidate all existing sessions so other devices are logged out
                conn.execute('DELETE FROM sessions WHERE user_id = ? AND session_token != (SELECT session_token FROM sessions WHERE user_id = ? ORDER BY expires_at DESC LIMIT 1)', (user_id, user_id))
                conn.commit()
            return self._send_response(200, json.dumps({'message': 'Password changed. Other sessions have been logged out.'}))

        _admin_user = re.match(r'^/api/v1/admin/users/(\d+)$', parsed_url.path)
        if _admin_user:
            admin = self._check_admin_auth()
            if not admin: return
            target_id = int(_admin_user.group(1))
            try:
                length = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(length))
            except Exception:
                return self._send_response(400, json.dumps({'error': 'Invalid JSON'}))
            allowed = {'username', 'nickname', 'email', 'is_admin', 'quota_bytes', 'quota_override'}
            updates = {k: v for k, v in data.items() if k in allowed}
            if not updates:
                return self._send_response(400, json.dumps({'error': 'Nothing to update'}))
            parts = ', '.join(f'{k} = ?' for k in updates)
            vals  = list(updates.values()) + [target_id]
            with _db_connect() as conn:
                conn.execute(f'UPDATE users SET {parts} WHERE id = ?', vals)
                conn.commit()
            return self._send_response(200, json.dumps({'message': 'Updated'}))

        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))

    def do_DELETE(self):
        """Routes DELETE requests (used to revoke shares and cancel upload sessions)."""
        if self._redirect_to_https_if_needed():   # ← P2
            return

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
        _admin_user_del = re.match(r'^/api/v1/admin/users/(\d+)$', parsed_url.path)
        if _admin_user_del:
            admin = self._check_admin_auth()
            if not admin: return
            target_id = int(_admin_user_del.group(1))
            if target_id == admin['id']:
                return self._send_response(400, json.dumps({'error': 'Cannot delete your own account'}))
            # Note: user files on disk are NOT deleted here intentionally.
            # Manual cleanup via filesystem if needed: SERVE_ROOT/FluxDrop/<user_id>/
            with _db_connect() as conn:
                conn.execute('DELETE FROM sessions WHERE user_id = ?', (target_id,))
                conn.execute('DELETE FROM users WHERE id = ?', (target_id,))
                conn.commit()
            return self._send_response(200, json.dumps({'message': 'User deleted'}))
        # Trash bin: permanently delete one item or empty entire trash
        _tr_item = self.trash_item_pattern.match(parsed_url.path)
        if _tr_item:
            return self._handle_trash_delete(int(_tr_item.group(2)))
        if self.trash_list_pattern.match(parsed_url.path):
            return self._handle_trash_empty()

        _notif_del = re.match(r'^/api/v1/notifications/(\\d+)$', parsed_url.path)
        if _notif_del:
            return self._handle_notifications_delete(int(_notif_del.group(1)))

        # Avatar remove: DELETE /api/v1/me/avatar
        if parsed_url.path == '/api/v1/me/avatar':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Authentication required'}))
            with _db_connect() as conn:
                conn.execute(
                    'UPDATE users SET avatar_data = NULL, avatar_mime = NULL WHERE id = ?',
                    (user_id,)
                )
                conn.commit()
            return self._send_response(200, json.dumps({'ok': True}))

        return self._send_response(404, json.dumps({"error": "Endpoint not found"}))


    # ── Policy acceptance API ─────────────────────────────────────────────────

    def _handle_policy_status(self):
        versions = _get_policy_versions()
        current_tos = versions['tos']
        current_pp  = versions['pp']
        logging.info(f'[policy/status] current_tos={current_tos!r} current_pp={current_pp!r}')

        user_id = self._check_token_auth()
        logging.info(f'[policy/status] user_id={user_id!r}')
        accepted_tos = accepted_pp = None
        if user_id:
            try:
                with _db_connect() as conn:
                    r = conn.execute(
                        "SELECT policy_type, version FROM policy_acceptances "
                        "WHERE user_id = ? AND policy_type IN ('tos','pp') "
                        "ORDER BY accepted_at DESC",
                        (user_id,)
                    ).fetchall()
                logging.info(f'[policy/status] raw DB rows: {r}')
                by_type = {}
                for row in r:
                    by_type.setdefault(row[0], row[1])
                logging.info(f'[policy/status] by_type: {by_type}')
                accepted_tos = by_type.get('tos')
                accepted_pp  = by_type.get('pp')
            except Exception:
                logging.exception('_handle_policy_status: DB error')
        else:
            logging.warning('[policy/status] no authenticated user — token missing or invalid')

        needs_tos = accepted_tos != current_tos
        needs_pp  = accepted_pp  != current_pp
        logging.info(
            f'[policy/status] accepted_tos={accepted_tos!r} vs current={current_tos!r} → needs_tos={needs_tos} | '
            f'accepted_pp={accepted_pp!r} vs current={current_pp!r} → needs_pp={needs_pp}'
        )

        body = json.dumps({
            'current_tos':  current_tos,
            'current_pp':   current_pp,
            'accepted_tos': accepted_tos,
            'accepted_pp':  accepted_pp,
            'needs_tos':    needs_tos,
            'needs_pp':     needs_pp,
            # False when the bearer token was missing or invalid.  The client
            # uses this to distinguish "genuinely needs to accept policy" from
            # "session expired — redirect to login", without relying on
            # needs_tos/needs_pp which are meaningless for unauthenticated requests.
            'token_valid':  user_id is not None,
        })
        # Must not be cached — stale policy status silently bypasses version checks.
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body.encode('utf-8'))))
            self.send_header('Cache-Control', 'no-store')
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _handle_policy_accept(self):
        """POST /api/v1/policy/accept
        Body JSON: { "tos": "0.0.0", "pp": "0.0.0" }
        At least one key must be present.  Versions must match the current
        required versions (the client can't pre-accept future versions).
        Requires authentication.
        """
        versions = _get_policy_versions()

        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Authentication required.'}), 'application/json')

        content_len = int(self.headers.get('Content-Length', 0))
        if content_len <= 0 or content_len > 512:
            return self._send_response(400, json.dumps({'error': 'Invalid body.'}), 'application/json')
        try:
            data = json.loads(self.rfile.read(content_len))
        except Exception:
            return self._send_response(400, json.dumps({'error': 'Invalid JSON.'}), 'application/json')

        to_record = []
        if 'tos' in data:
            if data['tos'] != versions['tos']:
                return self._send_response(400, json.dumps({
                    'error': f"TOS version mismatch: expected {versions['tos']}, got {data['tos']}"
                }), 'application/json')
            to_record.append(('tos', versions['tos']))
        if 'pp' in data:
            if data['pp'] != versions['pp']:
                return self._send_response(400, json.dumps({
                    'error': f"PP version mismatch: expected {versions['pp']}, got {data['pp']}"
                }), 'application/json')
            to_record.append(('pp', versions['pp']))

        if not to_record:
            return self._send_response(400, json.dumps({'error': 'Nothing to record.'}), 'application/json')

        now = time.time()
        try:
            with _db_connect() as conn:
                for ptype, ver in to_record:
                    conn.execute(
                        'INSERT OR REPLACE INTO policy_acceptances '
                        '(user_id, policy_type, version, accepted_at) VALUES (?,?,?,?)',
                        (user_id, ptype, ver, now)
                    )
                conn.commit()
        except Exception:
            logging.exception('_handle_policy_accept: DB error')
            return self._send_response(500, json.dumps({'error': 'Internal server error.'}), 'application/json')

        logging.info(f"Policy acceptance recorded: user_id={user_id} {to_record}")
        return self._send_response(200, json.dumps({'ok': True}), 'application/json')


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
        _MAX_PASSWORD = 1024  # bcrypt only uses first 72 bytes, but with new pre-hash it's now well above that; cap are not needed but wanted
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
        username = data.get('username', '')
        password = data.get('password', '')
        if not username or not password:
            return self._send_response(400, json.dumps({'error': 'Username and password required.'}))

        # P5: Mirror the registration caps to prevent bcrypt DoS on the login path
        _MAX_USERNAME_LOGIN = 64
        _MAX_PASSWORD_LOGIN = 1024
        if len(username) > _MAX_USERNAME_LOGIN or len(password) > _MAX_PASSWORD_LOGIN:
            # Return 401, not 400 — avoids leaking that the *length* was the problem
            return self._send_response(401, json.dumps({'error': 'Invalid credentials.'}))

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
                if not bcrypt.checkpw(_prepare_password(password), stored_hash.encode('utf-8')):  # ← P6
                    # Legacy check — user has a pre-P6 hash
                    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                        # Upgrade their hash transparently
                        new_hash = bcrypt.hashpw(_prepare_password(password), bcrypt.gensalt(rounds=12))
                        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash.decode(), user_id))
                        conn.commit()
                        # login proceeds normally
                    else:
                        return self._send_response(401, json.dumps({'error': 'Invalid credentials.'}))
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
            _token_hash   = _hash_session_token(session_token)   # ← P1
            expires_at = datetime.now() + timedelta(days=7) # Session expires in 7 days
            cursor.execute(
                "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
                (user_id, _token_hash, expires_at)               # ← store hash
            )
            conn.commit()
            conn.execute("DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP")
            conn.commit()

        with _db_connect() as conn:
            _adm = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
        _is_admin = bool(_adm[0]) if _adm else False
        return self._send_response(200, json.dumps({
            "message": "Login successful.", "token": session_token,
            "username": username, "is_admin": _is_admin
        }))

    def handle_auth_logout(self):
        """Handles user logout by deleting the session token."""
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return self._send_response(400, json.dumps({"error": "No token provided."}))

        token = auth_header.split(' ', 1)[1]
        with _db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_token = ?",
               (_hash_session_token(token),))    # ← P1
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
                try:
                    with open(target_fs, "rb") as f:
                        f.seek(start)
                        remaining = length
                        while remaining > 0:
                            chunk = f.read(min(65536, remaining))
                            if not chunk: break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError) as _disc:
                    logging.debug('Share download: client disconnected (%s)', _disc)
            else:
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", content_type)
                if disposition:
                    self.send_header("Content-Disposition", disposition)
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(file_size))
                self.end_headers()
                try:
                    with open(target_fs, "rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk: break
                            self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError) as _disc:
                    logging.debug('Share download: client disconnected (%s)', _disc)
            return

        # --- Directory listing page ---
        if os.path.isdir(target_fs):
            if share["track_stats"]:
                _log_share_access(token, visitor_user_id, action="view")

            qs = parse_qs(parsed_url.query)

            # ?foldersize=1 — return JSON total size of the shared (sub-)folder
            if qs.get('foldersize', ['0'])[0] == '1':
                total = 0
                try:
                    for dirpath, _dirs, files in os.walk(target_fs):
                        for fn in files:
                            try: total += os.path.getsize(os.path.join(dirpath, fn))
                            except OSError: pass
                except Exception: pass
                return self._send_response(200, json.dumps({'size': total}))

            # ?zip=1 — stream the shared folder as a ZIP archive
            if qs.get('zip', ['0'])[0] == '1':
                # Re-use the authenticated ZIP handler but temporarily satisfy its
                # auth check by delegating directly to _handle_zip_fs which takes
                # an already-resolved filesystem path.
                return self._handle_zip_share(target_fs, os.path.basename(target_fs.rstrip('/')) or 'download')

            return self._send_response(200, self._render_share_page(share, token, target_fs, base_fs, sub_path or ""), "text/html")

        return self._send_response(404, "<h1>404 — Not Found</h1>", "text/html")
        # This message by no means should came up with the FluxDrop interaction as-is, so if it will - that's the sign of an error

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
        # Extract the raw visitor token so we can append it to all generated
        # links/URLs.  This propagates auth through plain <a href> navigation.
        # We look in the same places _check_token_auth() does.
        _raw_auth = self.headers.get('Authorization', '')
        _visitor_token_raw = None
        if _raw_auth.startswith('Bearer '):
            _visitor_token_raw = _raw_auth.split(' ', 1)[1].strip()
        else:
            _visitor_token_raw = parse_qs(urlparse(self.path).query).get('token', [None])[0]
        # Build the query-string suffix to append to every share URL
        _tok_qs = ('?token=' + quote(_visitor_token_raw, safe='')) if _visitor_token_raw else ''
        # Helper: append token to a URL that may already have a query string
        def _turl(url):
            if not _visitor_token_raw:
                return url
            sep = '&' if '?' in url else '?'
            return url + sep + 'token=' + quote(_visitor_token_raw, safe='')

        # --- Breadcrumb ---
        crumb_parts = sub_path_clean.split("/") if sub_path_clean else []
        crumbs_html = f'<a href="{_turl(f"/share/{token}")}" style="color:#3b82f6;text-decoration:none">Home</a>'
        for i, part in enumerate(crumb_parts):
            crumb_url = _turl("/share/" + token + "/" + "/".join(quote(seg, safe="") for seg in crumb_parts[:i+1]))
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
                entry_url_base = "/share/" + token + "/" + "/".join(quote(seg, safe="") for seg in rel_from_base.split("/"))
                entry_url  = _turl(entry_url_base)
                st = os.stat(entry_fs)
                mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                pad = indent * 20
                if os.path.isdir(entry_fs):
                    zip_url  = _turl(entry_url_base + "?zip=1")
                    size_url = _turl(entry_url_base + "?foldersize=1")
                    rows += f"""<tr class="entry-row">
                        <td style="padding:8px 12px 8px {12+pad}px">
                            <a href="{entry_url}" style="color:#3b82f6;text-decoration:none;font-weight:500">📁 {name}</a>
                        </td>
                        <td style="padding:8px 12px;color:#94a3b8" id="fsz-{rel_from_base.replace('/','_')}">
                            <span style="font-size:11px;color:#cbd5e1;cursor:pointer" onclick="loadShareFolderSize(this,{repr(size_url)})">— (load)</span>
                        </td>
                        <td style="padding:8px 12px;color:#94a3b8">{mtime}</td>
                        <td style="padding:8px 12px">
                            <button onclick="startShareZip({repr(zip_url)})"
                               style="background:#0ea5e9;color:white;border:none;padding:3px 10px;border-radius:5px;font-size:12px;cursor:pointer">⬇ ZIP</button>
                        </td>
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
            parent_url = _turl(("/share/" + token + "/" + "/".join(quote(seg, safe="") for seg in crumb_parts[:-1])).rstrip("/") if crumb_parts else f"/share/{token}")
            back_row = f'<tr><td colspan="4" style="padding:6px 12px"><a href="{parent_url}" style="color:#64748b;text-decoration:none;font-size:13px">⬆ Parent folder</a></td></tr>'
            entries_html = back_row + entries_html
        else:
            entries_html = build_rows(base_fs, indent=0)

        if not entries_html:
            entries_html = '<tr><td colspan="4" style="padding:16px;color:#94a3b8;text-align:center">This folder is empty</td></tr>'

        # --- Upload section ---
        upload_section = ""
        encoded_subpath = quote(sub_path_clean, safe='/')
        tok_param_upload = ('&token=' + quote(_visitor_token_raw, safe='')) if _visitor_token_raw else ''

        if share["allow_anon_upload"]:
            # Anyone can upload — show the upload UI directly
            _upload_section_visible = True
            _upload_auth_required   = False
        elif share["allow_auth_upload"]:
            # Always render the section — but wrap it in a JS auth gate that
            # reads localStorage first, so visitors who are already logged in
            # on this device see the upload UI without a round-trip to the server.
            _upload_section_visible = True   # render always; JS gates it
            _upload_auth_required   = not bool(visitor_user_id)
        else:
            _upload_section_visible = False
            _upload_auth_required   = False

        if _upload_section_visible:
            # Pre-compute all conditional HTML fragments as plain Python strings
            # BEFORE the f-string.  Nesting f-strings with different quote delimiters
            # (f'''...''' inside f"""...""") produces literal rendering artifacts:
            # the closing '' marker and expression braces appear as visible text.
            _ui_hidden    = ' style="display:none"' if _upload_auth_required else ''
            _auth_js_bool = 'true' if _upload_auth_required else 'false'
            _init_token   = json.dumps(_visitor_token_raw or '')
            _subpath_js   = json.dumps(sub_path_clean)

            if _upload_auth_required:
                _auth_gate_html = (
                    '\n                <!-- Auth gate: hidden once JS resolves a valid token -->'
                    '\n                <div id="upload-auth-gate" style="text-align:center;padding:8px 0">'
                    '\n                    <p style="font-size:13px;color:#64748b;margin:0 0 10px">'
                    '\n                        A FluxDrop account is required to upload here.'
                    '\n                    </p>'
                    '\n                    <div id="upload-auth-form">'
                    '\n                        <input type="text" id="upload-usr" placeholder="Username"'
                    '\n                               style="width:100%;max-width:280px;padding:8px 12px;'
                    'border:1px solid #e2e8f0;border-radius:8px;font-size:13px;'
                    'margin-bottom:6px;display:block;margin:0 auto 6px">'
                    '\n                        <input type="password" id="upload-pwd" placeholder="Password"'
                    '\n                               style="width:100%;max-width:280px;padding:8px 12px;'
                    'border:1px solid #e2e8f0;border-radius:8px;font-size:13px;'
                    'margin-bottom:6px;display:block;margin:0 auto 6px">'
                    '\n                        <button onclick="doUploadLogin()"'
                    '\n                                style="background:#3b82f6;color:white;border:none;'
                    'border-radius:8px;padding:8px 20px;font-size:13px;cursor:pointer">'
                    '\n                            Login &amp; unlock upload'
                    '\n                        </button>'
                    '\n                        <div id="upload-auth-err" style="color:#ef4444;font-size:12px;margin-top:6px"></div>'
                    '\n                    </div>'
                    '\n                </div>'
                )
            else:
                _auth_gate_html = ''

            upload_section = f"""
            <div id="upload-section" style="margin-top:24px;padding:16px;background:#f0fdf4;border:1px solid #86efac;border-radius:10px">
                {_auth_gate_html}
                <div id="upload-ui"{_ui_hidden}>
                    <h3 style="margin:0 0 10px;font-size:15px;color:#166534">Upload files to this folder</h3>
                    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                        <input type="file" id="upload-file" multiple style="font-size:14px">
                        <button onclick="uploadFiles()"
                            style="background:#16a34a;color:white;border:none;border-radius:8px;
                                   padding:8px 18px;cursor:pointer;font-size:14px;flex-shrink:0">
                            Upload
                        </button>
                        <button onclick="promptMkdir()"
                            style="background:#0ea5e9;color:white;border:none;border-radius:8px;
                                   padding:8px 18px;cursor:pointer;font-size:14px;flex-shrink:0">
                            📁 New Folder
                        </button>
                        <span id="upload-status" style="font-size:13px;color:#166534"></span>
                    </div>
                    <div id="upload-progress" style="margin-top:8px"></div>
                </div>

                <script>
                const _CDN_ORIGIN    = 'https://{PUBLIC_DOMAIN}';
                const _AUTH_REQUIRED = {_auth_js_bool};
                let   _uploadToken   = {_init_token};

                (function tryLocalStorage() {{
                    if (!_AUTH_REQUIRED) return;
                    const stored = localStorage.getItem('fluxdrop_token');
                    if (stored) _unlockUpload(stored);
                }})();

                function _unlockUpload(token) {{
                    _uploadToken = token;
                    const gate = document.getElementById('upload-auth-gate');
                    const ui   = document.getElementById('upload-ui');
                    if (gate) gate.style.display = 'none';
                    if (ui)   ui.style.display   = '';
                }}

                async function doUploadLogin() {{
                    const usr = document.getElementById('upload-usr').value.trim();
                    const pwd = document.getElementById('upload-pwd').value;
                    const err = document.getElementById('upload-auth-err');
                    if (!usr || !pwd) {{ err.textContent = 'Please enter username and password.'; return; }}
                    err.textContent = 'Logging in…';
                    try {{
                        const r = await fetch(_CDN_ORIGIN + '/auth/login', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{username: usr, password: pwd}})
                        }});
                        const d = await r.json();
                        if (!r.ok) {{ err.textContent = d.error || 'Login failed.'; return; }}
                        localStorage.setItem('fluxdrop_token', d.token);
                        localStorage.setItem('fluxdrop_username', d.username);
                        err.textContent = '';
                        _unlockUpload(d.token);
                    }} catch(e) {{ err.textContent = 'Network error: ' + e.message; }}
                }}

                function _uploadUrl() {{
                    const base = '/share/{token}/upload?subpath={encoded_subpath}';
                    return _uploadToken ? base + '&token=' + encodeURIComponent(_uploadToken) : base;
                }}

                async function uploadFiles() {{
                    const files = document.getElementById('upload-file').files;
                    if (!files.length) {{ document.getElementById('upload-status').textContent = 'No files selected'; return; }}
                    const statusEl   = document.getElementById('upload-status');
                    const progressEl = document.getElementById('upload-progress');
                    statusEl.textContent = `Uploading ${{files.length}} file(s)…`;
                    let done = 0, failed = 0;
                    for (const f of files) {{
                        const fd = new FormData();
                        fd.append('file', f, f.name);
                        progressEl.textContent = `[${{done + failed + 1}}/${{files.length}}] ${{f.name}}…`;
                        try {{
                            const r = await fetch(_uploadUrl(), {{method: 'POST', body: fd}});
                            if (r.ok) done++;
                            else {{
                                failed++;
                                if (r.status === 403 && _AUTH_REQUIRED) {{
                                    _uploadToken = '';
                                    localStorage.removeItem('fluxdrop_token');
                                    const gate = document.getElementById('upload-auth-gate');
                                    const ui   = document.getElementById('upload-ui');
                                    if (gate) gate.style.display = '';
                                    if (ui)   ui.style.display   = 'none';
                                    document.getElementById('upload-auth-err').textContent =
                                        'Session expired — please log in again.';
                                    break;
                                }}
                            }}
                        }} catch(e) {{ failed++; }}
                    }}
                    statusEl.textContent = `Done: ${{done}} uploaded${{failed ? ', ' + failed + ' failed' : ''}}`;
                    progressEl.textContent = '';
                    if (done > 0) setTimeout(() => location.reload(), 1200);
                }}

                async function promptMkdir() {{
                    const name = prompt('New folder name:');
                    if (!name || !name.trim()) return;
                    const curSubpath = {_subpath_js};
                    const subpath = curSubpath ? curSubpath + '/' + name.trim() : name.trim();
                    try {{
                        const r = await fetch('/share/{token}/mkdir?token=' +
                            encodeURIComponent(_uploadToken || ''), {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{subpath}})
                        }});
                        if (r.ok) location.reload();
                        else {{ const t = await r.text(); alert('Failed: ' + t); }}
                    }} catch(e) {{ alert('Error: ' + e); }}
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

        # Current-folder ZIP and size URLs (for the page header download button)
        current_zip_url  = _turl(f"/share/{token}" + (f"/{sub_path_clean}" if sub_path_clean else "") + "?zip=1")
        current_size_url = _turl(f"/share/{token}" + (f"/{sub_path_clean}" if sub_path_clean else "") + "?foldersize=1")

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
            current_zip_url=current_zip_url,
            current_size_url=current_size_url,
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

    def _handle_zip_share(self, base_fs: str, folder_name: str):
        """Build a ZIP session for base_fs (already validated by caller) and
        return the JSON metadata so the client can stream/resume via zip_stream."""
        self._zip_share_override = base_fs
        try:
            return self._handle_zip_meta('/__share_override__')
        finally:
            self._zip_share_override = None

    # --- Folder ZIP download (streaming, ZIP_STORED) ---

    # ── Trash bin API handlers ────────────────────────────────────────────────

    def _handle_trash_list(self):
        """GET /api/v1/trash — list the authenticated user's trash items."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        items = _trash_list(user_id)
        retention = _trash_retention_days()
        notice = None
        if retention == 7:
            notice = ('Due to server capacity demand, new items are kept for 7 days. '
                      'Retention will return to 30 days once space is freed.')
            # bad hardcode, needs complex fix I think because l10n key does nothing
        return self._send_response(200, json.dumps({
            'items': items,
            'retention_days': retention,
            'notice': notice,
        }))

    def _handle_trash_file_stream(self, item_id: int):
        """GET /api/v1/trash/<id>/file  — stream a trashed file for preview.
        Uses session-token auth (same as all other authenticated endpoints).
        Only the owning user can access their own trash items.
        """
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        try:
            with _db_connect() as conn:
                conn.row_factory = sqlite3.Row   # dict-style access for this query only
                row = conn.execute(
                    'SELECT trash_path, is_dir, size_bytes FROM trash_items'
                    ' WHERE id = ? AND user_id = ?',
                    (item_id, user_id)
                ).fetchone()
        except Exception as exc:
            return self._send_response(500, json.dumps({'error': str(exc)}))
        if not row:
            return self._send_response(404, json.dumps({'error': 'Trash item not found'}))
        if row['is_dir']:
            return self._send_response(400, json.dumps({'error': 'Cannot stream a directory'}))
        trash_path = row['trash_path']
        if not os.path.isfile(trash_path):
            return self._send_response(404, json.dumps({'error': 'Trashed file missing from disk'}))

        filename  = os.path.basename(trash_path).split('__')[0]  # strip __<uid> suffix
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or 'application/octet-stream'
        file_size = os.path.getsize(trash_path)

        bufsize      = 4 * 1024 * 1024   # 4 MiB read buffer
        disposition  = self._content_disposition(filename).replace('attachment;', 'inline;', 1)
        range_header = self.headers.get('Range')

        if range_header:
            m = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if m:
                start = int(m.group(1))
                end   = int(m.group(2)) if m.group(2) else file_size - 1
            else:
                start, end = 0, file_size - 1
            start  = max(0, min(start, file_size - 1))
            end    = max(start, min(end,   file_size - 1))
            length = end - start + 1
            self.send_response(206)
            self._send_cors_headers()
            self.send_header('Content-Type',        mime_type)
            # Use RFC 5987 encoding for non-ASCII names (Cyrillic, CJK, etc.)
            self.send_header('Content-Disposition',
                            self._content_disposition(filename).replace('attachment;', 'inline;', 1))
            self.send_header('Accept-Ranges',       'bytes')
            self.send_header('Content-Range',       f'bytes {start}-{end}/{file_size}')
            self.send_header('Content-Length',      str(length))
            self.send_header('Cache-Control',       'no-store')
            self.end_headers()
            try:
                with open(trash_path, 'rb') as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(bufsize, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_response(200)
            self._send_cors_headers()
            self.send_header('Content-Type',        mime_type)
            self.send_header('Content-Disposition', disposition)
            self.send_header('Accept-Ranges',       'bytes')
            self.send_header('Content-Length',      str(file_size))
            self.send_header('Cache-Control',       'no-store')
            self.end_headers()
            try:
                with open(trash_path, 'rb') as f:
                    while True:
                        chunk = f.read(bufsize)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _handle_trash_folder_list(self, item_id: int):
        """GET /api/v1/trash/<id>/list — return the file tree of a trashed folder.

        Response JSON:
          { "items": [{"name","path","is_dir","size_bytes","depth"}, …],
            "total_bytes": N, "count": N, "truncated": false }
        """
        MAX_WALK_ITEMS = 2000
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        try:
            with _db_connect() as conn:
                row = conn.execute(
                    'SELECT trash_path, is_dir FROM trash_items WHERE id = ? AND user_id = ?',
                    (item_id, user_id)
                ).fetchone()
        except Exception as exc:
            return self._send_response(500, json.dumps({'error': str(exc)}))
        if not row:
            return self._send_response(404, json.dumps({'error': 'Trash item not found'}))
        trash_path, is_dir = row
        if not is_dir:
            return self._send_response(400, json.dumps({'error': 'Item is a file, not a folder'}))
        if not os.path.isdir(trash_path):
            return self._send_response(404, json.dumps({'error': 'Trashed folder missing from disk'}))

        items = []
        total_bytes = 0
        root = trash_path
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = os.path.relpath(dirpath, root)
                depth   = 0 if rel_dir == '.' else rel_dir.count(os.sep) + 1
                for dname in sorted(dirnames):
                    sub_rel = (os.path.join(rel_dir, dname).replace(os.sep, '/')
                               if rel_dir != '.' else dname)
                    items.append({'name': dname, 'path': sub_rel,
                                  'is_dir': True, 'size_bytes': 0, 'depth': depth + 1})
                    if len(items) >= MAX_WALK_ITEMS: break
                for fname in sorted(filenames):
                    fpath = os.path.join(dirpath, fname)
                    try:   sz = os.path.getsize(fpath)
                    except OSError: sz = 0
                    total_bytes += sz
                    rel_file = (os.path.join(rel_dir, fname).replace(os.sep, '/')
                                if rel_dir != '.' else fname)
                    items.append({'name': fname, 'path': rel_file,
                                  'is_dir': False, 'size_bytes': sz, 'depth': depth + 1})
                    if len(items) >= MAX_WALK_ITEMS: break
                if len(items) >= MAX_WALK_ITEMS: break
        except Exception as exc:
            logging.exception('_handle_trash_folder_list walk failed')
            return self._send_response(500, json.dumps({'error': str(exc)}))

        self._send_response(200, json.dumps({
            'items': items, 'total_bytes': total_bytes,
            'count': len(items), 'truncated': len(items) >= MAX_WALK_ITEMS,
        }))

    def _handle_space_analyze(self, parsed_url):
        """GET /api/v1/space_analyze[?path=/sub&limit=N&min_bytes=B]

        Walk the authenticated user's FluxDrop directory.
        If `path` is given (e.g. path=/Documents), list direct children of that
        sub-directory (one level deep) so the UI can navigate folder-by-folder.
        Omits the .trash sub-directory from results.

        Response JSON:
          { "items": [{name, path, is_dir, size_bytes}, …],
            "total_bytes": N, "scanned": N, "truncated": false }
        """
        MAX_HARD = 500

        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))

        qs = parse_qs(parsed_url.query)
        try:
            limit     = min(int(qs.get('limit',     ['200'])[0]), MAX_HARD)
            min_bytes = int(qs.get('min_bytes', ['0'])[0])
        except (ValueError, TypeError):
            limit, min_bytes = 200, 0

        # Requested sub-path (relative to user root, default = root)
        req_sub = qs.get('path', ['/'])[0].strip('/')

        user_root = os.path.normpath(
            os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id))
        )
        scan_root = os.path.normpath(
            os.path.join(user_root, req_sub) if req_sub else user_root
        )

        # Security: scan_root must be inside user_root
        if not os.path.realpath(scan_root).startswith(os.path.realpath(user_root)):
            return self._send_response(403, json.dumps({'error': 'Forbidden'}))
        if not os.path.isdir(scan_root):
            return self._send_response(404, json.dumps({'error': 'Path not found'}))

        def _dir_size(dpath):
            s = 0
            try:
                for dp, _, fns in os.walk(dpath):
                    for fn in fns:
                        try: s += os.path.getsize(os.path.join(dp, fn))
                        except OSError: pass
            except OSError: pass
            return s

        all_items   = []
        total_bytes = 0
        scanned     = 0

        try:
            for entry_name in sorted(os.listdir(scan_root)):
                if entry_name == '.trash':
                    continue
                entry_path = os.path.join(scan_root, entry_name)
                is_dir     = os.path.isdir(entry_path)
                sz         = _dir_size(entry_path) if is_dir else (
                    os.path.getsize(entry_path) if os.path.isfile(entry_path) else 0
                )
                total_bytes += sz
                scanned     += 1
                # Path relative to user root (leading slash)
                rel = '/' + os.path.relpath(entry_path, user_root).replace(os.sep, '/')
                if sz >= min_bytes:
                    all_items.append({
                        'name': entry_name, 'path': rel,
                        'is_dir': is_dir,   'size_bytes': sz,
                    })
        except Exception as exc:
            logging.exception('_handle_space_analyze failed')
            return self._send_response(500, json.dumps({'error': str(exc)}))

        all_items.sort(key=lambda x: x['size_bytes'], reverse=True)
        truncated = len(all_items) > limit
        self._send_response(200, json.dumps({
            'items':       all_items[:limit],
            'total_bytes': total_bytes,
            'scanned':     scanned,
            'truncated':   truncated,
        }))

    def _handle_trash_move(self):
        """POST /api/v1/trash  {path}  — soft-delete a file/folder into the trash."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        try:
            length = int(self.headers.get('Content-Length', 0))
            data   = json.loads(self.rfile.read(length) if length else b'{}')
        except Exception:
            return self._send_response(400, json.dumps({'error': 'Invalid JSON'}))
        path = data.get('path', '')
        if not isinstance(path, str) or not path.strip():
            return self._send_response(400, json.dumps({'error': 'path required'}))
        # Do NOT strip() the whole path — folder names may intentionally end
        # with spaces (e.g. "my folder ").  Only strip surrounding slashes so
        # the join below works correctly; leading slash is re-added if needed.
        path = path.strip('/')
        path = '/' + path   # restore leading slash for the rest of the handler
        # Resolve to filesystem path (user-relative)
        user_root = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
        if path.startswith('/FluxDrop/'):
            parts = path.lstrip('/').split('/', 2)
            if len(parts) < 2 or parts[1] != str(user_id):
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))
            sub = parts[2] if len(parts) > 2 else ''
            fs_path  = os.path.join(user_root, sub)   # no normpath: preserve trailing spaces
            orig_rel = '/' + sub if sub else '/'
        else:
            fs_path  = os.path.join(user_root, path.lstrip('/'))  # no normpath: preserve trailing spaces
            orig_rel = '/' + path.lstrip('/')
        # Security: resolve symlinks on the *parent* directory only, not the
        # leaf, so that a trailing-space name is not mangled by realpath.
        fs_parent   = os.path.realpath(os.path.dirname(fs_path))
        root_real   = os.path.realpath(user_root)
        if not fs_parent.startswith(root_real):
            return self._send_response(403, json.dumps({'error': 'Forbidden'}))
        if not os.path.exists(fs_path):
            return self._send_response(404, json.dumps({'error': 'Path not found'}))
        try:
            row = _move_to_trash(user_id, fs_path, orig_rel)
            with _db_connect() as conn:
                conn.execute(
                    'INSERT INTO trash_items (user_id, original_path, trash_path,'
                    ' deleted_at, size_bytes, is_dir, retention_days)'
                    ' VALUES (?,?,?,?,?,?,?)',
                    (row['user_id'], row['original_path'], row['trash_path'],
                     row['deleted_at'], row['size_bytes'], row['is_dir'],
                     row['retention_days'])
                )
                conn.commit()
            return self._send_response(200, json.dumps({
                'message': 'Moved to trash',
                'retention_days': row['retention_days'],
            }))
        except Exception as e:
            logging.exception('_handle_trash_move failed')
            return self._send_response(500, json.dumps({'error': str(e)}))

    def _handle_trash_restore(self, item_id: int):
        """POST /api/v1/trash/<id>/restore — restore a trash item to its original path."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        try:
            orig = _trash_restore(user_id, item_id)
            return self._send_response(200, json.dumps({'message': 'Restored', 'path': orig}))
        except RuntimeError as e:
            return self._send_response(409, json.dumps({'error': str(e)}))
        except Exception as e:
            logging.exception('_handle_trash_restore failed')
            return self._send_response(500, json.dumps({'error': str(e)}))

    def _handle_trash_delete(self, item_id: int):
        """DELETE /api/v1/trash/<id> — permanently delete one trash item."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        try:
            _trash_delete_permanent(user_id, item_id)
            return self._send_response(200, json.dumps({'message': 'Permanently deleted'}))
        except RuntimeError as e:
            return self._send_response(404, json.dumps({'error': str(e)}))
        except Exception as e:
            logging.exception('_handle_trash_delete failed')
            return self._send_response(500, json.dumps({'error': str(e)}))

    def _handle_trash_empty(self):
        """DELETE /api/v1/trash — permanently delete ALL trash items for the user."""
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
        try:
            items = _trash_list(user_id)
            for item in items:
                try:
                    _trash_delete_permanent(user_id, item['id'])
                except Exception:
                    pass
            return self._send_response(200, json.dumps({'message': f'Emptied {len(items)} item(s)'}))
        except Exception as e:
            logging.exception('_handle_trash_empty failed')
            return self._send_response(500, json.dumps({'error': str(e)}))


    def _handle_zip(self, path_segment: str):
        import zipfile as _zf
        import struct  as _st
        import zlib    as _zl

        # Share path override: _handle_zip_share already resolved and validated
        # the filesystem path — skip auth and path resolution entirely.
        share_override = getattr(self, '_zip_share_override', None)
        if share_override is not None:
            base_fs = share_override
            user_id = 'share'   # for the log line only
        else:
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Unauthorized'}))

            relative_path = unquote(path_segment)
            user_root = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))

            if relative_path.startswith('/cdn'):
                cdn_rel = relative_path[len('/cdn'):]
                base_fs = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
                if not os.path.realpath(base_fs).startswith(os.path.realpath(CDN_UPLOAD_DIR)):
                    return self._send_response(400, json.dumps({'error': 'Invalid path.'}))
            else:
                base_fs = os.path.normpath(os.path.join(user_root, relative_path.lstrip('/')))
                if not os.path.realpath(base_fs).startswith(user_root):
                    return self._send_response(403, json.dumps({'error': 'Forbidden'}))

        if not os.path.isdir(base_fs):
            return self._send_response(404, json.dumps({'error': 'Not a directory.'}))

        # ── ZIP constants ────────────────────────────────────────────────────────
        LFH_SIG  = b'PK\x03\x04'
        DD_SIG   = b'PK\x07\x08'
        CDH_SIG  = b'PK\x01\x02'
        EOCD_SIG = b'PK\x05\x06'
        # ZIP64 signatures
        ZIP64_EOCD_SIG    = b'PK\x06\x06'
        ZIP64_EOCD_LOCATOR = b'PK\x06\x07'

        FLAG_DD       = 0x0008
        METHOD_STORED = 0
        UINT32_MAX    = 0xFFFF_FFFF
        UINT16_MAX    = 0xFFFF

        # ── Pre-walk ─────────────────────────────────────────────────────────────
        files_info = []   # (abs_path, arcname, arcname_bytes, file_size, dos_time, dos_date)
        missing_files = []  # arcnames that were found in os.walk but unreadable at stat time
        for dirpath, _dirs, filenames in os.walk(base_fs):
            for fname in sorted(filenames):
                if fname in ('.placeholder', '.create_marker'):
                    continue
                abs_path = os.path.join(dirpath, fname)
                arcname  = os.path.relpath(abs_path, base_fs).replace(os.sep, '/')
                arcname_bytes = arcname.encode('utf-8')
                try:
                    st       = os.stat(abs_path)
                    fsz      = st.st_size
                    import time as _time
                    lt       = _time.localtime(st.st_mtime)
                    dos_time = (lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec >> 1)
                    dos_date = ((lt.tm_year - 1980) << 9) | (lt.tm_mon << 5) | lt.tm_mday
                except OSError:
                    missing_files.append(arcname)
                    continue
                files_info.append((abs_path, arcname, arcname_bytes, fsz, dos_time, dos_date))

        # ── Compute Content-Length ───────────────────────────────────────────────
        # Each local file entry:
        #   30 + len(fn)                local file header (no zip64 extra — sizes in descriptor)
        #   + 20                        ZIP64 extra field in LFH  (tag+size+compressed+uncompressed)
        #   + file_size                 data
        #   + 24                        data descriptor with ZIP64 sizes (sig+crc+comp64+uncomp64)
        # CDH entry:
        #   46 + len(fn) + zip64_extra  (zip64 extra = 28 bytes always for simplicity)
        # EOCD64: 56 + ZIP64 EOCD locator: 20 + EOCD32: 22

        Z64_LFH_EXTRA  = 20   # tag(2)+size(2)+comp(8)+uncomp(8)
        Z64_DD_SIZE    = 24   # sig(4)+crc(4)+comp(8)+uncomp(8)
        Z64_CDH_EXTRA  = 28   # tag(2)+size(2)+uncomp(8)+comp(8)+lhoffset(8)
        EOCD64_SIZE    = 56 + 20 + 22   # zip64 eocd + locator + classic eocd

        total_cl = 0
        for _, _, arcname_bytes, fsz, _, _ in files_info:
            fn = len(arcname_bytes)
            total_cl += 30 + fn + Z64_LFH_EXTRA + fsz + Z64_DD_SIZE
        cd_size = sum(46 + len(fi[2]) + Z64_CDH_EXTRA for fi in files_info)
        total_cl += cd_size + EOCD64_SIZE

        folder_name  = os.path.basename(base_fs.rstrip('/')) or 'download'
        zip_filename = folder_name + '.zip'

        # ── Send headers ─────────────────────────────────────────────────────────
        try:
            self.send_response(200)
            self._send_cors_headers()
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', self._content_disposition(zip_filename))
            self.send_header('Content-Length', str(total_cl))
            if missing_files:
                import urllib.parse as _up
                self.send_header('X-Zip-Missing-Files',
                                 _up.quote(json.dumps(missing_files), safe=''))
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            return

        READ_BUF = 2 * 1024 * 1024
        offset   = 0          # running byte offset (Python int, no overflow)
        cd_entries = []

        def _write(data: bytes):
            nonlocal offset
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
                raise
            offset += len(data)

        try:
            for abs_path, arcname, arcname_bytes, file_size, dos_time, dos_date in files_info:
                fn_len = len(arcname_bytes)
                local_offset = offset   # record start of this entry

                # ── ZIP64 extra field for LFH ────────────────────────────────
                z64_extra = _st.pack('<HH QQ',
                    0x0001,          # tag = ZIP64
                    16,              # size of following data
                    file_size,       # uncompressed  (Q = uint64)
                    file_size,       # compressed    (Q = uint64)
                )

                # ── Local file header ────────────────────────────────────────
                # Sizes in header = 0xFFFFFFFF signals "see ZIP64 extra field"
                lfh = _st.pack('<4sHHHHHIIIHH',
                    LFH_SIG,
                    45,             # version needed: 4.5 (ZIP64)
                    FLAG_DD,
                    METHOD_STORED,
                    dos_time, dos_date,
                    0,              # CRC placeholder (real value in descriptor)
                    UINT32_MAX,     # compressed   size → ZIP64
                    UINT32_MAX,     # uncompressed size → ZIP64
                    fn_len,
                    len(z64_extra),
                ) + arcname_bytes + z64_extra
                _write(lfh)

                # ── File data ────────────────────────────────────────────────
                crc = 0
                bytes_written = 0
                try:
                    with open(abs_path, 'rb') as f:
                        remaining = file_size
                        while remaining > 0:
                            chunk = f.read(min(READ_BUF, remaining))
                            if not chunk:
                                break
                            _write(chunk)
                            crc = _zl.crc32(chunk, crc) & 0xFFFF_FFFF
                            bytes_written += len(chunk)
                            remaining -= len(chunk)
                except OSError:
                    logging.warning(f'ZIP64: file vanished mid-stream: {abs_path!r} (arcname: {arcname!r})')
                if bytes_written < file_size:
                    pad = bytes(file_size - bytes_written)
                    _write(pad)
                    crc = _zl.crc32(pad, crc) & 0xFFFF_FFFF
                    bytes_written = file_size

                # ── ZIP64 data descriptor ────────────────────────────────────
                dd = _st.pack('<4s I QQ',
                    DD_SIG,
                    crc,
                    bytes_written,   # compressed   (Q)
                    bytes_written,   # uncompressed (Q)
                )
                _write(dd)

                # ── Central directory entry ──────────────────────────────────
                # ZIP64 extra for CDH: uncompressed + compressed + local header offset
                z64_cdh_extra = _st.pack('<HH QQQ',
                    0x0001, 24,
                    bytes_written,   # uncompressed
                    bytes_written,   # compressed
                    local_offset,    # local header offset (Q)
                )
                cdh = _st.pack('<4sHHHHHHIIIHHHHHII',
                    CDH_SIG,
                    45, 45,          # version made by / needed
                    FLAG_DD,
                    METHOD_STORED,
                    dos_time, dos_date,
                    crc,
                    UINT32_MAX,      # compressed   → ZIP64
                    UINT32_MAX,      # uncompressed → ZIP64
                    fn_len,
                    len(z64_cdh_extra),
                    0,               # file comment
                    0,               # disk start
                    0,               # internal attr
                    0,               # external attr
                    UINT32_MAX,      # local header offset → ZIP64
                ) + arcname_bytes + z64_cdh_extra
                cd_entries.append(cdh)

            # ── Central directory ────────────────────────────────────────────────
            cd_start = offset
            for cdh in cd_entries:
                _write(cdh)
            cd_end = offset
            cd_total_size = cd_end - cd_start
            n_entries = len(cd_entries)

            # ── ZIP64 End of Central Directory record ────────────────────────────
            # Size of zip64 EOCD record = total_size - 12 (sig + size field itself)
            zip64_eocd = _st.pack('<4s Q HHII QQ QQ',
                ZIP64_EOCD_SIG,
                44,              # size of remaining record (= 56 - 12)
                45,              # version made by
                45,              # version needed
                0,               # disk number
                0,               # disk with CD
                n_entries,       # entries on this disk  (Q)
                n_entries,       # total entries         (Q)
                cd_total_size,   # CD size               (Q)
                cd_start,        # CD offset             (Q)
            )
            _write(zip64_eocd)

            # ── ZIP64 EOCD locator ───────────────────────────────────────────────
            zip64_locator = _st.pack('<4s I Q I',
                ZIP64_EOCD_LOCATOR,
                0,               # disk with start of zip64 EOCD
                cd_end,          # offset of zip64 EOCD record
                1,               # total number of disks
            )
            _write(zip64_locator)

            # ── Classic EOCD (required — points to ZIP64 structures) ────────────
            eocd = _st.pack('<4s HH HH II H',
                EOCD_SIG,
                0, 0,            # disk / disk with CD
                min(n_entries, UINT16_MAX),
                min(n_entries, UINT16_MAX),
                min(cd_total_size, UINT32_MAX),
                min(cd_start,      UINT32_MAX),
                0,               # comment length
            )
            _write(eocd)

            try:
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
                pass

            logging.info(
                f'ZIP64 streamed: {zip_filename} '
                f'({len(files_info)} files, {total_cl} bytes) user={user_id}'
            )

        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
            pass   # client disconnected mid-stream


    def _handle_zip_meta(self, path_segment: str):
        """GET /api/v1/zip_meta/<path>
        Auth + path resolution only — returns a job_id immediately (status='scanning').
        The actual CRC32 scan and offset-table build runs in a background thread.
        Client polls GET /api/v1/zip_status/<job_id> until status='ready'.
        """
        share_override = getattr(self, '_zip_share_override', None)
        if share_override is not None:
            base_fs = share_override
            user_id = 'share'
        else:
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Unauthorized'}))
            relative_path = unquote(path_segment)
            user_root = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))
            if relative_path.startswith('/cdn'):
                cdn_rel = relative_path[len('/cdn'):]
                base_fs = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
                if not os.path.realpath(base_fs).startswith(os.path.realpath(CDN_UPLOAD_DIR)):
                    return self._send_response(400, json.dumps({'error': 'Invalid path.'}))
            else:
                base_fs = os.path.normpath(os.path.join(user_root, relative_path.lstrip('/')))
                if not os.path.realpath(base_fs).startswith(user_root):
                    return self._send_response(403, json.dumps({'error': 'Forbidden'}))

        if not os.path.isdir(base_fs):
            return self._send_response(404, json.dumps({'error': 'Not a directory.'}))

        # Create job entry immediately so the client can start polling
        job_id = str(_uuid_mod.uuid4())
        with _zip_jobs_lock:
            _zip_jobs[job_id] = {
                'status':   'scanning',
                'progress': 0,      # files scanned so far
                'total':    None,   # total files (set after pre-walk)
                'error':    None,
                'expires':  time.time() + ZIP_JOB_TTL,
                'user_id':  user_id,  # 'share' for share-initiated jobs — used by zip_status auth
                # session payload set when scan completes:
                'session':  None,
                'filename': None,
                'size':     None,
                'missing':  None,
                'needs_hashing': False,
            }

        folder_name = os.path.basename(base_fs.rstrip('/')) or 'download'

        # Launch the heavy scan in a background thread so this request returns fast
        threading.Thread(
            target=_zip_build_job,
            args=(job_id, base_fs, folder_name, user_id),
            daemon=True,
            name=f'ZipBuild-{job_id[:8]}',
        ).start()

        logging.info('zip_meta: job %s started for %r user=%s', job_id[:8], base_fs, user_id)
        return self._send_response(202, json.dumps({
            'job_id':  job_id,
            'status':  'scanning',
            'poll_url': f'/api/v1/zip_status/{job_id}',
        }))

    def _handle_zip_status(self, job_id: str):
        """GET /api/v1/zip_status/<job_id>
        Returns current job state.  When status='ready' the response also
        includes the stream URL, filename, size, missing list, and needs_hashing.
        """
        with _zip_jobs_lock:
            job = _zip_jobs.get(job_id)

        if not job:
            return self._send_response(404, json.dumps({'error': 'Job not found or expired'}))

        # Auth: share-initiated jobs (user_id=='share') are public — the job_id
        # itself is the access token (UUIDv4, unguessable).  Authenticated jobs
        # require a valid Bearer token, but we don't re-verify ownership because
        # the job was already auth-gated at creation time.
        if job.get('user_id') != 'share':
            user_id = self._check_token_auth()
            if not user_id:
                return self._send_response(401, json.dumps({'error': 'Unauthorized'}))

        with _zip_jobs_lock:
            job = _zip_jobs.get(job_id)

        if not job:
            return self._send_response(404, json.dumps({'error': 'Job not found or expired'}))

        # Refresh TTL on poll so active clients keep the job alive
        with _zip_jobs_lock:
            if job_id in _zip_jobs:
                _zip_jobs[job_id]['expires'] = time.time() + ZIP_JOB_TTL

        status = job['status']
        resp   = {'job_id': job_id, 'status': status}

        if status == 'scanning':
            resp['progress'] = job['progress']
            resp['total']    = job['total']

        elif status == 'ready':
            session_id = job['session']
            resp.update({
                'session_id':    session_id,
                'filename':      job['filename'],
                'size':          job['size'],
                'ttl':           ZIP_SESSION_TTL,
                'missing':       job['missing'],
                'needs_hashing': job['needs_hashing'],
                'url':           f'/api/v1/zip_stream/{session_id}',
            })

        elif status == 'error':
            resp['error'] = job['error']

        return self._send_response(200, json.dumps(resp))


    def _handle_zip_stream(self, session_id: str):
        """GET /api/v1/zip_stream/<session_id>[  Range: bytes=N-M ]
        Streams the ZIP using the pre-built session.  Supports Range requests
        so interrupted downloads can resume without rebuilding the archive.
        No data is written to disk — everything streams directly to the wire.
        """
        with _zip_sessions_lock:
            session = _zip_sessions.get(session_id)

        if not session:
            return self._send_response(404, json.dumps({'error': 'ZIP session not found or expired'}))

        # Refresh expiry on access
        with _zip_sessions_lock:
            if session_id in _zip_sessions:
                _zip_sessions[session_id]['expires'] = time.time() + ZIP_SESSION_TTL

        total_size = session['total_size']
        filename   = session['filename']

        # Parse Range header
        range_hdr = self.headers.get('Range', '')
        req_start, req_end = 0, total_size - 1
        status = 200
        if range_hdr.startswith('bytes='):
            try:
                parts     = range_hdr[6:].split('-')
                req_start = int(parts[0]) if parts[0] else 0
                req_end   = int(parts[1]) if len(parts) > 1 and parts[1] else total_size - 1
                req_end   = min(req_end, total_size - 1)
                status    = 206
            except (ValueError, IndexError):
                pass

        length = req_end - req_start + 1

        try:
            self.send_response(status)
            self._send_cors_headers()
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', self._content_disposition(filename))
            self.send_header('Content-Length', str(length))
            self.send_header('Accept-Ranges', 'bytes')
            if status == 206:
                self.send_header('Content-Range', f'bytes {req_start}-{req_end}/{total_size}')
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            return

        READ_BUF  = 2 * 1024 * 1024
        remaining = length   # bytes left to send to the client

        def _write(data: bytes) -> bool:
            """Send up to `remaining` bytes of data. Returns False on disconnect."""
            nonlocal remaining
            if remaining <= 0 or not data:
                return True
            send = data[:remaining]
            try:
                self.wfile.write(send)
                remaining -= len(send)
                return True
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
                return False

        def _write_clipped(data: bytes, virt_start: int) -> bool:
            """Send the portion of `data` (whose first byte is at virtual offset
            `virt_start`) that falls within [req_start, req_end].
            Returns False on disconnect."""
            virt_end = virt_start + len(data)
            ol_s = max(virt_start, req_start)
            ol_e = min(virt_end,   req_end + 1)
            if ol_s >= ol_e:
                return True
            return _write(data[ol_s - virt_start : ol_e - virt_start])

        try:
            # ── File entries ──────────────────────────────────────────────────
            # Since the ZIP uses STORED (no compression) every virtual offset is
            # deterministic and pre-computed in the session.  We can therefore
            # jump directly to the entry that contains req_start without reading
            # or re-hashing anything before it.
            for entry in session['files']:
                if remaining <= 0:
                    break

                lf_offset   = entry['lf_offset']
                data_offset = entry['data_offset']
                fsz         = entry['size']
                entry_end   = data_offset + fsz   # first byte of the next entry

                # This entry ends entirely before req_start — skip it with zero I/O.
                if entry_end <= req_start:
                    continue

                # This entry starts entirely after req_end — nothing more to send.
                if lf_offset > req_end:
                    break

                # ── LFH (fixed-size header for this entry) ───────────────────
                lfh = entry['lfh']
                if not _write_clipped(lfh, lf_offset):
                    return

                # ── File data ────────────────────────────────────────────────
                if fsz > 0:
                    # How many bytes of this file's data lie before req_start?
                    # Seek past them directly — no disk read, no _write call.
                    file_skip  = max(0, req_start - data_offset)
                    # How many bytes of this file's data lie after req_end?
                    file_trail = max(0, entry_end - (req_end + 1))
                    # Bytes we actually need to read and send from this file.
                    read_len   = fsz - file_skip - file_trail

                    if read_len > 0:
                        try:
                            with open(entry['abs_path'], 'rb') as fh:
                                if file_skip:
                                    fh.seek(file_skip)
                                sent = 0
                                while sent < read_len:
                                    chunk = fh.read(min(READ_BUF, read_len - sent))
                                    if not chunk:
                                        break
                                    if not _write(chunk):
                                        return
                                    sent += len(chunk)
                        except OSError:
                            # File disappeared mid-stream — pad with zeros so the
                            # stream length stays correct (CRC will flag the file).
                            logging.warning('zip_stream: file vanished during send: %r',
                                            entry['abs_path'])
                            pad = read_len
                            while pad > 0:
                                chunk = bytes(min(READ_BUF, pad))
                                if not _write(chunk):
                                    return
                                pad -= len(chunk)

            # ── Central directory + EOCD ──────────────────────────────────────
            # cd_start is stored in the session; the other structs follow it.
            cd_start = session['cd_start']
            tail_parts = [
                (session['cd_bytes'],    cd_start),
                (session['zip64_eocd'],  cd_start + len(session['cd_bytes'])),
                (session['zip64_loc'],   cd_start + len(session['cd_bytes']) + len(session['zip64_eocd'])),
                (session['eocd'],        cd_start + len(session['cd_bytes']) + len(session['zip64_eocd']) + len(session['zip64_loc'])),
            ]
            for data, virt_start in tail_parts:
                if remaining <= 0:
                    break
                if not _write_clipped(data, virt_start):
                    return

            try:
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError):
                pass

        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError) as _disc:
            logging.debug('zip_stream: client disconnected (%s)', _disc)

    # --- Lazy folder size ---
    # --- Lazy folder size ---

    def _handle_foldersize(self, path_segment: str):
        """GET /api/v1/foldersize/<path>  — return total size of a folder tree.

        This is called lazily per-row by the frontend so that the directory
        listing itself stays fast.  Walks the tree synchronously; for very large
        trees this may take a second or two, but it runs in its own thread via
        ThreadingHTTPServer so it never blocks other requests.
        """
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))

        relative_path = unquote(path_segment)
        user_root = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))

        if relative_path.startswith('/cdn'):
            cdn_rel = relative_path[len('/cdn'):]
            base_fs = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
            if not os.path.realpath(base_fs).startswith(os.path.realpath(CDN_UPLOAD_DIR)):
                return self._send_response(400, json.dumps({'error': 'Invalid path.'}))
        else:
            base_fs = os.path.normpath(os.path.join(user_root, relative_path.lstrip('/')))
            if not os.path.realpath(base_fs).startswith(user_root):
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))

        if not os.path.isdir(base_fs):
            return self._send_response(404, json.dumps({'error': 'Not a directory.'}))

        total = 0
        file_count = 0
        try:
            for dirpath, _dirs, filenames in os.walk(base_fs):
                for fname in filenames:
                    try:
                        total += os.path.getsize(os.path.join(dirpath, fname))
                        file_count += 1
                    except OSError:
                        pass
        except OSError as e:
            return self._send_response(500, json.dumps({'error': str(e)}))

        return self._send_response(200, json.dumps({
            'path': relative_path,
            'size': total,
            'file_count': file_count,
        }))

    def _handle_archive_tree(self, path_segment: str):
        """GET /api/v1/archive_tree/<path>  — return the file tree of an archive without
        downloading the whole file.

        For ZIP files this reads only the central directory (last ~1% of the file),
        which is extremely fast even for multi-GB archives.  For .tar.gz/.tgz a
        lightweight streaming header scan is used so we never buffer the full payload.

        Returns JSON: { entries: [{name, size, is_dir}], format: 'zip'|'tar' }
        Requires a valid session + download token (same auth as /api/v1/download).
        """
        import zipfile as _zf

        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Unauthorized'}))

        relative_path = unquote(path_segment)
        user_root = os.path.normpath(os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id)))

        if relative_path.startswith('/cdn'):
            cdn_rel  = relative_path[len('/cdn'):]
            base_fs  = os.path.normpath(os.path.join(CDN_UPLOAD_DIR, cdn_rel.lstrip('/')))
            if not os.path.realpath(base_fs).startswith(os.path.realpath(CDN_UPLOAD_DIR)):
                return self._send_response(400, json.dumps({'error': 'Invalid path.'}))
        else:
            base_fs = os.path.normpath(os.path.join(user_root, relative_path.lstrip('/')))
            if not os.path.realpath(base_fs).startswith(user_root):
                return self._send_response(403, json.dumps({'error': 'Forbidden'}))

        if not os.path.isfile(base_fs):
            return self._send_response(404, json.dumps({'error': 'File not found.'}))

        # Validate download token (same gate as the download handler)
        parsed_qs = parse_qs(urlparse(self.path).query)
        dl_token  = parsed_qs.get('dl_token', [None])[0]
        if dl_token is None:
            return self._send_response(403, json.dumps({'error': 'dl_token required.'}))

        if relative_path.startswith('/cdn'):
            rel_path_for_db = relative_path
        else:
            rel_path_for_db = '/' + os.path.relpath(base_fs, user_root).replace(os.sep, '/')

        token_meta = _validate_download_token(rel_path_for_db, dl_token)
        if token_meta is None:
            return self._send_response(403, json.dumps({'error': 'Invalid or expired dl_token.'}))

        ext = (base_fs.rsplit('.', 1)[-1] if '.' in base_fs else '').lower()

        try:
            if ext == 'zip':
                # Python's zipfile reads only the End-of-Central-Directory record and
                # the Central Directory — it never reads compressed file data, so
                # this is O(number_of_entries), not O(file_size).
                entries = []
                with _zf.ZipFile(base_fs, 'r') as zf:
                    for info in zf.infolist():
                        entries.append({
                            'name':   info.filename,
                            'size':   info.file_size if not info.is_dir() else None,
                            'is_dir': info.is_dir(),
                        })
                return self._send_response(200, json.dumps({'format': 'zip', 'entries': entries}))

            elif ext in ('tar', 'gz', 'tgz'):
                # Stream tar headers only — skip over file data without reading it.
                import tarfile as _tf
                entries = []
                mode = 'r:gz' if ext in ('gz', 'tgz') else 'r:'
                with _tf.open(base_fs, mode) as tf:
                    for member in tf.getmembers():
                        entries.append({
                            'name':   member.name,
                            'size':   member.size if not member.isdir() else None,
                            'is_dir': member.isdir(),
                        })
                return self._send_response(200, json.dumps({'format': 'tar', 'entries': entries}))

            else:
                return self._send_response(415, json.dumps({'error': f'.{ext} archive tree not supported.'}))

        except Exception as exc:
            logging.exception('archive_tree failed')
            return self._send_response(500, json.dumps({'error': str(exc)}))

    def handle_public_share_upload(self, token: str):
        """POST /share/<token>/upload[?subpath=<relative>] — upload into a shared folder or subfolder."""
        share = _get_share(token)
        if not share or not share["is_dir"]:
            return self._send_response(404, json.dumps({"error": "Share not found or not a folder."}))

        visitor_user_id = self._check_token_auth()
        if not share["allow_anon_upload"] and share["allow_auth_upload"]:
            if not visitor_user_id:
                return self._send_response(403, json.dumps({"error": "A FluxDrop account is required to upload here."}))
        elif not share["allow_anon_upload"] and not share["allow_auth_upload"]:
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
                written = 0
                while True:
                    chunk = file_item.stream.read(1 * 1024 * 1024)
                    if not chunk: break
                    written += len(chunk)
                    if written > MAX_SHARE_UPLOAD_BYTES:
                        f.close()
                        try:
                            os.remove(save_path)
                        except OSError:
                            pass
                        return self._send_response(413, json.dumps({"error": "File too large."}))
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
        # Right now, it's not working, and... The purpose is unknown to be fair. Will be marked for removal
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
                    pending = _pending_dest_paths(user_id)
                    for name in sorted(os.listdir(target)):
                        p  = os.path.join(target, name)
                        if not os.path.isdir(p) and p in pending:
                            continue                                # skip partial upload file
                        st  = os.stat(p)
                        rel = '/' + os.path.relpath(p, user_dir).replace(os.sep, '/')
                        entries.append({
                            "name": name, "path": rel,
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
                bufsize = 4 * 1024 * 1024   # 4 MB read buffer
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
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLError) as _disc:
                logging.debug('Download: client disconnected (%s)', _disc)
                return
            except Exception as e:
                logging.error('Download failed (non-client error): %s', e)
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

                # CDN files are hard-deleted immediately (no trash for shared area).
                # Per-user files go into the trash bin (soft delete).
                is_cdn = relative_path.startswith('/cdn')
                for p in paths:
                    p_clean = strip_prefix(p)
                    target = os.path.normpath(os.path.join(base_fs, p_clean.lstrip('/')))
                    if not os.path.realpath(target).startswith(os.path.realpath(base_fs)):
                        errors.append(p)
                        continue
                    try:
                        if is_cdn:
                            # CDN: immediate removal as before
                            if os.path.isfile(target):
                                os.remove(target)
                            elif os.path.isdir(target):
                                shutil.rmtree(target)
                            else:
                                errors.append(p)
                        else:
                            # User file: soft-delete into trash
                            if not os.path.exists(target):
                                errors.append(p)
                                continue
                            orig_rel = '/' + os.path.relpath(target, base_fs).replace(os.sep, '/')
                            row = _move_to_trash(user_id, target, orig_rel)
                            with _db_connect() as _tc:
                                _tc.execute(
                                    'INSERT INTO trash_items (user_id, original_path, trash_path,'
                                    ' deleted_at, size_bytes, is_dir, retention_days)'
                                    ' VALUES (?,?,?,?,?,?,?)',
                                    (row['user_id'], row['original_path'], row['trash_path'],
                                     row['deleted_at'], row['size_bytes'], row['is_dir'],
                                     row['retention_days'])
                                )
                                _tc.commit()
                    except Exception as e:
                        logging.exception(f"Delete/trash failed for {target}")
                        errors.append(p)
                if errors:
                    return self._send_response(500, json.dumps({"error": "Some deletes failed", "failed": errors}))
                return self._send_response(200, json.dumps({"message": "Moved to trash"}))
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

                # Update any share links whose path starts with the old path.
                # This covers both a direct file share and any shares for
                # folders that contain the renamed item.
                old_rel = '/' + old.lstrip('/')
                new_rel = '/' + new.lstrip('/')
                try:
                    with _db_connect() as conn:
                        # Exact match (file or folder share pointing at the moved item)
                        conn.execute(
                            "UPDATE shared_links SET path = ? WHERE owner_id = ? AND path = ?",
                            (new_rel, user_id, old_rel)
                        )
                        # Prefix match (shares for items *inside* a renamed folder)
                        prefix = old_rel.rstrip('/') + '/'
                        new_prefix = new_rel.rstrip('/') + '/'
                        cur = conn.execute(
                            "SELECT token, path FROM shared_links WHERE owner_id = ? AND path LIKE ?",
                            (user_id, prefix + '%')
                        )
                        rows = cur.fetchall()
                        for row in rows:
                            updated = new_prefix + row[1][len(prefix):]
                            conn.execute(
                                "UPDATE shared_links SET path = ? WHERE token = ?",
                                (updated, row[0])
                            )
                        conn.commit()
                except Exception:
                    logging.exception("Failed to update share paths after rename — shares may be stale")
                    # Non-fatal: the rename itself succeeded

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
        """Handles CatBox fileupload with streaming + configurable size cap."""
        from config import CATBOX_MAX_UPLOAD_BYTES as _CATBOX_LIMIT

        file_items = files.getlist('fileToUpload')
        if not file_items:
            return self._send_response(400, "Bad Request: Missing 'fileToUpload' field.", "text/plain")

        file_item = file_items[0]
        if not file_item or not file_item.filename:
            return self._send_response(400, "Bad Request: No file selected for upload.", "text/plain")

        # ── Early Content-Length check (avoids wasting time streaming a too-large file) ──
        try:
            declared_size = int(self.headers.get('Content-Length', 0))
        except ValueError:
            declared_size = 0
        if declared_size > _CATBOX_LIMIT:
            return self._send_response(
                413,
                f"File too large: declared {declared_size // (1024**2)} MB, "
                f"limit is {_CATBOX_LIMIT // (1024**2)} MB. "
                f"Set CATBOX_MAX_UPLOAD_BYTES env var to change the limit.",
                "text/plain"
            )

        try:
            file_ext    = os.path.splitext(file_item.filename)[1]
            random_name = secrets.token_urlsafe(6).lower().replace('-', '').replace('_', '')
            new_filename = f"{random_name}{file_ext}"

            save_path = os.path.normpath(os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR, new_filename))
            if not os.path.realpath(save_path).startswith(os.path.realpath(SERVE_ROOT)):
                return self._send_response(400, "Bad Request: Invalid path.", "text/plain")

            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            chunk_size    = 2 * 1024 * 1024  # 2 MB read buffer
            bytes_written = 0

            with open(save_path, 'wb') as f:
                while True:
                    chunk = file_item.stream.read(chunk_size)
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    # Runtime guard: reject mid-stream if the actual data exceeds limit
                    if bytes_written > _CATBOX_LIMIT:
                        f.close()
                        try:
                            os.remove(save_path)
                        except OSError:
                            pass
                        return self._send_response(
                            413,
                            f"File too large: stream exceeded {_CATBOX_LIMIT // (1024**2)} MB limit. "
                            f"Set CATBOX_MAX_UPLOAD_BYTES env var to change.",
                            "text/plain"
                        )
                    f.write(chunk)

                    if bytes_written % (100 * 1024 * 1024) == 0:
                        logging.info(f"CatBox upload progress: {bytes_written // (1024*1024)} MB")

            file_url = f"https://{PUBLIC_DOMAIN}:{HTTPS_PORT}/{CATBOX_UPLOAD_DIR}/{new_filename}"
            logging.info(
                f"CatBox user '{auth_user_display}' uploaded '{file_item.filename}' "
                f"({bytes_written} bytes) to '{save_path}'"
            )

            protected_flag = form.get('protected') or form.get('require_token')
            if protected_flag and str(protected_flag).lower() in ('1', 'true', 'on'):
                rel = '/' + os.path.relpath(save_path, SERVE_ROOT).replace(os.sep, '/')
                try:
                    _mark_file_protected(rel, created_by=user_id)
                    logging.info(f"Marked uploaded file as protected: {rel} (created_by={user_id})")
                    return self._send_response(
                        200,
                        file_url + "\n[PROTECTED] This file requires a token to view. "
                        "Generate a token using the server CLI.",
                        "text/plain"
                    )
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
    server = _FastThreadingHTTPServer(server_address, AuthHandler)
    proto = 'HTTPS' if use_ssl else 'HTTP'
    if use_ssl:
        if not all(os.path.exists(f) for f in [CERT_FILE, KEY_FILE]):
            logging.critical(f"SSL cert/key not found. Cannot start {proto}.")
            return
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            # Prefer ChaCha20 for software-only CPU (no AES-NI).
            # See server_https.py for the full rationale.
            # OP_PRIORITIZE_CHACHA is required for TLS 1.3; without it
            # OP_CIPHER_SERVER_PREFERENCE alone is ignored for TLS 1.3 suites.
            if hasattr(ssl, 'OP_PRIORITIZE_CHACHA'):
                context.options |= ssl.OP_PRIORITIZE_CHACHA
            try:
                context.set_ciphersuites(
                    'TLS_CHACHA20_POLY1305_SHA256:'
                    'TLS_AES_256_GCM_SHA384:'
                    'TLS_AES_128_GCM_SHA256'
                )
            except AttributeError:
                pass
            try:
                context.set_ciphers(
                    'ECDHE+CHACHA20:ECDHE+AESGCM:DHE+CHACHA20:DHE+AESGCM:'
                    '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK'
                )
            except ssl.SSLError as _ce:
                logging.warning('Could not set custom TLS 1.2 cipher list: %s', _ce)
            # Disable server-side session cache — same rationale as server_https.py:
            # unbounded growth causes memory pressure and eventual instability
            # after days of uptime.  File transfers benefit minimally from resumption.
            try:
                context.set_session_cache_mode(ssl.SESS_CACHE_OFF)
            except AttributeError:
                pass
            context.options |= getattr(ssl, 'OP_NO_TICKET', 0)
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

class _InternalAuthHandler(AuthHandler):
    """AuthHandler variant used exclusively by the plain-HTTP loopback listener.

    The only difference: _redirect_to_https_if_needed() is a no-op.
    server_https already holds the TLS session with the real client; the
    loopback leg is trusted internal traffic and must never redirect.
    Redirecting here would hand server_https a 308 response, which it
    forwards to the browser, breaking every API/auth call.
    """

    def _redirect_to_https_if_needed(self) -> bool:
        return False   # loopback leg is always trusted plain HTTP


def run_internal_server():
    """Plain HTTP listener on 127.0.0.1 only — no TLS.
    Used exclusively by server_https._proxy_to_cdn so that the loopback leg
    carries no encryption overhead (software AES on i3 370m bottlenecks at
    ~20 MB/s when both legs are TLS).  Never bind to 0.0.0.0.
    """
    server = _FastThreadingHTTPServer(('127.0.0.1', CDN_INTERNAL_PORT), _InternalAuthHandler)
    logging.info(
        'CDN internal plain-HTTP listener on 127.0.0.1:%d (loopback only)',
        CDN_INTERNAL_PORT,
    )
    try:
        server.serve_forever()
    except Exception as e:
        logging.critical('CDN internal HTTP listener on port %d failed: %s',
                         CDN_INTERNAL_PORT, e)
    finally:
        server.server_close()


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

        # A2: Prune share_access_log (keep 90 days, consistent with status_snapshots retention)
        try:
            with _db_connect() as conn:
                conn.execute(
                    "DELETE FROM share_access_log WHERE accessed_at < datetime('now', '-90 days')"
                )
                conn.commit()
        except Exception:
            logging.exception('TokenPurge: failed to prune share_access_log')

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

        # Purge expired trash items
        try:
            n = _trash_purge_expired()
            if n:
                logging.info(f'TokenPurge: purged {n} expired trash item(s)')
        except Exception:
            logging.exception('TokenPurge: trash purge failed')

        # A10: Keep only the 100 most recent message_board rows
        try:
            with _db_connect() as conn:
                conn.execute(
                    "DELETE FROM message_board WHERE id NOT IN "
                    "(SELECT id FROM message_board ORDER BY id DESC LIMIT 100)"
                )
                conn.commit()
        except Exception:
            logging.exception('TokenPurge: failed to prune message_board')

        # Purge stale IP Beacon entries:
        #   - devices not seen for > 30 days
        #   - read tokens older than 7 days (they're lightweight shareable links;
        #     owners can regenerate via the UI)
        try:
            with _db_connect() as conn:
                now_ts = time.time()
                conn.execute(
                    'DELETE FROM beacon_devices WHERE last_seen < ?',
                    (now_ts - 30 * 86400,)
                )
                # Purge read tokens idle for more than 7 days.
                # COALESCE falls back to created_at for rows that pre-date
                # the last_used column (they'll get last_used = NULL until
                # their first lookup after the migration).
                conn.execute(
                    'DELETE FROM beacon_read_tokens'
                    ' WHERE COALESCE(last_used, created_at) < ?',
                    (now_ts - 7 * 86400,)
                )
                conn.commit()
        except Exception:
            logging.exception('TokenPurge: beacon purge failed')

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

def _require_admin(handler_method):
    """Decorator for request handler methods that require admin privileges."""
    def wrapper(self, *args, **kwargs):
        user_id = self._check_token_auth()
        if not user_id:
            return self._send_response(401, json.dumps({'error': 'Authentication required'}))
        with _db_connect() as conn:
            row = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
        if not row or not row[0]:
            return self._send_response(403, json.dumps({'error': 'Admin access required'}))
        return handler_method(self, user_id, *args, **kwargs)
    return wrapper

def _get_user_disk_usage(user_id: int) -> int:
    """Return total bytes used by a user (excluding .trash — trash is free quota)."""
    user_dir   = os.path.join(SERVE_ROOT, 'FluxDrop', str(user_id))
    trash_root = os.path.realpath(_user_trash_root(user_id))
    total = 0
    try:
        for dirpath, dirs, filenames in os.walk(user_dir):
            # Skip .trash subtree so trash bytes don't count against quota
            if os.path.realpath(dirpath).startswith(trash_root):
                dirs[:] = []  # prune walk
                continue
            for f in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, f))
                except OSError:
                    pass
    except OSError:
        pass
    return total

if __name__ == '__main__':
    # --- Pre-flight Checks & Setup ---
    init_db()  # Initialize the database

    # Reset any checksum jobs left in 'running' state by a previous process
    # (they were interrupted mid-computation and need to be retriggered by the user).
    _stale_jobs = checksum_jobs_reset_stale()
    if _stale_jobs:
        logging.info('Checksum jobs: reset %d stale running job(s) to error', _stale_jobs)
    # Re-enqueue jobs that were pending when the server last shut down.
    for _pj in checksum_jobs_get_pending():
        try:
            if _pj['user_id'] is not None:
                _pj_abs = os.path.normpath(os.path.join(
                    SERVE_ROOT, 'FluxDrop', str(_pj['user_id']),
                    _pj['relative_path'].lstrip('/')))
            else:
                _pj_abs = os.path.normpath(os.path.join(
                    CDN_UPLOAD_DIR, _pj['relative_path'].lstrip('/')))
            if os.path.isfile(_pj_abs):
                dispatch_checksum_job(_pj['id'], _pj_abs,
                                       _pj['relative_path'], _pj['user_id'],
                                       _pj['algos'])
            else:
                checksum_job_update_status(
                    _pj['id'], 'error', 'File not found at startup re-queue')
        except Exception as _pje:
            logging.warning('Checksum jobs: could not re-enqueue job %d: %s',
                            _pj['id'], _pje)

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
    _reconcile_open_outages()   # close orphaned rows from any previous crash/restart
    net_mon_thread.start()

    quota_thread = threading.Thread(target=_quota_updater_thread, name="QuotaUpdater", daemon=True)
    quota_thread.start()

    # --- Start Server Threads ---
    http_thread = threading.Thread(target=run_server, args=(HTTP_PORT, False), name="HTTP-Thread", daemon=True)
    https_thread = threading.Thread(target=run_server, args=(HTTPS_PORT, True), name="HTTPS-Thread", daemon=True)
    internal_thread = threading.Thread(target=run_internal_server, name="CDN-Internal-HTTP", daemon=True)

    http_thread.start()
    https_thread.start()
    internal_thread.start()

    try:
        # Keep the main thread alive to handle shutdown
        while http_thread.is_alive() and https_thread.is_alive() and internal_thread.is_alive():
            http_thread.join(timeout=1)
            https_thread.join(timeout=1)
            internal_thread.join(timeout=1)
    except KeyboardInterrupt:
        logging.info("Main thread received KeyboardInterrupt. Shutting down.")
    finally:
        logging.info("Shutdown complete.")
