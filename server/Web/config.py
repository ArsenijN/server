#!/usr/bin/env python3
import os
import errno

# Centralized configuration for sensitive paths and defaults.
BASE_DIR = os.path.dirname(__file__)
DEFAULT_SECRETS_DIR = os.path.join(BASE_DIR, 'secrets')
SECRETS_DIR = os.getenv('SECRETS_DIR', DEFAULT_SECRETS_DIR)

# ---------------------------------------------------------------------------
# Load any environment-style files from the secrets directory before we use
# os.getenv() below.  This mirrors the behaviour already present in
# server_cdn.py and makes it easy to keep all credentials outside of version
# control; see secrets/samples for examples.

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
                os.environ.setdefault(key.strip(), val.strip())
    except FileNotFoundError:
        pass

# try common names; user can create one locally
_load_env_file(os.path.join(SECRETS_DIR, 'smtp.env'))
_load_env_file(os.path.join(SECRETS_DIR, 'credentials_local.env'))
_load_env_file(os.path.join(SECRETS_DIR, 'vars.env'))

# Ensure secrets directory exists (will be created by deploy step; harmless locally)
os.makedirs(SECRETS_DIR, exist_ok=True)

# Public serve directory (files to serve). Override with env `SERVE_DIRECTORY` in production.
SERVE_DIRECTORY = os.getenv('SERVE_DIRECTORY', '/home/arsen/servers/self-host/site/TestWeb')

# Log files (these are not secrets but kept here for single-point config)
LOG_FILE_HTTP = os.getenv('LOG_FILE_HTTP', '/home/arsen/servers/self-host/site/Web/logs.txt')
LOG_FILE_HTTPS = os.getenv('LOG_FILE_HTTPS', '/home/arsen/servers/self-host/site/Web/logsV2.txt')
LOG_FILE_CDN = os.getenv('LOG_FILE_CDN', '/home/arsen/servers/self-host/site/Web/LogsCDN.txt')

# Sensitive artifacts (default placed under the secrets directory)
BLACKLIST_FILE = os.getenv('BLACKLIST_FILE', os.path.join(SECRETS_DIR, 'blklst.txt'))
DB_FILE = os.getenv('DB_FILE', os.path.join(SECRETS_DIR, 'fluxdrop_users.db'))
AUDIT_LOG = os.getenv('AUDIT_LOG', os.path.join(SECRETS_DIR, 'audit.log'))

# SSL certificate/key
CERT_FILE = os.getenv('CERT_FILE', os.path.join(SECRETS_DIR, 'myCA.pem'))
KEY_FILE = os.getenv('KEY_FILE', os.path.join(SECRETS_DIR, 'myCA.key'))
WILDCARD_CERT_FILE = os.getenv('WILDCARD_CERT_FILE', '/etc/letsencrypt/live/cf-wildcard/fullchain.pem')
WILDCARD_KEY_FILE  = os.getenv('WILDCARD_KEY_FILE',  '/etc/letsencrypt/live/cf-wildcard/privkey.pem')

# CDN upload area (sensitive if private). By default keep under secrets.
CDN_UPLOAD_DIR = os.getenv('CDN_UPLOAD_DIR', os.path.join(SECRETS_DIR, 'CDN_uploads'))
# Try to create the CDN upload dir, but do not raise on permission errors (import-time safe).
try:
	os.makedirs(CDN_UPLOAD_DIR, exist_ok=True)
except OSError as e:
	if e.errno != errno.EACCES:
		raise

# Ensure public upload directory exists inside the serve directory
PUBLIC_UPLOAD_DIR = os.path.join(SERVE_DIRECTORY, 'uploads')
try:
	os.makedirs(PUBLIC_UPLOAD_DIR, exist_ok=True)
except OSError as e:
	if e.errno != errno.EACCES:
		raise

# Public-facing domain (can be overridden via env)
PUBLIC_DOMAIN = os.getenv('PUBLIC_DOMAIN', 'arseniusgen.uk.to')

# HSTS max-age, in seconds. Single source of truth — this same value used to be
# hardcoded as the literal string 'max-age=300; includeSubDomains' independently
# in ~6 places across server_http.py and server_cdn.py, which meant changing it
# meant remembering to touch every one of them. 300s (5 min) is intentionally
# short for now (staged rollout); bump via env or here once confirmed stable,
# and every call site picks it up automatically.
HSTS_MAX_AGE = int(os.getenv('HSTS_MAX_AGE', '300'))
HSTS_HEADER_VALUE = f'max-age={HSTS_MAX_AGE}; includeSubDomains'

# SMTP credentials should come from env vars in production
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', os.getenv('SMTP_PORT', '587')))
SMTP_SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL', '')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD', '')

# Chunks
# Chunk size and abandoned-session TTL are tunable via env
UPLOAD_CHUNK_SIZE = int(os.getenv('UPLOAD_CHUNK_SIZE', int(1 * 1024 * 1024))) #default 1 MB

UPLOAD_TMP_DIR           = os.getenv('UPLOAD_TMP_DIR', os.path.join(
    '/tmp', 'fluxdrop_upload_sessions'
))

SERVE_ROOT = os.path.abspath(os.getenv('SERVE_ROOT', '/media/arsen/dab4b7b7-8867-4bf3-9304-6fd153c0a028'))

# Host/ports
HOST = os.getenv('HOST', '0.0.0.0')
HTTP_PORT = int(os.getenv('HTTP_PORT', '63512'))
HTTPS_PORT = int(os.getenv('HTTPS_PORT', '64800'))
CDN_INTERNAL_PORT = int(os.getenv('CDN_INTERNAL_PORT', '64799'))  # loopback-only, no TLS

# Canonical external base URL — the origin the public actually reaches the server
# on. Every user-facing absolute URL (verification email, share links, upload
# response URLs) is built from this. Behind a reverse proxy that terminates TLS
# on 443 (fluxdrop.me) this is just "https://<domain>" with no port; when the
# CDN's own HTTPS port is exposed to browsers directly it includes that port.
#   - PUBLIC_BASE_URL   — set this directly for full control (e.g. https://fluxdrop.me)
#   - PUBLIC_HTTPS_PORT — or just override the port; 443 → no suffix
PUBLIC_HTTPS_PORT = int(os.getenv('PUBLIC_HTTPS_PORT', str(HTTPS_PORT)))
_pub_port_suffix  = '' if PUBLIC_HTTPS_PORT in (443, 0) else f':{PUBLIC_HTTPS_PORT}'
PUBLIC_BASE_URL   = os.getenv(
    'PUBLIC_BASE_URL', f'https://{PUBLIC_DOMAIN}{_pub_port_suffix}'
).rstrip('/')

# Default server root for CDN: use the larger media volume rather than the server's SSD (in most cases).
CATBOX_UPLOAD_DIR = os.getenv('CATBOX_UPLOAD_DIR', 'CB_uploads')

_SNIPPETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snippets')

UPLOAD_SESSION_TTL = int(os.getenv('UPLOAD_SESSION_TTL', str(48 * 3600)))   # 48 h
MAX_JSON_BODY = int(os.getenv('MAX_JSON_BODY', str(1  * 1024 * 1024)))  # 1 MB — cap all JSON request bodies
MAX_SHARE_UPLOAD_BYTES = int(os.getenv('MAX_SHARE_UPLOAD_BYTES', str(500 * 1024 * 1024)))   # 500 MB — cap anonymous share uploads
MAX_UPLOAD_BYTES = int(os.getenv('MAX_UPLOAD_BYTES', str(10 * 1024 * 1024 * 1024)))     # 10 GB legacy upload cap


# Never saw it actually changed (dynamic quota) - need to be tested
# Seems like related to the "small size of CDN drive" in my current server config
DEFAULT_QUOTA_BYTES = 50 * 1024 ** 3  # 50 GB
QUOTA_MIN_BYTES     = 10 * 1024 ** 3  # floor: never drop below 10 GB
QUOTA_MAX_BYTES     = 100 * 1024 ** 3 # ceiling: never exceed 100 GB


CATBOX_MAX_UPLOAD_BYTES = int(os.getenv('CATBOX_MAX_UPLOAD_BYTES', str(2 * 1024 ** 3)))  # 2 GB default

# When False (production default), routine static-file access logs are suppressed
# to reduce per-request log I/O overhead on the CDN path.  API, auth, and share
# requests are always logged regardless of this setting.
# Set DEBUG_LOGGING=1 in your environment to restore full access logging.
DEBUG_LOGGING = os.getenv('DEBUG_LOGGING', '').lower() in ('1', 'true', 'yes')