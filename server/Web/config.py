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

# SMTP credentials should come from env vars in production
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', os.getenv('SMTP_PORT', '587')))
SMTP_SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL', '')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD', '')

# Chunks
UPLOAD_CHUNK_SIZE = os.getenv('UPLOAD_CHUNK_SIZE', str(1 * 1024 * 1024)) #default 1 MB

# Ensure that ports are provided from configs also
HTTP_PORT = int(os.getenv('HTTP_PORT', '8080'))
HTTPS_PORT = int(os.getenv('HTTPS_PORT', '8443'))

UPLOAD_TMP_DIR = os.getenv(
    'UPLOAD_TMP_DIR',
    '/tmp/fluxdrop_upload_sessions'
)

SERVE_ROOT = os.path.abspath(os.getenv('SERVE_ROOT', '/media/arsen/dab4b7b7-8867-4bf3-9304-6fd153c0a028'))

# Host/ports
HOST = os.getenv('HOST', '0.0.0.0')
HTTP_PORT = int(os.getenv('HTTP_PORT', '63512'))
HTTPS_PORT = int(os.getenv('HTTPS_PORT', '64800'))

# Default server root for CDN: use the larger media volume rather than the server's SSD (in most cases).
CATBOX_UPLOAD_DIR = os.getenv('CATBOX_UPLOAD_DIR', 'CB_uploads')