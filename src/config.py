#!/usr/bin/env python3
import os
import errno

# Centralized configuration for sensitive paths and defaults.
BASE_DIR = os.path.dirname(__file__)
DEFAULT_SECRETS_DIR = os.path.join(BASE_DIR, 'secrets')
SECRETS_DIR = os.getenv('SECRETS_DIR', DEFAULT_SECRETS_DIR)

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
