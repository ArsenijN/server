#!/usr/bin/env python3
"""
Simple CLI to generate or set an access token for a protected file.
Usage:
    python generate_token.py --file <filename> --username <user> --password <pw>
Options:
    --file: path relative to SERVE_ROOT (e.g. "/FluxDrop/1/foo.txt") or a CDN
             path (use "/cdn/..." or just a filename to target a file under the
             CDN upload directory).
    --token: optionally provide a token; if omitted a random token is generated and printed.

This tool verifies the provided username/password against the users table before allowing token creation.
"""
import os
import sys
import argparse
import sqlite3
import hashlib
import secrets
from config import DB_FILE, CDN_UPLOAD_DIR, SERVE_DIRECTORY


def main():
    ap = argparse.ArgumentParser(description='Generate/set access token for a protected file')
    ap.add_argument('--file', '-f', required=True, help='File path (relative to SERVE_ROOT) or filename in CDN upload dir')
    ap.add_argument('--username', '-u', required=True, help='Username (must exist in users table)')
    ap.add_argument('--password', '-p', required=True, help='Password for the username')
    ap.add_argument('--token', help='Optional token value to set. If omitted one will be generated and printed.')
    args = ap.parse_args()

    # Normalize relative path
    candidate = args.file
    if candidate.startswith('/'):
        rel = candidate
        # if user passed an absolute filesystem path pointing inside the CDN upload
        # directory, convert it to the API-friendly "/cdn" form
        if os.path.commonpath([os.path.abspath(rel), os.path.abspath(CDN_UPLOAD_DIR)]) == os.path.abspath(CDN_UPLOAD_DIR):
            # strip the physical CDN_UPLOAD_DIR prefix and replace with '/cdn'
            rel = '/cdn' + rel[len(os.path.abspath(CDN_UPLOAD_DIR)):]
    else:
        # assume it's a filename or relative path under CDN_UPLOAD_DIR
        rel = '/cdn/' + candidate.lstrip('/')

    # Verify credentials
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (args.username,))
        row = cursor.fetchone()
        if not row:
            print('ERROR: user not found')
            sys.exit(2)
        user_id, stored_hash, salt = row
        # compute hash same as server
        candidate_hash = hashlib.sha256((salt + args.password).encode('utf-8')).hexdigest()
        if candidate_hash != stored_hash:
            print('ERROR: invalid credentials')
            sys.exit(3)

        # Generate or use provided token
        token = args.token if args.token else secrets.token_urlsafe(16)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()

        # Upsert into protected_files
        try:
            cursor.execute(
                "INSERT INTO protected_files (relative_path, protected, token_hash, created_by) VALUES (?, 1, ?, ?) "
                "ON CONFLICT(relative_path) DO UPDATE SET token_hash=excluded.token_hash, protected=1, created_by=excluded.created_by",
                (rel, token_hash, user_id)
            )
            conn.commit()
        except Exception as e:
            print('ERROR: failed to store token in DB:', e)
            sys.exit(4)

    print('SUCCESS')
    print('file:', rel)
    print('username:', args.username)
    print('token:', token)
    print('\nDistribute the token (shown above) to trusted viewers. They can view the file by visiting:')
    print(f"https://<your-domain>[:port]{rel}?token={token}")


if __name__ == '__main__':
    main()
