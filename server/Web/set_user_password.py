#!/usr/bin/env python3
"""
Set/reset a user's password (admin CLI). Usage:
    python set_user_password.py --username USER --password NEWPASS [--db path]
This updates the users table with a new salt and password_hash compatible with the server.
"""
import argparse
import sqlite3
import secrets
import hashlib
from config import DB_FILE

ap = argparse.ArgumentParser()
ap.add_argument('--username', '-u', required=True)
ap.add_argument('--password', '-p', required=True)
ap.add_argument('--db', help='Path to DB file', default=DB_FILE)
args = ap.parse_args()

salt = secrets.token_hex(16)
hash_hex = hashlib.sha256((salt + args.password).encode('utf-8')).hexdigest()

with sqlite3.connect(args.db) as conn:
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (args.username,))
    row = c.fetchone()
    if not row:
        print('User not found')
        raise SystemExit(2)
    c.execute('UPDATE users SET password_hash = ?, salt = ? WHERE username = ?', (hash_hex, salt, args.username))
    conn.commit()
    print(f'Password updated for user {args.username}')
