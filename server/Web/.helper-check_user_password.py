#!/usr/bin/env python3
"""
Check a username/password against the users table using the server's hashing.
Usage: python check_user_password.py --username USER --password PASS [--db path]
"""
import argparse
import sqlite3
import hashlib
from server_cdn import hash_password
from config import DB_FILE

ap = argparse.ArgumentParser()
ap.add_argument('--username', '-u', required=True)
ap.add_argument('--password', '-p', required=True)
ap.add_argument('--db', help='Path to DB file', default=DB_FILE)
args = ap.parse_args()

with sqlite3.connect(args.db) as conn:
    c = conn.cursor()
    c.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (args.username,))
    row = c.fetchone()
    if not row:
        print('User not found')
        raise SystemExit(2)
    user_id, stored_hash, salt = row
    computed_hash, _ = hash_password(args.password, salt)
    print('user_id:', user_id)
    print('stored_hash:', stored_hash)
    print('salt:', salt)
    print('computed_hash:', computed_hash)
    if computed_hash == stored_hash:
        print('MATCH: password is correct')
    else:
        print('NO MATCH: password incorrect')
