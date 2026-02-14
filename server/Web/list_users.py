#!/usr/bin/env python3
"""
List users in the FluxDrop users DB.
Usage: python list_users.py [--db path]
"""
import sqlite3
import argparse
from config import DB_FILE

ap = argparse.ArgumentParser()
ap.add_argument('--db', help='Path to database file', default=DB_FILE)
args = ap.parse_args()

conn = sqlite3.connect(args.db)
c = conn.cursor()
c.execute('SELECT id, username, nickname, email, created_at FROM users')
rows = c.fetchall()
if not rows:
    print('No users found in', args.db)
else:
    for r in rows:
        print(f'id={r[0]} username={r[1]} nickname={r[2]} email={r[3]} created_at={r[4]}')
conn.close()
