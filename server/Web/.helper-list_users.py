#!/usr/bin/env python3
"""
List users in the FluxDrop users DB.
Usage: python .helper-list_users.py [--db path]
"""
import argparse
import sqlite3
from config import DB_FILE

ap = argparse.ArgumentParser()
ap.add_argument('--db', help='Path to database file', default=DB_FILE)
args = ap.parse_args()

conn = sqlite3.connect(args.db)
# is_admin / quota_* were added by a later migration (core/db.py) — fall back
# to the base columns on a DB the server hasn't started against yet.
cols = {r[1] for r in conn.execute('PRAGMA table_info(users)')}
extra = [c for c in ('is_admin', 'quota_bytes', 'quota_override') if c in cols]
rows = conn.execute(
    'SELECT id, username, nickname, email, created_at'
    + ''.join(f', {c}' for c in extra) + ' FROM users ORDER BY id'
).fetchall()
if not rows:
    print('No users found in', args.db)
else:
    for r in rows:
        line = f'id={r[0]} username={r[1]} nickname={r[2]} email={r[3]} created_at={r[4]}'
        for name, val in zip(extra, r[5:]):
            line += f' {name}={val}'
        print(line)
conn.close()
