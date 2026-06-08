# FluxDrop — Module Split Migration Guide

How to divide `server_cdn.py` into logical modules without breaking anything.
This is a pure refactor — no behaviour changes, no new features.

---

## Target layout

```
site/
├── server_cdn.py          # entry point only (~120 lines after split)
├── config.py              # unchanged
├── shared.py              # unchanged
├── db_schema.py           # new — init_db() and all schema SQL
├── db_helpers.py          # new — all non-schema DB utility functions
├── auth_helpers.py        # new — password hashing, session tokens, email
├── handlers/
│   ├── __init__.py        # empty
│   ├── base.py            # new — AuthHandler class definition + core methods
│   ├── auth.py            # new — handle_auth_* methods
│   ├── files.py           # new — handle_fluxdrop_api_*, download, zip, etc.
│   ├── shares.py          # new — handle_share_*, handle_public_share_*
│   ├── uploads.py         # new — handle_upload_session_* + handle_batch_tar_upload
│   ├── trash.py           # new — _handle_trash_*
│   ├── beacon.py          # new — _handle_beacon_*
│   ├── status.py          # new — _handle_status_*, _handle_board_*, net monitor
│   └── catbox.py          # new — handle_catbox_*
└── workers.py             # new — _token_purge_worker, _quota_updater_thread, run_server
```

The `handlers/` sub-package is optional — if you prefer flat files, all the
handler modules can live directly in `site/` alongside `server_cdn.py`.

---

## Step-by-step instructions

All steps below describe moving code with no edits to logic. Do them one module at
a time, restart the server after each, and check the logs before continuing.

---

### Step 1 — Create `db_schema.py`

**What moves:** the entire `init_db()` function (lines 244–502 in the current file).

1. Create `db_schema.py` in the same directory as `server_cdn.py`.
2. Add these imports at the top:
   ```python
   import sqlite3
   import logging
   from db_helpers import _db_connect   # you'll create this in Step 2
   ```
   *(For now you can also just import `_db_connect` from `server_cdn` temporarily
   and fix the circular import in Step 2.)*
3. Cut the entire `init_db` function from `server_cdn.py` and paste it into
   `db_schema.py`.
4. In `server_cdn.py`, replace the cut block with:
   ```python
   from db_schema import init_db
   ```
5. Restart. `init_db()` is called at startup — you'll see the DB migration messages
   as usual if it worked.

---

### Step 2 — Create `db_helpers.py`

**What moves:** `_db_connect` and all the pure DB utility functions that are not
part of the HTTP handler. Specifically:

- `_db_connect` (line 216)
- `_get_upload_notifications` / `_fire_upload_notification` (lines 525–644)
- `_upload_init` / `_upload_get` / `_upload_receive_chunk` / `_upload_assemble` /
  `_upload_session_status` / `_purge_abandoned_upload_sessions` (lines 646–925)
- `_rate_limit` (line 1037)
- `_create_share` / `_get_shares_for_user` / `_get_share_raw` / `_parse_expiry` /
  `_is_share_expired` / `_get_share` / `_update_share` / `_delete_share` /
  `_log_share_access` / `_get_share_stats` (lines 1419–1575)
- `_user_trash_root` / `_trash_*` functions (lines 1576–1725)
- `_is_file_protected` / `_check_token_for_file` / `_mark_file_protected` /
  `_mint_download_token` / `_validate_download_token` / `_update_token_progress` /
  `_purge_expired_download_tokens` (lines 1726–1854)
- `_get_user_disk_usage` / `_get_server_free_bytes` / `_compute_dynamic_quota` /
  `_quota_updater_thread` (lines 6713–6773)

**Imports needed in `db_helpers.py`:**
```python
import os, sqlite3, hashlib, secrets, threading, logging, time, shutil, json
from contextlib import contextmanager
from datetime import datetime, timedelta
from config import DB_FILE, UPLOAD_TMP_DIR
```

In `server_cdn.py`, replace all the moved definitions with:
```python
from db_helpers import (
    _db_connect, _rate_limit, _upload_init, _upload_get, _upload_receive_chunk,
    _upload_assemble, _upload_session_status, _purge_abandoned_upload_sessions,
    _create_share, _get_share, _get_share_raw, _update_share, _delete_share,
    _log_share_access, _get_share_stats, _get_shares_for_user,
    _is_share_expired, _parse_expiry,
    _user_trash_root, _trash_list, _trash_restore, _trash_delete_permanent,
    _trash_purge_expired, _trash_size_used, _move_to_trash, _trash_size_for,
    _trash_retention_days,
    _is_file_protected, _check_token_for_file, _mark_file_protected,
    _mint_download_token, _validate_download_token, _update_token_progress,
    _purge_expired_download_tokens,
    _get_upload_notifications, _fire_upload_notification,
    _get_user_disk_usage, _get_server_free_bytes, _compute_dynamic_quota,
    _quota_updater_thread,
    _chunk_locks, _chunk_locks_mutex, _get_chunk_lock, _release_chunk_lock,
    _assembly_progress_set, _assembly_progress_get, _assembly_progress_clear,
)
```

---

### Step 3 — Create `auth_helpers.py`

**What moves:**
- `_sha256_hash` (line 1855)
- `hash_password` (line 1860)
- `_hash_session_token` (line 2418)
- `_prepare_password` (line 2424)
- `send_verification_email` (line 1871)

**Imports needed in `auth_helpers.py`:**
```python
import hashlib, bcrypt, secrets, base64 as _base64, smtplib, logging, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from config import SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD, PUBLIC_DOMAIN
```

In `server_cdn.py`:
```python
from auth_helpers import (
    _sha256_hash, hash_password, _hash_session_token,
    _prepare_password, send_verification_email,
)
```

---

### Step 4 — Create `workers.py`

**What moves:**
- `run_server` (line 6536)
- `_token_purge_worker` (line 6561)
- The quota constants (`DEFAULT_QUOTA_BYTES`, `QUOTA_MIN_BYTES`, `QUOTA_MAX_BYTES`)
  and `_quota_updater_thread` — move these from `db_helpers.py` here if you prefer
  all thread workers in one place. Your call.

**Imports needed in `workers.py`:**
```python
import os, ssl, logging, threading, time
from http.server import ThreadingHTTPServer
from config import CERT_FILE, KEY_FILE
from server_cdn import HOST, HTTP_PORT, HTTPS_PORT, SERVE_ROOT, AuthHandler
# (or pass these as arguments to run_server — cleaner but more changes)
```

⚠️ **Circular import risk:** `workers.py` needs `AuthHandler`, which lives in
`server_cdn.py`. The safest pattern is to keep `run_server` in `server_cdn.py` for
now and only move the background workers (`_token_purge_worker`,
`_quota_updater_thread`, `_net_monitor_worker`) to `workers.py`. Move `run_server`
last, after the handler split.

---

### Step 5 — Split `AuthHandler` into handler modules (optional, most impactful)

This is the biggest step. The recommended approach is **mixin classes** so you
don't have to touch the routing in `do_GET`/`do_POST`/etc.

**Example — create `handlers/auth.py`:**
```python
# handlers/auth.py
import json, secrets, logging
from datetime import datetime, timedelta
from auth_helpers import hash_password, _hash_session_token, _prepare_password, _sha256_hash
from db_helpers import _db_connect, _rate_limit
import bcrypt

class AuthMixin:
    def handle_auth_register(self, data): ...   # paste method body here
    def handle_auth_login(self, data):    ...
    def handle_auth_logout(self):         ...
    def handle_auth_verify(self, query_string): ...
```

**In `server_cdn.py`, change the class declaration:**
```python
from handlers.auth   import AuthMixin       as _AuthMixin
from handlers.shares import SharesMixin     as _SharesMixin
from handlers.uploads import UploadsMixin   as _UploadsMixin
from handlers.trash  import TrashMixin      as _TrashMixin
from handlers.beacon import BeaconMixin     as _BeaconMixin
from handlers.status import StatusMixin     as _StatusMixin
from handlers.files  import FilesMixin      as _FilesMixin
from handlers.catbox import CatboxMixin     as _CatboxMixin

class AuthHandler(
    _AuthMixin, _SharesMixin, _UploadsMixin, _TrashMixin,
    _BeaconMixin, _StatusMixin, _FilesMixin, _CatboxMixin,
    SimpleHTTPRequestHandler,
):
    # Only the class-level attributes, route patterns, core methods
    # (_send_response, end_headers, _check_token_auth, do_GET, do_POST,
    #  do_PATCH, do_DELETE, do_OPTIONS, do_HEAD, send_head) stay here.
    ...
```

Python's MRO means `self.handle_auth_login(...)` called from `do_POST` works
transparently — no other changes needed in the routing code.

---

## Common pitfalls

**Circular imports** are the main risk. The safe resolution order is:
```
config.py  →  shared.py  →  db_helpers.py  →  auth_helpers.py
                                          ↓
                                     db_schema.py
                                          ↓
                              handlers/*.py (mixins)
                                          ↓
                                   server_cdn.py (AuthHandler + routing)
                                          ↓
                                      workers.py
```
Nothing in `config.py` or `shared.py` should import from the layers above it.

**`SERVE_ROOT` and other runtime globals** — several helper functions reference
`SERVE_ROOT`, `UPLOAD_TMP_DIR`, etc. directly. When you move them to a new module,
import these from `config.py` (they're already there or can be added) rather than
from `server_cdn.py`.

**`_net_monitor_state` and `_net_state_lock`** — these globals are used by both
`_net_monitor_worker` (in the status section) and `_token_purge_worker`. Keep them
in `workers.py` or a `state.py` so both workers can import them without a circular
dependency.

---

## Recommended order

Do one step at a time. Between each step: restart the server, hit a few endpoints,
check the log file for import errors or tracebacks.

1. `db_schema.py` — lowest risk, no cross-dependencies
2. `auth_helpers.py` — small, self-contained
3. `db_helpers.py` — largest single move, but all pure functions
4. Background workers out of `server_cdn.py`
5. Handler mixins, starting with the smallest (`beacon`, `catbox`, `trash`)
6. `run_server` to `workers.py` last

The whole process can realistically be done in a single session, but splitting it
across restarts gives you a safe rollback point at each stage.





*Release note: **Rollout for full HSTS compliance. Phase 1 (failed).***
***Added caching for quota background scan



Ok, can you start to make the patches (with helpers where I need to place/change them exactly, like few reference lines  of original code as boundaries), and, I think about how I can use subfolder for the modules of CDN since right now, HTTP/HTTPS hosters (for static files) are in the same folder with CDN, so it'll be a lot of files, so I think about using /modules/​ as place where I can move the modules from main server_cdn.py 