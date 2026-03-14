# FluxDrop — Security & Code Audit v3
*Covers: `server_cdn.py`, `server_http.py`, `server_https.py`, `shared.py`, `config.py`,*
*`_helper-check_user_password.py`, `_helper-generate_token.py`, `_helper-set_user_password.py`*
*Supersedes audit v2. All v2 items are resolved unless explicitly carried forward.*

---

## Summary table

| # | Issue | Severity | File(s) |
|---|-------|----------|---------|
| **A1** | `_rl_attempts` dict grows unbounded in memory | 🟡 Medium | `server_cdn.py` |
| **A2** | `share_access_log` table never pruned | 🟡 Medium | `server_cdn.py` |
| **A3** | Helper scripts still use SHA-256 for credential verification | 🟡 Medium | `_helper-*.py` |
| **A4** | `handle_upload_session_init` JSON body read without size cap | 🟡 Medium | `server_cdn.py` |
| **A5** | `handle_public_share_upload` has no per-file size limit | 🟡 Medium | `server_cdn.py` |
| **A6** | Verbose `_check_token_auth` success log on every authenticated request | 🟢 Low | `server_cdn.py` |
| **A7** | `_dd_check_google()` scrapes HTML — fragile and leaks timing data | 🟢 Low | `server_cdn.py` |
| **A8** | `handle_upload_session_complete` re-hashes entire file into RAM for files < 500 MB | 🟢 Low | `server_cdn.py` |
| **A9** | `handle_public_share` folder page embeds raw `repr()` of Python string in JS | 🟢 Low | `server_cdn.py` |
| **A10** | `message_board` table never pruned | 🟢 Low | `server_cdn.py` |

---

## Part 1 — Resolved items from v2

All 14 items from v2 are confirmed fixed in the uploaded code:

- **N7** `quote_plus` import fixed ✅
- **N8** `/upload` stub removed ✅
- **N1** Blacklist refresh thread started in CDN ✅
- **N2** Blacklist guard on `do_PATCH` / `do_DELETE` / `do_OPTIONS` ✅
- **N4** `secrets.compare_digest` used for SHA-256 path ✅
- **N3** Token truncated to 8 chars in failed-auth log ✅
- **N9** `os.chdir()` race fixed in both HTTP servers ✅
- **N12** Input length validation on registration fields ✅
- **N5** `pending_verifications` periodic purge ✅
- **N6** `net_outages` / `incident_log` periodic pruning ✅
- **6** bcrypt migration with transparent SHA-256 upgrade-on-login ✅
- **N11** `captcha_challenges` TTL eviction ✅
- **N10** `ssl._create_unverified_context()` replaced with public API ✅
- **7** `localhost` removed from `ALLOWED_ORIGINS` ✅
- **datetime.utcnow()** deprecation warning fixed ✅

---

## Part 2 — New findings

---

### 🟡 A1 — `_rl_attempts` dict grows unbounded

```python
# server_cdn.py ~line 702
_rl_attempts: dict[str, list[float]] = collections.defaultdict(list)
```

The rate-limiter correctly prunes old timestamps from each bucket's list on
every call, but it **never removes the key itself**. A unique IP that hits one
endpoint once creates a permanent entry. After months of running and receiving
probes from thousands of unique IPs, the dict can hold tens of thousands of
empty lists.

**Fix — after pruning timestamps, delete the key if the list is now empty:**

```python
def _rate_limit(ip: str, bucket: str = "auth", max_hits: int | None = None) -> bool:
    limit = max_hits if max_hits is not None else (_RL_MAX_AUTH if bucket == "auth" else _RL_MAX_API)
    key   = f"{bucket}:{ip}"
    now   = time.monotonic()
    with _rl_lock:
        ts = _rl_attempts[key]
        _rl_attempts[key] = [t for t in ts if now - t < _RL_WINDOW]
        if not _rl_attempts[key]:          # ← add this
            del _rl_attempts[key]          # ← evict empty bucket
            if max_hits is None or len([]) < limit:
                _rl_attempts[key] = []
        if len(_rl_attempts[key]) >= limit:
            return False
        _rl_attempts[key].append(now)
        return True
```

Or more cleanly — check length before appending:

```python
with _rl_lock:
    now = time.monotonic()
    key = f"{bucket}:{ip}"
    recent = [t for t in _rl_attempts.get(key, []) if now - t < _RL_WINDOW]
    if len(recent) >= limit:
        if recent:
            _rl_attempts[key] = recent
        else:
            _rl_attempts.pop(key, None)
        return False
    recent.append(now)
    _rl_attempts[key] = recent
    return True
```

---

### 🟡 A2 — `share_access_log` grows without bound

Every file download, preview, embed, and folder visit writes a row to
`share_access_log`. The table has no TTL, no row-count cap, and no pruning
code anywhere in the codebase. The stats endpoint only reads the 100 most
recent rows (`_get_share_stats` uses `LIMIT 100`), so rows beyond that are
invisible to users but still accumulate on disk indefinitely.

**Fix — add pruning to `_token_purge_worker` (keep 90 days, consistent with
status_snapshots retention):**

```python
# In _token_purge_worker, alongside N5/N6 pruning:
try:
    with _db_connect() as conn:
        conn.execute(
            "DELETE FROM share_access_log WHERE accessed_at < datetime('now', '-90 days')"
        )
        conn.commit()
except Exception:
    logging.exception('TokenPurge: failed to prune share_access_log')
```

---

### 🟡 A3 — Helper scripts bypass bcrypt and use raw SHA-256

Three helper scripts still hardcode the old SHA-256 path:

**`_helper-check_user_password.py`** — imports `hash_password` from
`server_cdn` (so it does use bcrypt), but the comparison at the end uses `==`
on the result:
```python
computed_hash, _ = hash_password(args.password, salt)   # bcrypt — salt ignored
if computed_hash == stored_hash:   # ← broken: bcrypt produces a different hash each call
```
`bcrypt.hashpw` with a new salt always produces a different output — this will
**always print "NO MATCH"** for bcrypt users, because it hashes with a fresh
random salt instead of using `bcrypt.checkpw` to verify against the stored one.

**`_helper-generate_token.py`** — uses raw SHA-256 directly to verify
credentials before minting a file token:
```python
candidate_hash = hashlib.sha256((salt + args.password).encode('utf-8')).hexdigest()
if candidate_hash != stored_hash:   # broken for migrated bcrypt users
```
This will reject valid passwords for any user who has already migrated to bcrypt.

**`_helper-set_user_password.py`** — sets passwords using SHA-256, bypassing
the bcrypt migration entirely:
```python
salt = secrets.token_hex(16)
hash_hex = hashlib.sha256((salt + args.password).encode('utf-8')).hexdigest()
```
Any password set via this tool will be a SHA-256 hash. It will still work at
login (via the legacy path), but defeats the purpose of the migration for
admin-reset accounts.

**Fix for all three — use the server's own functions:**

```python
# _helper-check_user_password.py
import bcrypt
if stored_hash.startswith('$2b$'):
    ok = bcrypt.checkpw(args.password.encode('utf-8'), stored_hash.encode('utf-8'))
else:
    import hashlib, secrets as _s
    ok = (hashlib.sha256((salt + args.password).encode('utf-8')).hexdigest() == stored_hash)
print('MATCH' if ok else 'NO MATCH')

# _helper-generate_token.py  — replace the SHA-256 verify block with the same pattern above

# _helper-set_user_password.py — use hash_password from server_cdn
from server_cdn import hash_password
new_hash, new_salt = hash_password(args.password)
# then UPDATE ... SET password_hash=new_hash, salt=new_salt
```

---

### 🟡 A4 — `handle_upload_session_init` reads JSON body without a size cap

```python
# server_cdn.py handle_upload_session_init():
length = int(self.headers.get('Content-Length', 0))
data   = json.loads(self.rfile.read(length))
```

Every other JSON-body endpoint checks `content_len > MAX_JSON_BODY` (1 MB)
before reading. This one does not. A client can declare a `Content-Length` of
several hundred megabytes and the server will attempt to read and JSON-parse
the entire stream.

**Fix — add the standard guard before the read:**

```python
length = int(self.headers.get('Content-Length', 0))
if length <= 0 or length > MAX_JSON_BODY:
    return self._send_response(400, json.dumps({'error': 'Invalid or missing request body.'}))
data = json.loads(self.rfile.read(length))
```

---

### 🟡 A5 — `handle_public_share_upload` has no per-file size limit

The chunked upload path (`handle_upload_session_chunk`) enforces
`content_length > UPLOAD_CHUNK_SIZE * 2` (50 MB per chunk). The legacy
multipart form upload used by the share page's "Upload" button has no such
guard:

```python
# server_cdn.py handle_public_share_upload():
with open(save_path, "wb") as f:
    while True:
        chunk = file_item.stream.read(1 * 1024 * 1024)
        if not chunk: break
        f.write(chunk)
```

An anonymous visitor with access to an upload-enabled share can fill the
disk by uploading an arbitrarily large file.

**Fix — add a byte counter inside the write loop:**

```python
MAX_SHARE_UPLOAD = int(os.getenv('MAX_SHARE_UPLOAD_BYTES', str(500 * 1024 * 1024)))  # 500 MB default

written = 0
with open(save_path, "wb") as f:
    while True:
        chunk = file_item.stream.read(1 * 1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > MAX_SHARE_UPLOAD:
            f.close()
            os.remove(save_path)
            return self._send_response(413, json.dumps({'error': 'File too large.'}))
        f.write(chunk)
```

---

### 🟢 A6 — `_check_token_auth` logs success on every authenticated request

```python
logging.info(f"Token auth success for user_id '{result[0]}'")
```

This fires for every single authenticated API call — file list, download
token mint, chunk upload, etc. At moderate usage this floods the log file
with hundreds of INFO lines per minute that have no diagnostic value, making
it harder to spot real events.

**Fix — remove the success log line entirely, or drop it to DEBUG:**

```python
logging.debug(f"Token auth success for user_id '{result[0]}'")
```

---

### 🟢 A7 — `_dd_check_google()` is a fragile HTML scrape

```python
body = r.read(8192).decode('utf-8', errors='ignore').lower()
return ('problems at google' in body or 'user reports indicate' in body)
```

DownDetector can change its wording or page structure at any time, silently
making this check always return `False`. More importantly, this outbound
HTTPS request happens during a connectivity outage — if the network is
actually down, it will always fail (correctly returning `None`), but if the
network is merely degraded, the 5-second timeout adds latency to the outage
detection loop and generates misleading log noise.

It's also an undisclosed dependency on a third-party service that has no SLA
and may block scrapers. Consider removing the DownDetector check entirely and
relying solely on the two DNS probes, or replacing it with a documented public
API if one is needed.

---

### 🟢 A8 — Post-assembly SHA-256 re-reads entire file into RAM

```python
# server_cdn.py handle_upload_session_complete():
with open(dest_path, 'rb') as f:
    sha256 = hashlib.sha256(f.read()).hexdigest() if size < 500 * 1024 * 1024 else 'skipped (>500MB)'
```

`f.read()` on a 499 MB file allocates a 499 MB byte string in RAM on the
handler thread. Under concurrent uploads this can spike memory significantly.
The whole-file SHA-256 is **already computed incrementally during assembly**
in `_upload_assemble()` and returned; the response value from that function
could simply be passed through rather than recomputed.

**Fix — return the hash from `_upload_assemble` and use it directly:**

```python
# _upload_assemble() already computes actual_sha256 — return it:
return dest_path, actual_sha256

# In handle_upload_session_complete:
dest_path, sha256 = _upload_assemble(upload_token)
```

---

### 🟢 A9 — `repr()` of user-controlled string injected into inline JavaScript

```python
# server_cdn.py handle_public_share() — share folder page upload section:
const _CURRENT_SUBPATH = {repr(sub_path_clean)};
```

`repr()` is Python's debug serialiser — not a JavaScript escaper. For
well-formed ASCII paths it happens to produce valid JS string literals, but
a path containing a single quote, backslash, or Unicode outside ASCII can
break the JS syntax or, in a worst case, allow a visitor who can create
subfolders with crafted names to inject script.

**Fix — use `json.dumps()` which produces a proper JSON/JS string literal:**

```python
const _CURRENT_SUBPATH = {json.dumps(sub_path_clean)};
```

---

### 🟢 A10 — `message_board` table never pruned

Admin posts to `message_board` are never deleted automatically (only manually
via the DELETE endpoint). In normal use the board stays small, but it should
be bounded for consistency.

**Fix — add to `_token_purge_worker` alongside the other pruning:**

```python
try:
    with _db_connect() as conn:
        conn.execute(
            "DELETE FROM message_board WHERE id NOT IN "
            "(SELECT id FROM message_board ORDER BY id DESC LIMIT 100)"
        )
        conn.commit()
except Exception:
    logging.exception('TokenPurge: failed to prune message_board')
```

---

## Priority order

| Priority | Item | Effort |
|----------|------|--------|
| 🟡 1 | **A3** — Fix helper scripts for bcrypt compatibility | ~30 lines across 3 files |
| 🟡 2 | **A4** — Add JSON body size cap to `handle_upload_session_init` | 2 lines |
| 🟡 3 | **A5** — Add per-file size limit to `handle_public_share_upload` | ~10 lines |
| 🟡 4 | **A1** — Evict empty buckets from `_rl_attempts` | ~5 lines |
| 🟡 5 | **A2** — Add `share_access_log` pruning to purge worker | 3 lines |
| 🟢 6 | **A9** — Replace `repr()` with `json.dumps()` in inline JS | 1 line |
| 🟢 7 | **A8** — Avoid re-reading assembled file for SHA-256 | ~5 lines |
| 🟢 8 | **A6** — Demote `_check_token_auth` success log to DEBUG | 1 line |
| 🟢 9 | **A10** — Add `message_board` pruning to purge worker | 3 lines |
| 🟢 10 | **A7** — Remove or replace fragile DownDetector HTML scrape | Design decision |

---

## Things still done well

All positives from v2 remain valid:

- No RCE vectors, no `eval`/`exec`/`subprocess` on user input.
- Parameterised SQL throughout — no SQL injection risk.
- Path traversal defended consistently with `os.path.realpath().startswith()`.
- `/FluxDrop/` hard-blocked from direct URL access.
- Session tokens use `secrets.token_urlsafe(32)`.
- Cross-user access checked on every API endpoint.
- CORS origins whitelisted with `Allow-Credentials` scoped to known hosts only.
- bcrypt migration now in place with transparent upgrade on login.
- Per-chunk and whole-file SHA-256 integrity verification on chunked uploads.
- Download tokens are short-lived and path-scoped; session token never appears in download URLs.
- `X-Anon-Device-Token` for anonymous share uploads uses `secrets.compare_digest`.
- WAL journal mode with 15 s lock timeout.
- Background purge worker with exponential backoff on DB unavailability.
- Admin privilege verified server-side via `is_admin` column on every admin endpoint.
