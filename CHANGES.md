# Changelog

**FluxDrop / Self-Host Server** — changes since last commit

---

## Backend (`server_cdn.py`)

### Bug fixes

- **Fixed expired pending registrations blocking new sign-ups** — the pending
  verification check was missing `AND expires_at > CURRENT_TIMESTAMP`, so any
  unverified registration (e.g. from a lost confirmation email) permanently
  blocked that username/email from being registered again. Now expired rows are
  ignored by the check and automatically deleted when a fresh registration
  replaces them.

- **Fixed SQLite "database is locked" / open-handle overflow** — all DB access
  now goes through a single `_db_connect()` helper that enables WAL journal mode
  (`PRAGMA journal_mode=WAL`) and sets a 15-second lock timeout. WAL allows
  concurrent readers alongside a writer, eliminating the serialisation bottleneck
  that caused handle exhaustion under load.

- **Fixed Python 3.12 `datetime` adapter deprecation warning** — `expires_at`
  is now stored as an ISO 8601 string (`.isoformat()`) instead of a raw
  `datetime` object, removing the deprecation warning and ensuring correct
  comparison with `CURRENT_TIMESTAMP` in SQL queries.

- **Fixed `NameError: BASE_DIR`** — the email icon path was referencing
  `BASE_DIR` which is defined in `config.py` but was never imported into
  `server_cdn.py`. Fixed to use
  `os.path.join(SERVE_DIRECTORY, 'fluxdrop_pp', 'icon.svg')`.

### Email improvements

- **FluxDrop icon now appears in Gmail** — the confirmation email previously
  used an external `<img src="https://...icon.svg">` URL which Gmail blocks.
  The icon is now rasterised to a transparent PNG at send-time using
  `wand`/ImageMagick, then embedded as a CID inline attachment
  (`Content-Disposition: inline` + `X-Attachment-Id` header) so Gmail displays
  it without a "show images" prompt and without showing it as a file attachment.
  SVG is not supported by any major email client — PNG is used instead.

- **Redesigned confirmation email** — new layout matches the FluxDrop site
  header: icon and "FluxDrop" title side-by-side at the same height, blue
  call-to-action button, plain-text fallback included for non-HTML clients.

- **Added `MIMEMultipart` / `MIMEImage` email structure** — replaced single
  `MIMEText('html')` with a proper `multipart/related` → `multipart/alternative`
  hierarchy, which is the correct structure for emails with inline images.

---

## Frontend (`index.html`)

### New features

- **Upload progress tray** — file uploads now show a floating tray in the
  bottom-left corner (mirroring the existing download tray on the bottom-right)
  with a live progress bar, bytes sent / total, current speed (KB/s or MB/s),
  and ETA. The underlying `uploadFormData` function was rewritten from
  `fetch()` (which provides no upload progress) to `XMLHttpRequest` with
  `upload.onprogress` events. HTTP fallback on network error is preserved.

---

## Dev tooling (`sync_to_server.sh`)

- **Switched to SSH ControlMaster** — all `rsync` calls and the final `ssh`
  command now share a single multiplexed connection opened at script start.
  The SSH passphrase is only requested once per run instead of once per
  `rsync` invocation.

- **`RSYNC_OPTS` is now a proper bash array** — was previously a plain string,
  which caused `--exclude` patterns with quotes to be passed incorrectly to
  rsync (shell word-splitting broke them).

- **`secrets/` is now excluded from sync** — live credentials, the SQLite DB,
  and SSL keys in `secrets/` are no longer at risk of being overwritten by a
  sync from a development machine.

- **Removed `ssh-add` logic** — the old script attempted to add the SSH key to
  an agent on every run. The ControlMaster approach makes this unnecessary.
