# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

Work is ordered by phase: priority fixes first, then backend, then the API V2
groundwork, then the frontend V2 (FE V2) rewrite.  Items inside a phase are
roughly ordered by priority (top = first).

Items marked "needs testing" are collected as a checklist in
[TESTING.md](./TESTING.md).

---

## Rules

- Do NOT implement breaking features into the patch versions (e.g. V0.19.2 over
V0.19.1), add them to the "API V2" phase instead (allowed in V0.20 over V0.19)
- Starting from V0.21.0.5, the commits may start to have only 1 change per
commit, if this practice will be better than current mix
- Frontend V1 (current UI): keep fixing bugs; new features may still be added,
but with low effort (not "pretty") -- FE V2 should have everything unified and
pretty
- API V2 is added next to API V1, V1 endpoints stay for legacy purposes (they
are used in a lot of places, switching fully to V2 may take a long time)

### Versioning

Under breaking changes are:
- API changes
- Function changes (e.g. function starts to output or request different inputs)
- Features that will be replaced with new ones, dropping old ones
- Overall incompatible code changes between versions

Those features should be added as `y` increment in `Vx.y.z`. Full backend code
changes should be added as `x` increment in `Vx.y.z`. Other changes that can be
used without changes in API or external dependencies can be added as `z`
increment in `Vx.y.z`

Overall thought: increment `y` if API responces or requests are changed to the
point where older listener code can't do anything with (e.g. renaming the
variables, tables, etc.)

---

## Phase 0 -- Priority fixes (non-breaking, current version line)

- [x] Backend doesn't always save all received chunks: after pausing the
upload, a chunk that was successfully sent may not be saved (unACK issue?).
Not related to internet conditions AFAIK; recheck after the recent proxy fixes
(may affect only Immich over WebSocket, or regular HTTP too)
  - Cause found in the client, fixed, needs testing: on pause, workers
  that weren't mid-send waited instead of exiting, so Resume started a
  second run from the highest chunk taken while the old run woke up too;
  chunks in between could be skipped ("Missing chunks" on complete). Now
  chunks come from a queue, Resume asks `/status` for the missing ones, and
  the client re-checks `/status` before `/complete` -- tested on the live
  server (pause/resume, quick pause/resume, pause during a retry)
- [x] Not always UI cancels the upload (says "Cancelling..." and does nothing)
  - Cause found, fixed, needs testing: Cancel on a *paused* upload never
  sent the DELETE or left the "cancelling" state, since the paused run had
  already ended. Also, pausing during a chunk retry cancelled the upload
  -- tested on the live server
- [x] Trash bin: file preview inside trashed folders (`/api/v1/trash/<id>/list`
exists, but `/api/v1/trash/<id>/file` rejects folders -- needs a sub-path
parameter with the `_is_within()` containment check)
  - Done, needs testing: `/trash/<id>/file?path=<sub/path>` (checked with
  `_is_within()`); files in the "Browse" tree are clickable and open the
  preview. The tree is now nested properly and escapes file names -- tested
  on the live server (incl. the `../..` path check → 403)
- [ ] ZIP download:
  - [ ] Cancel the file hashing, or avoid the multithreaded file hash after
  canceling the ZIP download, or do it only if server is unused or via `nice`
  - [ ] Lock the job so the worker never re-reads the same folder and no new
  worker is spawned for the same job
  - [ ] If the client ping is missing for 3+ seconds or the client cancels:
  stop the worker, put the files to a pending list, keep computed hashes
  - Done, needs testing: one job per folder+user (a 2nd request or Resume
  joins it); Cancel sends `DELETE /api/v1/zip_status/<job>`; no poll for
  `ZIP_JOB_IDLE_STOP` (20 s, not 3 -- background tabs throttle timers) stops
  the job, even mid-file; hashes done so far stay stored, and polling the job
  again continues from the file it stopped at
- [x] Do not make speed probe for small files (e.g. less than 25 MB) -- not if
internet is bad -- if so, needs changes in how the chunks are calculated, maybe
a dynamic chunk size based on the upload speed
  - Done, needs testing: files under 25 MB skip the probe; they reuse the
  speed of an upload finished in the last 10 min, or else use 1 MB chunks
  (safe for the 90 s chunk timeout on a bad connection) -- tested
- [ ] Check the upload concurrency behavior on weak connections
- [ ] Publish Privacy Policy and Terms of Service v0.1.0: set up
`privacy@fluxdrop.me`, fill in `[CONTACT EMAIL]`, the email provider and the
effective date, then bump `policies/versions.json`

## Phase 0 -- Frontend V1 fixes (low effort)

- [ ] File preview modal may blink with light when it doesn't keep up when file
loads/decodes
  - Likely cause found, fixed, needs testing: PDF previews were an iframe with
  a white background, shown before the PDF viewer painted. Now dark and faded
  in once loaded. If it also happens with other types, note which
- [x] `ap-body`'s spinning wheel is still spinning in background (not visible
but Animations debugger sees it) -- confirmed fixed on the live server
  - It's the boot loader (`fd-boot-spin`) left in `#app-root`. Safety net
  added (removed once anything else appears in `#app-root`); the render path
  that skipped it is still unknown -- needs testing
- [ ] Hide file selector (`fd-sel-bar`) for the mobile version if no keyboard
is present
  - Done, needs testing: hidden on touch-only devices (no fine pointer and
  no hover anywhere); multi-item actions stay in the long-press menu
- [ ] Add animation for file copy when task is executed (button pressed)
- [ ] Info panel title showed 📁/📄 like an item name -- now ℹ️ (V0.22.0.30),
needs testing
- [ ] Profile menu opened under the Info panel -- opening it now closes the
panel (V0.22.0.30), needs testing
- [ ] Selection bar items were on separate lines (V0.22.0.25 regression) --
fixed V0.22.0.30, needs testing
- [ ] Dark mode buttons too light for white text (~2.5:1) -- now `#2563eb`
(~5.2:1, WCAG AA) in V0.22.0.30, needs testing; the selection bar's Trash /
Clear are red / grey again in dark mode
- [ ] Add loading wheels/bars to:
  - [ ] Stats button for shared links manager -- Done, needs testing
  - [ ] Profile infos -- Done, needs testing (quota card and account line)
- [ ] Fix i18n in error-related pages -- share expired / not found / login
pages are translated on the server since V0.22.0.20; needs testing

---

## Phase 1 -- Backend hardening and groundwork (non-breaking)

- [ ] Make separate "testing" server where I would be able to test everything
before pushing to the real one (needed before the FE V2 rewrite)
- [x] Add code map -- `CODEMAP.md` (+ the module index in `server_cdn.py`)
- [x] Check code for security flaws/vulnerabilities -- audit v8, covering
everything since V0.20.0.21 (see `fluxdrop_audit.md`, incl. the cadence:
focused review each `y` bump, full read each `x` bump or ~6 months)
  - [ ] B8: HSTS -- it never reached browsers (B23, fixed V0.22.0.30, now
  1 week); raise `HSTS_MAX_AGE` to `31536000` after a month of clean
  certificate renewals (around 2026-12-10)
  - [ ] B9: drop `unsafe-inline` from CSP -- done by FE V2 (no inline scripts)
- [ ] Use the background hashsums for silent file check activity in
background -- specifiable time period in server config
  - [ ] Add parchives to avoid file damages on server
  - [ ] Add some kind of messages if files got corrupted on server side and
  were unrecoverable
  - Done, needs testing: scrub in the background scanner
  (`INTEGRITY_SCRUB_DAYS`/`_MAX_GB`), `file_integrity_issues` table, emails
  to the operator and the owner (in their language), warning in the Info
  panel. Parity (par2) still to do
- [x] Fix CSP for used domain other than `PUBLIC_DOMAIN` (e.g. accessing
FluxDrop from fluxdrop.me, and it loads the link relative to arseniusgen.uk.to
as specified in `PUBLIC_DOMAIN`)
  - Done, needs testing: FluxDrop lives on `PUBLIC_BASE_URL` (fluxdrop.me);
  on `FLUXDROP_LEGACY_HOSTS` (arseniusgen.*) its pages, shares and API are
  308-redirected there (plain HTTP: app pages only; `/beacon` never) --
  tested on the live server
- [x] Port settings clash: `server_cdn.py` and the front servers
(`server_http.py`, `server_https.py`) read the same `HTTP_PORT` /
`HTTPS_PORT` names, and all of them load `vars.env` -- setting them there
makes two servers bind one port. Give the front servers their own names
(e.g. `FRONT_HTTP_PORT` / `FRONT_HTTPS_PORT`, keeping the old fallbacks)
  - Done: `FRONT_HTTP_PORT` / `FRONT_HTTPS_PORT` are read first (sample,
  README and wiki updated). Still open: `server_http.py` builds its HTTPS
  redirects from config's `HTTPS_PORT` (the CDN's, 64800 by default) --
  check that this is intended
    - Fixed (V0.22.0.9): redirects use the host and port of
    `PUBLIC_BASE_URL` (prod: fluxdrop.me:443), also for `/api/` and `/auth/`
- [ ] Remove `wand` and `requests` from `requirements.txt` (nothing imports
`wand` since the email icon moved to Pillow, so ImageMagick isn't needed;
`requests` was only used by the CatBox `urlupload`, now disabled)
  - Done (`bcrypt` comment fixed too); the server venv can drop them with
  `pip uninstall wand requests`
- [ ] CatBox API: better limits before it's used for real (per-IP rate limit
and daily volume for anonymous uploads, retention/expiry for anonymous files,
counting against quota for signed-in users); kill switch
`CATBOX_API_ENABLED` exists
  - Done, needs testing: `CATBOX_ANON_PER_MIN` / `_DAILY_MB` /
  `_RETENTION_DAYS`; signed-in uploads checked against quota (incl. their
  existing CatBox files); owners recorded in `catbox_uploads`
- [ ] Archive preview (`/api/v1/archive_tree`): a 1.6 GB `.tar.gz` gives
HTTP 502 -- gzip has no index, so listing decompresses the whole file, and
the proxy gives `/api/` 10 s; the CDN keeps working after the proxy gave up.
  - [ ] Cache the listing (key: path + size + mtime), outside the quota
  - [ ] Build it in a single low-priority background worker; return
  `202 pending` with progress, the UI polls; pre-warm after upload completes
  - [ ] Zip-bomb limits: stream headers with `tarfile` `r|gz` + `next()`
  instead of `getmembers()`, cap entries (mark as truncated), cap the
  decompressed/compressed ratio and the time per job; cap ZIP entries too
  - Done, needs testing (`core/archive_tree.py`): all of the above, with
  the cache in `secrets/archive_tree_cache`; the preview shows progress and
  a "truncated" note. Tested locally with tar.gz, zip, a plain .gz and two
  gzip bombs; on the live server the 1.6 GB archive, the cache and zip
  previews work. Still to test: pre-warm after upload
- [x] Upload session purge (`core/upload.py`) compares naive local
`datetime.now()` with the UTC `last_activity` -- sessions are purged 2-3 h
early (same class of bug as audit B14)
  - Done: compares in UTC -- verified live: a session idle since
  2026-11-03 15:27 was purged 2026-11-05 15:31 (48 h TTL)
- [ ] Use separate email for FluxDrop
- [ ] Send emails in the user's locale
  - Done, needs testing: `users.lang` (from the app/browser at sign-up,
  then synced from the app's language switch via `PATCH /api/v1/me`);
  verification and upload-notification emails use it. Report emails to the
  operator stay English
- [ ] Update the services (and exclude the entry in the `.gitignore`)
  - Done: unit files match the live ones; the `webserver-https` memory
  drop-in (`webserver-https.service.d/override.conf`) is in the repo now;
  `ip_beacon.service` points at https://fluxdrop.me. The friend's site
  moved away: its `.gitignore` entries and routes are gone (V0.22.0.30).
  Left on the server, needs `sudo`: stop/disable/remove
  `tilesna_api.service`, delete `Web/tilesna_api.py`, `TestWeb/tilesna_practyka`
- [x] Document the new proxy method that is currently used with my Immich
instance -- wiki: Deployment → "Proxying another service"
  - Found while documenting, fixed: plain-HTTP `/api/` and `/auth/` requests
  to other subdomains (e.g. `http://gallery…/api/`) were redirected to
  FluxDrop's host; now to HTTPS on their own name
- [ ] Hash uploads while they arrive instead of re-reading the file after
  assembly (28 GB took ~13 min at ~35 MB/s on the i3, V0.22.0.40 shows
  "Calculating after upload…" meanwhile). Chunks can arrive out of order
  and in parallel, so: feed CRC32 + SHA-256 for chunks in order, park
  early ones until the gap fills (or fall back to the current re-read if
  it grows too big); a resumed session after a restart also falls back.
  The post-upload pass stays cheaper overall only if the extra reads are
  what hurts — measure CPU first, the hash itself is most of the cost.
  Optional: the browser could also send `sha256_final` (the API already
  checks it), but hashing 30 GB in JS is slow, so only as an opt-in

---

## Phase 2 -- API V2 (breaking, next to API V1)

- [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths;
background copy jobs already exist)
- [ ] Server-side filename sanitisation for illegal characters
- [ ] Reimplement the CDN path purpose, fix its errors: per-user CDN hosting
(upload files into a folder and link them from your own page; hosting a whole
page is possible, but should be a separate service using FluxDrop as API)
  - Model: personal space (private) / **public space** (per user, separate
  from personal files, everything public at stable links like
  `/p/<user>/...`, more management options) / CatBox (anonymous API
  uploads, no main button — a "My CatBox uploads" list in the profile once
  the API is back on)
  - Public space only for users with `can_publish` (admin-granted; later a
  subscription tier). The share "Allow CDN" option stays and uses the same flag
  - Serve user content (public space, CDN embeds, CatBox, inline previews)
  from a separate domain (e.g. `usercontent.fluxdrop.me`) so it can never
  reach the app's login; `CSP: sandbox` covers it until then
  - Remove the legacy global `CDN_UPLOAD_DIR` (admin-only since V0.22.0.19)
  - Abuse safeguards: admin "disable share" / "suspend user" from a report,
  a cap on shares per user, rate limits on share traffic
- [ ] "Shared with me" and "Recent" (Links / Files and folders) in the app:
a private per-user list of opened shares (not the owner's access log), shown
in the normal file table via an additive JSON share listing API; old
`/share/...` pages stay as the no-JS version
- [ ] Dynamic page building support (shared header/footer, changing body)
- [ ] Add proper account disable and deletion, GDPR compliance -- admin-side
deletion with a 30-day file purge is done; still missing:
  - [ ] Self-service deletion from the profile
  - [ ] Data export ("Download everything as a ZIP")
- [ ] Share access statistics: decide on the default (currently on) and
whether owners should see visitors' usernames or just "signed-in user"
- [ ] Add a way to track IPs, auths, etc. -- special admin page for specific
usages, for example the abuse
- [ ] Backend for the new FE V2 pages: support tickets, reviews, blogs

---

## Phase 3 -- Frontend V2 (full rewrite)

### Shell
- [ ] Proper header and footer
- [ ] Redesign the login page and the "session expired" state
- [ ] Language switch UK → EN doesn't update dialogs that are already open
(the page auto-translates English text one way only; open dialogs would
have to be rebuilt). FE V2: render every text through t() and re-render on
language change
- [ ] Login with Google (OAuth; link to an existing account by verified
email)
- [ ] Dynamic page building (footer and header are shared, the body is
different, if it's blogs - text of the blogs are changing, etc.)
- [ ] Divide snippets to dedicated HTML, JS and CSS (no inline scripts/styles)
- [ ] Add some animation to the main file browser from the landing page

### File manager
- [ ] Fixed by size main modal with overflow buffer inside it, to make a
slide-in animation for the `fd-sel-bar` (slide down with some part of the UI)
- [ ] Rework the `btn-toolbar-toggle` to become as mini modal (aka menu) with
options
- [ ] Keyboard navigation of the file list: rows are clickable but not
focusable (Firefox a11y check "keyboard"); the name and ⋮ buttons inside
are reachable by Tab. Proper fix: a grid with arrow keys (roving tabindex)
- [ ] AJAX-like updates (no visual reloads of the content)
- [ ] Multiple files streaming (archive and stream to the server; one stream -
a lot of files) from `batch_tar_upload.py`
- [ ] Multithreaded file upload (2+ files processing simultaneously)
- [ ] Mobile version as an installable app via Chrome (PWA) or as "native"
Android Material Design one

### Previews
- [ ] `.7z`, `.rar` and other archive types for file table previews
- [ ] `.docx`, `.pptx`, `.odt`, `.odf`, `.ods`, and other office formats
- [ ] `.dng` and other raw image formats
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds
on i5 8350U) -- may be solved by server-side thumbs (Phase 4)

### New pages
- [ ] "Landing page" for CatBox API to use it from the browser, and "CatBox
API usage" page
- [ ] Blogs page
- [ ] Support page (tickets system)
- [ ] Reviews
- [ ] MIDI and modules player (tracker music). Inspired by modarchive.org

---

## Phase 4 -- Long-term

- [ ] **Encryption of stored files** (today: none, HTTPS only — README and
  PP draft say so). Three levels, can be combined:
  1. *At rest, key on the server* (LUKS on the storage drive, or per-file
     AES with a key in `secrets/`): protects a stolen disk / leaked backup,
     **not** against the operator or a server order — the key is there.
     Cheap, nothing in the app changes.
  2. *Key derived from the password* at login: no key at rest, but the
     server sees the password and holds the key in memory while you're
     signed in; shares/CDN/previews need it too. Little real gain over 1.
  3. **End-to-end "vault" folders (opt-in)**: the browser encrypts with a
     key from a passphrase the server never sees (WebCrypto: PBKDF2/Argon2
     → AES-GCM per upload chunk, fits the chunked upload), the server stores
     ciphertext only, downloads decrypt in the browser (stream through
     `sw.js`). Share links carry the key in the URL `#fragment` (never sent
     to the server, like Mega). Costs: no server previews / thumbnails /
     ZIP / CDN embed / checksum of the real content for vault files; lost
     passphrase = lost files (no reset); reports on vault shares can only
     be judged from what the reporter shows. TOS §(encrypted files) and PP
     need updating; a server order could only produce ciphertext.
  Decided (2026-11-12): 1 and 3. 1 waits for a spare drive (needs room to
  move all files over without downtime); 3 as a FE V2 feature with its own
  design doc — it needs no migration, only new vault folders are encrypted.

- [ ] Photo contest (annual) with subscription tiers as prizes — after
subscriptions exist; better as a separate service on the FluxDrop API
- [ ] cRes ("Access cached resources for fast!") as a separate service on top
of the FluxDrop API: download an external URL into the user's storage, so it
uses the server's bandwidth. Replaces the disabled CatBox `urlupload`. Must
use an SSRF-safe fetch (public IPs only, re-checked on every redirect -- see
`core/notifications.py`), a timeout, a size cap and quota, and no automatic
Brotli decoding of untrusted responses (HTTP2Shell, CVE-2026-111497)
- [ ] "Enhanced" previews: background FFmpeg thumbs for any supported file
type (incl. JPEG/WebP versions of AVIF, HEIF, etc.), thumbs can be included
into the quota, or excluded from quota
- [ ] Special player with "video preview support", aka "slow internet mode"
(re-convert the uploaded videos with AV1 to reduce bandwidth and resolution)
- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
  read/write privileges
  - [ ] Add settings to control whether group members may add/remove other
  users, set quotas, etc.
- [ ] Add checkers for external HTTP and HTTPS hosters for outage page
- [ ] Migration to other host platform for HTTP and HTTPS efficiency and
optimizations (Python; go to gunicorn or something else) -- WIP
- [ ] Replace the server hardware (aka FluxDrop + home NAS with proper storage
media)
- [ ] Discover ways to build own page via modules (zero-code; not necessary
since I can just remember CSS and HTML, and do that by hands)

---

## Wiki updates pending (the user edits/commits the wiki)
- [ ] Share links (V0.22.0.46–47): a file link opened in a browser shows a
  page (name, size, Download, inline preview if allowed); curl/wget/download
  managers still get the file (content negotiation on `Accept` /
  `Sec-Fetch-Dest`); `?download=1` always the file, `?preview=1` inline,
  CDN-embed links always the raw file; HEAD works on share links now
- [ ] Report form works without JavaScript (posts to `/report`), translated
  on the server, `?lang=en|uk`
- [ ] `/?policy=tos` and `/?policy=pp` open the policy in the app (linked
  from share, report and error pages)
- [ ] Link previews in chats: `og:` tags on file and folder share pages,
  the status page and the app
- [ ] Share links and the trash (V0.22.0.52): trashing pauses the item's
  links, restoring brings them back, deleting from the trash (or expiry)
  removes them; rename/move keep links working (they follow the item)

## Can't reproduce / gone / unclear
*Kept for reference; reopen with exact steps if it shows up again.*

- [ ] Bug with item selector when `Shift` is used (actions modal stays opened)
-- not reproducible since; not found in the code (Shift+click already closes
the context menu and the Info panel)

---

## Done items that are pending for removal as finished:
*New lines between chunks of finished items means the patch version change
(e.g. `Vx.y.z.0` to `Vx.y.z.1`)*

(end of release note there)

- [x] Content reports: Report link on share pages, `/report` form for CDN
files, Reports tab in the admin panel, email alerts
- [x] IP Beacon registration requires a login (was open to anyone)
- [x] Server logs kept for 90 days (daily rotation), `maintenance.log` too
- [x] Account deletion removes files after 30 days; fixed the constraint error
when deleting users with share links
- [x] Offline page no longer loads Google Fonts
- [x] Draft Privacy Policy and Terms of Service v0.1.0

- [x] Background hashsums (do it via `nice` so it will execute when server
isn't fully utilized, as background thing) -- make it as improvement for the
current `maintenance window`
- [ ] Fix i18n in:
  - [x] Profile panel (`profile-panel-overlay`) -- title, avatar and password
  status messages, save/change buttons, Space Analyzer tooltips

---

*Note: **the entries inside "Done items that are pending for removal as
finished" will be purged after the release version will be ready and released***

*Note: **additional notes is now moved to the [DEVNOTES.md](/DEVNOTES.md),
please reach to it to acknowledge those notes***
