# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

Work is ordered by phase: priority fixes first, then backend, then the API V2
groundwork, then the frontend V2 (FE V2) rewrite.  Items inside a phase are
roughly ordered by priority (top = first).

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

- [ ] Backend doesn't always save all received chunks: after pausing the
upload, a chunk that was successfully sent may not be saved (unACK issue?).
Not related to internet conditions AFAIK; recheck after the recent proxy fixes
(may affect only Immich over WebSocket, or regular HTTP too)
  - Cause found in the client, fixed, needs testing: on pause, workers
  that weren't mid-send waited instead of exiting, so Resume started a
  second run from the highest chunk taken while the old run woke up too;
  chunks in between could be skipped ("Missing chunks" on complete). Now
  chunks come from a queue, Resume asks `/status` for the missing ones, and
  the client re-checks `/status` before `/complete`
- [ ] Not always UI cancels the upload (says "Cancelling..." and does nothing)
  - Cause found, fixed, needs testing: Cancel on a *paused* upload never
  sent the DELETE or left the "cancelling" state, since the paused run had
  already ended. Also, pausing during a chunk retry cancelled the upload
- [ ] Trash bin: file preview inside trashed folders (`/api/v1/trash/<id>/list`
exists, but `/api/v1/trash/<id>/file` rejects folders -- needs a sub-path
parameter with the `_is_within()` containment check)
  - Done, needs testing: `/trash/<id>/file?path=<sub/path>` (checked with
  `_is_within()`); files in the "Browse" tree are clickable and open the
  preview. The tree is now nested properly and escapes file names
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
- [ ] Do not make speed probe for small files (e.g. less than 25 MB) -- not if
internet is bad -- if so, needs changes in how the chunks are calculated, maybe
a dynamic chunk size based on the upload speed
  - Done, needs testing: files under 25 MB skip the probe; they reuse the
  speed of an upload finished in the last 10 min, or else use 1 MB chunks
  (safe for the 90 s chunk timeout on a bad connection)
- [ ] Check the upload concurrency behavior on weak connections
- [ ] Publish Privacy Policy and Terms of Service v0.1.0: set up
`privacy@fluxdrop.me`, fill in `[CONTACT EMAIL]`, the email provider and the
effective date, then bump `policies/versions.json`

## Phase 0 -- Frontend V1 fixes (low effort)

- [ ] File preview modal may blink with light when it doesn't keep up when file
loads/decodes
- [ ] Bug with item selector when `Shift` is used (actions modal stays opened)
- [ ] `ap-body`'s spinning wheel is still spinning in background (not visible
but Animations debugger sees it)
  - It's the boot loader (`fd-boot-spin`) left in `#app-root`. Safety net
  added (removed once anything else appears in `#app-root`); the render path
  that skipped it is still unknown -- needs testing
- [ ] Hide file selector (`fd-sel-bar`) for the mobile version if no keyboard
is present
- [ ] Add animation for file copy when task is executed (button pressed)
- [ ] Add loading wheels/bars to:
  - [ ] Stats button for shared links manager
  - [ ] Profile infos
- [ ] Fix i18n in error-related pages -- untested

---

## Phase 1 -- Backend hardening and groundwork (non-breaking)

- [ ] Make separate "testing" server where I would be able to test everything
before pushing to the real one (needed before the FE V2 rewrite)
- [ ] Add code map
- [ ] Check code for security flaws/vulnerabilities -- audit v8, covering
everything since V0.20.0.21 (last audit, see `fluxdrop_audit.md`)
  - [ ] B8: raise HSTS `max-age` (still `300`)
  - [ ] B9: drop `unsafe-inline` from CSP -- done by FE V2 (no inline scripts)
- [ ] Use the background hashsums for silent file check activity in
background -- specifiable time period in server config
  - [ ] Add parchives to avoid file damages on server
  - [ ] Add some kind of messages if files got corrupted on server side and
  were unrecoverable
- [ ] Fix CSP for used domain other than `PUBLIC_DOMAIN` (e.g. accessing
FluxDrop from fluxdrop.me, and it loads the link relative to arseniusgen.uk.to
as specified in `PUBLIC_DOMAIN`)
- [ ] Port settings clash: `server_cdn.py` and the front servers
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
  gzip bombs
- [ ] Upload session purge (`core/upload.py`) compares naive local
`datetime.now()` with the UTC `last_activity` -- sessions are purged 2-3 h
early (same class of bug as audit B14)
  - Done: compares in UTC
- [ ] Use separate email for FluxDrop
- [ ] Send emails in the user's locale
- [ ] Update the services (and exclude the entry in the `.gitignore`)
- [ ] Document the new proxy method that is currently used with my Immich
instance

---

## Phase 2 -- API V2 (breaking, next to API V1)

- [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths;
background copy jobs already exist)
- [ ] Server-side filename sanitisation for illegal characters
- [ ] Reimplement the CDN path purpose, fix its errors: per-user CDN hosting
(upload files into a folder and link them from your own page; hosting a whole
page is possible, but should be a separate service using FluxDrop as API)
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
- [ ] Dynamic page building (footer and header are shared, the body is
different, if it's blogs - text of the blogs are changing, etc.)
- [ ] Divide snippets to dedicated HTML, JS and CSS (no inline scripts/styles)
- [ ] Add some animation to the main file browser from the landing page

### File manager
- [ ] Fixed by size main modal with overflow buffer inside it, to make a
slide-in animation for the `fd-sel-bar` (slide down with some part of the UI)
- [ ] Rework the `btn-toolbar-toggle` to become as mini modal (aka menu) with
options
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
