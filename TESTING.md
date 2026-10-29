# To test (V0.22.0.1 – V0.22.0.12)

Changes made since V0.22.0 that still need a check on the live server.
Tick an item when it works; if it doesn't, write what happened under it.
Details for each item are in README "What's new" and in the
"Done, needs testing" notes in `TODO.md`.

Needs `./build.sh` + deploy first (TestWeb and the backend).

## Uploads
- [x] **Pause / resume, big file** (several chunks in flight): pause, wait,
  resume. The upload finishes without "Missing chunks". Chunks that were in
  flight at pause may already count as received; that's expected (see note
  below)
- [x] **Pause / resume several times quickly**: no duplicate runs, progress
  doesn't jump backwards or past 100 %
- [ ] **Pause while a chunk is retrying** (e.g. drop the network for a few
  seconds, then pause): it pauses instead of cancelling
- [x] **Cancel a paused upload**: tray goes to "Cancelled" (not stuck on
  "Cancelling…"); the server log shows the session deleted; the next queued
  upload starts
- [x] **Small file (< 25 MB) right after a big one**: no speed test, reuses
  the speed. **Small file on a fresh page**: no speed test, 1 MB chunks
- [ ] **Unfinished upload session** is purged after `UPLOAD_SESSION_TTL`, not
  2-3 hours early (check `last_activity` vs. purge time in the log)

> Pausing aborts the in-flight requests in the browser, but a request whose
> body was already fully sent is still processed by the server: it checks
> the length and the chunk's SHA-256, writes it and records it. Resume then
> asks `/status` which chunks are missing, so those aren't sent twice.

## ZIP downloads
- [x] Download a folder as ZIP: works, hashes appear
- [ ] Cancel while it's "preparing": server log shows the job cancelled, CPU
  goes quiet -- no viible CPU load when downloading the ZIP because the files 
  have ready caches?
  > Yes: files whose CRC/SHA are already stored (and unchanged) aren't
  > hashed again, so the job only builds the list — nothing to cancel. To
  > see it work, use a folder with files that were never hashed (e.g. put
  > there over SFTP/scp, outside FluxDrop) and watch `htop` / the log.
- [ ] Close the tab while preparing: job stops after ~20 s
  (`ZIP_JOB_IDLE_STOP`); requesting the same folder again continues where it
  stopped instead of hashing from the start
- [ ] Request the same folder twice (two tabs): one job, both get the ZIP
- [ ] A folder with a file that disappears mid-job: the "skipped files" list
  shows it, names with `<`/`&` display as text

## Trash
- [X] Trashed folder → "Browse": files listed under their folders
- [X] Click a file there: preview opens (image, text, audio, video)
- [ ] Hand-edit `?path=../..` in the request: 403
  > Where: open a file preview from a trashed folder with DevTools →
  > Network open, find the `/api/v1/trash/<id>/file?path=…` request,
  > right-click → **Edit and Resend**, change `path=` to e.g.
  > `../../something` and send. Expect 403. (Pasting the URL into the
  > address bar won't work — it needs the login header.)

## Archive preview
- [x] Big `.tar.gz` (the 1.6 GB one): shows progress, then the tree; no 502
- [x] Open it again: instant (cached)
- [ ] Upload a new `.tar.gz`, open it a bit later: already cached (prewarm)
- [x] `.zip` preview still works

## Domains and redirects
- [ ] `http://fluxdrop.me/...` → `https://fluxdrop.me/...` (no `:64800`)
- [x] `https://arseniusgen.dev/fluxdrop_pp/...` and `arseniusgen.uk.to`
  equivalents → 308 to `https://fluxdrop.me/...` (prefix stripped)
- [x] Old share links (`/share/...`, `/api/...` on old domains) redirect and
  still work; login over the redirect works (308 keeps POST)
- [x] Main site pages on arseniusgen.dev that aren't FluxDrop are **not**
  redirected
- [x] IP beacon still reports (it isn't redirected)

## Misc
- [x] Boot spinner disappears once the app shows (check the Inspector: no
  `#fd-boot-loading` left)
- [ ] CatBox `urlupload` returns "disabled"; normal CatBox uploads and old
  CatBox links still work
- [ ] `pip install -r requirements.txt` on a clean venv works (wand and
  requests removed)
- [ ] `/status` shows version 0.22.0.12 (it's read once at start — restart
  the services after syncing)

## Added in V0.22.0.12
- [ ] **Upload a file whose name already exists** in the folder: the old
  file stays untouched (also while uploading); the new one is saved as
  `name (1).ext` and the tray shows that name. Cancel it halfway: the old
  file is still there, nothing else is left behind
- [ ] Same for a `.tar.gz` → `name (1).tar.gz`, and for a folder upload over
  an existing folder (each clashing file gets " (1)")
- [ ] **Interrupted, twice**: pause → reload → Interrupted → continue →
  pause → Interrupted → continue. One tray row only; when finished it shows
  "Done" with Dismiss, no Cancel. While the upload is running, continuing
  it from Interrupted says it's already uploading
- [ ] Cancel on an upload that has just finished shows "Done", not
  "Cancelled" (server 409 = already complete)
- [ ] **Esc** closes the Trash (and a preview opened from it first)
- [ ] Archive preview: the spinner keeps turning while the % updates
- [ ] ZIP download while the server prepares it: tray says "Building
  archive…" / "Hashing files…", then "Downloading via browser…"
- [ ] **Ukrainian UI**: Uploads/Downloads trays (title, ETA, Paused,
  Cancelled, Done, verifying), Info panel, Move/Rename/Copy dialog, copy
  toast (Cancel/Hide), archive preview progress
