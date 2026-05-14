# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### UI
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API
- [ ] Make avatar support (pre-scale down to 64x64 px, compress via AVIF or 
JPG)
- [ ] Custom right-click menu for folders and files (reduce amount of options 
with files)
- [ ] Add "view background connectivity debug console" in settings to see small 
one-liner somewhere at the bottom of the UI that will say what site currently 
try to fetch or do (at least via Internet)
- [ ] Fix "Allow only FluxDrop users to upload" doesn't work as intended ( - 
expected to be so no one can upload to folder except the registered users on 
FluxDrop)
- [ ] Make upload settings as drop-out menu for choosing who actually can 
upload (anyone or only FluxDrop users)
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Trash bin folder preview

### UX
- [ ] (unchecked) "fetch if the script.js changed" (at around 5472 line) may 
make cached fetch (the "Передано" shows "service worker"), so actually it 
doesn't make a fetch for updated version (or at least not always, or it's 
intended to be not always/after some time the cache version is on device?). 
Think about changing the system so it will fetch, like, "version.json" in the 
root, and if version is different inside the script.js or sw.js - update..?
- [ ] Instead of errors like "failed to fetch" after internet reconnect, 
ALWAYS catch it and DO NOT drop the hard error - RETRY until it IS successfull,
 or at least the N times
- [ ] Not implemented (regression): `TOS and PP acceptance modal showing when 
the token is not valid (user was forced to scroll to the bottom to skip it)`
- [ ] `⚠ can't access property "port1", channel is null` replaced with 
the `Cancelled` (catch if user cancel the download via browser)
- [ ] Add catcher or something so Firefox will not fail with "Програма-браузер 
несподівано завершила роботу."
- [ ] StreamSaver and browser can get out-of-sync
- [ ] Fix StreamSaver doesn't utilize full power of the download resuming 
(browser keeps downloading again fully instead of attempt to resume)
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else)
- [ ] Add quota "space analyzer" (like WizTree or Filelight or whatever - it 
will display what files takes the most, where and what)
- [ ] Fix issues with resuming the download (in FluxDrop file manager at least)
- [ ] Make download work as chunk-based in FluxDrop UI, keeping the regular 
octet-stream for legacy usage
- [ ] Add self-resume on network switch (offline handler shows and hides, but 
download doesn't continue)
- [ ] Add file picker to file browser (checkbox-styled or as "click on the 
`border-t` to select one)
  - [ ] Add ability to use regular keyboard shortcuts (shift for multiple file 
  pick, ctrl to specific, ctrl+shift for multiple from latest pick with ctrl; 
  aka regular file browser behavior like on Windows)
  - [ ] Add ability to double-click on the `border-t` to open the file/folder
- [ ] Optimize FluxDrop for mobile screens, regular 16:9 and other aspect 
ratios, later on make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Fix every FluxDrop snippet and site (UIs) to work properly with mobile 
and non-16:9 screens
- [ ] Add file streaming (archive and stream to the server; one stream - a lot 
of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
- [ ] Add loading wheel to the right of "Upload" button between prep and upload 
states - make it appear before new entry in `Uploads` or `Downloads` appears, 
also, bring the label to the static part so it will not scroll
- [ ] Add image placeholders between image fetch and display
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
even on i5 10400)
- [ ] Add folder downloads and size to the `share` snippet
- [ ] Auto negotiation for upload type (folder or file)
- [ ] Add dark theme switch, or at least make addons work properly and test 
them
- [ ] Improve user iterations by adding auto-reconnect on dropped connection 
(e.g. switched networks) - this means semi-constant pings to the server on 
download or/and upload
- [ ] Add handler for dropped connection mid upload/download with relable way 
to tell it (via pings or continuous connections)
- [ ] i18n support (language changes)
- [ ] Fix URL-encode issues with the "path persist" (so then it tried to access 
folder with name `New%20Folder` instead of `New Folder`)
- [ ] Do not show the window to "agree with the TOS and PP" when user token is 
expired - immediatelly "kick out" the user with purged token to the landing 
page
- [ ] Add close by click on the dimmed space into the links manager
- [ ] Make "X" non-scrollable in links manager (so can be closed without need 
to scroll to the top)
- [ ] Add fix for the timed out chunks causing full file reupload from the part 
where it's failed instead of pushing only the unloaded/wrong part of the file 
(aka reduce very large internet overhead)
- [ ] Fix the background media playing if internet is very bad and seems like 
only when attempt to reach for file was made after the preview window is 
closed (internet hang)
- [ ] Add stats window loading wheel/bar since bad internet causes high wait 
times without knowing what it is doing
- [ ] Add progressbar for blob fetches
- [ ] Add `.7z` and `.rar` for file table previews (and other ones)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents
- [ ] Add file info modal
  - [ ] Basics (file modify time, size, etc.)
  - [ ] Background hashsums (do it via `nice` so it will execute when server 
  isn't fully utilized, as background thing)
    - [ ] Use those hashes for silent file check activity in background
      - [ ] Add parchives to avoid file damages
      - [ ] Add some kind of messages if files got corrupted on server side and 
      was unrecoverable 
- [ ] Add "proper" loading wheels (1 second as least amount of time for the 
"apply" and other important features, more pleasant loadings for the file 
manager)
- [ ] Add variable chunk sizes on demand for different internet speeds and 
optimizations -- uploads, downloads is an issue
- [ ] Add the update notifier back

- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - [ ] Add settings to control whether group members may add/remove other
    users, set quotas, etc.

- [ ] **Legacy usage without JS** — at minimum, users should be able to
  download shared files without JavaScript enabled.

- [ ] **Misc future ideas**
  - [ ] Server-side filename sanitisation for illegal characters.
  - [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths).

### Server-side changes:

#### Critical:
- [ ] Fix StreamSaver not working - pending from V0.16.0.2
- [ ] Fix archive streaming may fail at ~6 GB of streamed files (including few 
20+ GB in the streamed archive folder)
- [ ] Fix issue with quota being very greedy, allowing to over-use the 
available space - probably, even if the quota is 50 GB, user, in theory, still 
would be able to upload one single 200 GB file
- [ ] Ensure that CatBox API have file size limits
- [ ] Zip download are handled as in-RAM operation, causing memory exhaust on 
client's device


#### Medium:
- [ ] Fix double TLS for proxy aka fix the file download speeds


#### Low:
- [ ] Fix problems with the Quad9 pings "failing" and firing the external 
outage
- [ ] Fix 206 not working in trash bin preview
- [ ] Delete "CDN" path as it serves no purpose and doesn't work (line 5718 in 
`server_cdn.py`). Seems like it was made to make "shared" folder for any user 
of FluxDrop, but true usage is unknown since it's seems like undocumented and 
was introduced in one of the edit sessions without need to be made
- [x] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) - WIP
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)
- [ ] (not necessary) Divide snippets to dedicated HTML, JS and CSS
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)
- [ ] Make special player with "video preview support", aka "slow internet 
mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce 
bandwidth and resolution)
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Add "enhanced" previews (bg activity that makes thumbs via FFmpeg for 
any type of file that's supported, thumbs can be included into the quota, or 
excluded from quota)
- [ ] Add partial content support for CatBox API and CDN itself for it's 
static hoster

---

## Items that needs additional checks or implementations:

- [ ] Fix HSTS redirects for FluxDrop file manager (currently doesn't work) -
means http to https on cdn (file manager) since login works ok (forwards to 
https) -- needs CDN migration to regular HTTP/HTTPS ports or single port to fix
 -- already WIP, implemented, not migrated due to some specific problems -- 
 doesn't work right now as intended to

---

## Done items that are pending for removal:






# FluxDrop — TODO (pending as new style but also and mainly as priority list)

Items are grouped by area and sorted within each group by priority.
Priorities: 🔴 critical (data loss / security / broken) · 🟡 high (noticeably broken UX) · 🟢 normal · ⚪ low / future

---

## 🔧 Server / Backend

### 🔴 Critical
- [ ] **Quota enforcement is too loose** — a single upload can exceed the user's quota (e.g. a 200 GB file when quota is 50 GB). Pre-flight size check needed before accepting the upload session.
- [ ] **ZIP archive streaming can corrupt or truncate** at ~6 GB when the folder contains files larger than ~20 GB — already partially patched; needs full regression test with a real 25+ GB folder.
- [ ] **CatBox API has no file size limit** — enforce `MAX_UPLOAD_BYTES` (or a separate limit) on all CatBox upload paths.

### 🟡 High
- [ ] **Download speed limited by double TLS** — proxy hop (HTTPS server → CDN) encrypts every byte twice since both sides use TLS on loopback. Fix: bypass proxy for large file downloads by redirecting browser directly to CDN port, keeping proxy only for small API calls.
- [ ] **`foldersize` endpoint has no cache** — walks HDD on every call. Apply same `_dir_cache` pattern already used in `status.py`.
- [ ] **Chunk timeout causes full re-upload** — when a chunk times out, the client retries the whole file from the failed chunk rather than only the missing chunk. Fix: track which chunks are confirmed server-side and only request those.
- [ ] **`"Allow only FluxDrop users to upload"` share setting does not enforce correctly** — anyone can still upload to a folder with this flag set.

### 🟢 Normal
- [ ] **Pre-push / server-sent hints** — push folder structure, quota, and pre-generated download tokens to the client before it asks (reduces round-trips on bad connections; especially useful for preview tokens).
- [ ] **Download resume broken in file manager** — `resumeDownload()` re-navigates correctly now but the tray entry doesn't reflect progress for native browser downloads. Consider polling `bytes_confirmed` from the download token.
- [ ] **Self-resume after network switch** — offline banner shows/hides correctly but interrupted downloads and uploads do not auto-retry when connectivity returns.
- [ ] **Quota space analyzer** — tree-view showing which folders/files consume the most space (like WizTree/Filelight), accessible from the storage quota bar.
- [ ] **Background file integrity hashes** — compute SHA-256 (via `nice`) for stored files in the background; surface corrupted-file warnings to the user; optionally store par2 parchives.
- [ ] **Server-side filename sanitisation** — strip or replace characters illegal on Windows/macOS (`< > : " / \ | ? *`) at upload time.
- [ ] **Explicit move and copy API endpoints** — current rename-path workaround is fragile for cross-directory operations.

### ⚪ Low / Future
- [ ] **Quad9 health-check false positives** — probe failures occasionally trigger "external outage" incorrectly. Add a secondary probe or increase failure threshold before alerting.
- [ ] **HTTP 206 not working for trash bin preview** — Range requests fail for files in `.trash/`.
- [ ] **Remove dead `/cdn/` route** (`server_cdn.py` line 5718) — appears to be an undocumented leftover with no active use case.
- [ ] **HSTS redirect for file manager** — HTTP → HTTPS redirect inside the CDN file manager still not working as intended; depends on proxy migration being fully deployed.
- [ ] **AV1 transcoding for "slow internet mode"** — re-encode uploaded videos server-side with FFmpeg (low priority; needs significant CPU or a background queue).
- [ ] **FFmpeg thumbnail generation** — background job producing thumbnails for all file types FFmpeg can decode; thumbnails optionally count toward / excluded from quota.
- [ ] **Replace server hardware** — current setup (i3 370m + old Toshiba HDD) is the hardware ceiling; plan for proper NAS with faster drives.

---

## 🖥️ Frontend / UI

### 🟡 High
- [ ] **URL-encode bug in path persistence** — navigating to a folder named `New Folder` encodes it as `New%20Folder` in the URL, and on reload the app tries to fetch `New%2520Folder` (double-encode). Decode before building API paths.
- [ ] **Expired token should skip TOS/PP modal** — currently shows the policy acceptance modal even when the session is already expired. Should silently purge token and redirect to landing page instead.
- [ ] **Variable chunk size based on measured speed** — current fixed 25 MB chunks are too large on bad LTE (long stall before first progress). Auto-tune chunk size from the speed probe result.
- [ ] **Background media continues playing after preview closes** — audio/video keeps playing when the preview modal is closed on a bad connection. Stop and unload the media element on close.
- [ ] **Upload spinner between "prepare" and tray entry appearing** — no visual feedback during the init API call before the upload tray entry is created. Add a spinner to the Upload button during this gap.

### 🟢 Normal
- [ ] **AJAX-style file list updates** — avoid full visual re-render of the file list on every operation (rename, delete, upload complete). Patch the in-memory list and update only the affected DOM rows.
- [ ] **File multi-select** — checkbox-style selection with standard keyboard shortcuts: `Shift+click` for range, `Ctrl+click` for individual, `Ctrl+A` for all.
- [ ] **Double-click to open** — currently requires clicking the filename link; double-clicking the row border should open file/folder.
- [ ] **Custom context menu** — right-click on file/folder shows a compact context menu (open, rename, move, delete, share, copy link) instead of relying on the action buttons.
- [ ] **Loading indicator for stats/share panel** — bad internet causes multi-second waits with no feedback. Show a spinner or skeleton while fetching.
- [ ] **Progress bar for blob fetches** — preview modal shows no progress while fetching large files for in-browser preview.
- [ ] **Image loading placeholders** — show a grey skeleton or blurred low-res placeholder while full-resolution images are fetching.
- [ ] **Chunk upload retry shows full re-upload** — progress bar resets to 0 on retry instead of showing only the failed chunk being re-sent. Fix progress accounting.
- [ ] **Links manager: close on backdrop click** — clicking the dimmed background behind the share manager should close it.
- [ ] **Links manager: sticky close button** — the `✕` button scrolls out of view on long share lists. Pin it to the top of the panel.
- [ ] **Folder size and download in share snippet** — the public share page for directories does not show total size or offer a folder-level download button.
- [ ] **Auto-detect upload type** — detect whether the dropped/selected item is a file or folder and switch the upload mode automatically.
- [ ] **Dark theme** — add a theme toggle; verify browser extension compatibility.
- [ ] **File info modal** — show modify time, size, MIME type, path. Later: hash values once background computation is done.
- [ ] **Preview support for `.7z`, `.rar`, `.docx`, `.pptx`, `.odt`, `.ods`** — show at minimum a file-type icon and metadata; full content preview where feasible.
- [ ] **HEIF decode slowness** — `<img>` decoding a HEIF file takes ~5s even on modern CPUs. Investigate whether server-side conversion to JPEG/AVIF on first preview request would help.
- [ ] **Trash bin folder preview** — currently the trash bin only shows flat file list; show folder structure.
- [ ] **Add progressbar / skeleton for "proper" loading states** — operations like rename, apply settings, etc. should show at least 1 second of visual feedback so fast operations feel confirmed rather than instant-and-silent.

### ⚪ Low / Future
- [ ] **CatBox browser UI** — landing page + usage stats page for the CatBox API endpoint.
- [ ] **User avatars** — upload, auto-scale to 64×64, store as AVIF or JPEG; show in profile menu and (optionally) in the file manager header.
- [ ] **Proper header and footer** — replace the minimal header with a proper nav bar; add a footer with version info and links.
- [ ] **Batch TAR upload UI** — surface the `batch_tar_upload.py` functionality (stream many files as one TAR) in the file manager UI.
- [ ] **i18n** — internationalisation framework; Ukrainian and English already have some groundwork in the policy system.
- [ ] **Group / family accounts** — shared root directory with configurable per-member read/write/admin privileges and shared quota pool.
- [ ] **No-JS shared file downloads** — users without JavaScript should be able to download a shared file via a plain `<a>` link (no fetch/token required).
- [ ] **Mobile optimisation and PWA** — responsive layout for all screens; PWA installable via Chrome; optionally a native Android Material Design app.
- [ ] **Connectivity debug console** — optional one-liner overlay in settings showing the current in-flight request (URL, status) for diagnosing bad-internet issues.
- [ ] **Split snippets into separate HTML/JS/CSS files** — cosmetic/maintenance; low urgency.