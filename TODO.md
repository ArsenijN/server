# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### Important without category (critical before release)
- [ ] Do NOT implement the breaking features into the patch versions (e.g. 
V0.19.2 over V0.19.1), instead, add them or new items to the separate TODO's 
list specifically for those breaking changes (that are allowed in the V0.20 
over V0.19)

### UI - add new features
- [ ] Add MIDI and modules player (tracker music). Inspired by modarchive.org
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API
- [ ] Markdown modal are open for i18n strings translations, but it should not
- [ ] File preview modal may blink with light when it doesn't keep up when file 
loads/decodes 
- [ ] Make file explorer use fixed by size main modal and overflow buffer 
inside it to...
  - [ ] Make an animation for the `fd-sel-bar` as slide in (slide down with 
  some part of the UI)
- [ ] Rework the `btn-toolbar-toggle` to become as mini modal (aka menu) with 
options
- [ ] Fix some modals being server-side generated instead of frontend's work

### UX - fixes for existing features or new overall experience enhancements
- [ ] Status page doesn't updates fully automatically (e.g. uptime)
- [ ] Make file info modal able to work as "turn on and stay until closed": 
toggle in settings to change this behavior; works as file info modal that 
doesn't close when user clicks outside of it
- [ ] Add multiple files streaming (archive and stream to the server; one 
stream - a lot of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make file upload multithreaded (2+ files processing simultaneously on 
upload)
- [ ] Make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content) -- file manager, ...
- [ ] Add ability to preload the JPEG/any current format for previews like AVIF 
and for other files (contribute to the background media scan via FFmpeg)
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
on i5 8350U)
- [ ] Add `.7z`, `.rar` and other archive types for file table previews
- [ ] Add `.docx`, `.pptx`, `.odt`, `.odf`, `.ods`, and other for previews
- [ ] Add `.dng` and other raw image formats support for previews
- [ ] Fix i18n in:
  - [x] Actions modal
  - [ ] Error-related pages -- untested
- [ ] Add more animations to:
  - [ ] File action modal closing
- [ ] Add loading wheels/bars/things to:
  - [ ] Stats button for shared links manager
  - [ ] Profile infos
- [ ] Uploads can't be paused and instead "cancels" if using the drag-n-drop
- [ ] Server sends entire file layout and their sizes in `https://fluxdrop.me/ap
i/v1/list/tmp` but client still fetches the individual files/folders like `https
://fluxdrop.me/api/v1/foldersize/tmp/sub` (contents of the `` is `{"path": "/tmp
", "entries": [{"name": "U.mp4", "path": "/tmp/U.mp4", "is_dir": false, "size": 
506758298, "mtime": "2026-05-30T20:14:22"}, {"name": "sub", "path": "/tmp/sub", 
"is_dir": true, "size": 0, "mtime": "2026-07-28T20:41:42"}, {"name": "\u041d\u04
3e\u0432\u0438\u0439 \u0422\u0435\u043a\u0441\u0442\u043e\u0432\u0438\u0439 \u04
34\u043e\u043a\u0443\u043c\u0435\u043d\u0442.txt", "path": "/tmp/\u041d\u043e\u0
432\u0438\u0439 \u0422\u0435\u043a\u0441\u0442\u043e\u0432\u0438\u0439 \u0434\u0
43e\u043a\u0443\u043c\u0435\u043d\u0442.txt", "is_dir": false, "size": 158, "mti
me": "2026-05-30T20:16:51"}]}`) -- problem is that **this** requests **does not 
output the folder size**, meaning that there **is** still meaning for the curren
t setup
- [ ] File selector does not reset when file is moved
- [ ] Hide file selector for the mobile version of the FluxDrop
- [ ] "📌 Зберігати вибір" are starts to be visible when there's more than one 
item inside folder, but doesn't stop being visible... Wait, why it wasn't there 
first time? It should be!
- [ ] Hold-to-manage feature on mobile is nifty - maybe should been also 
mentioned in the welcoming screen
- [ ] Opening the profile preview modal is very epilepsy-warning (mobile)
- [ ] Add animation after login window closes due to login event
- [ ] Add some animation to the main file browser from the landing page
- [ ] Check the upload concurrency behavior on weak connections
- [ ] Bug with item selector when `Shift` is used (actions modal stays opened)
- [ ] Check if upload still ends successfully (message that is sent via 
browser) even if the upload of one of the files fails (for example because of 
the quota) -- it is, and also smaller files are correctly uploaded that fits 
the quota
- [ ] File selector does not reset or reselect when file is renamed
- [ ] FluxDrop Web makes 2 connections to get the download token when viewing 
the archive's table of contents
- [ ] After upload FluxDrop Web fetches the same page (current working 
directory) 2 times

### Server-side non-breaking changes:

#### Critical:
- [ ] Trash bin file preview inside folders
- [ ] Maybe cancel the file hashing or avoid the ~~async~~ multithreaded file 
hash after canceling the ZIP download, or do it only if server is unused or via 
`nice`
- [ ] Do not make speed probe for small files (e.g. less than 25 MB) -- no if 
internet is bad

#### High:
- [ ] Status page doesn't load the amount of files on server on first load 
because of backend stalement
- [ ] Ability to download the shared folders without JS (fallback option for 
ZIP downloads)
- [ ] Update the helpers functionality
- [ ] Document the new proxy method that is currently used with my Immich 
instance
- [ ] Check code for security flaws/vulnerabilities
- [ ] Background hashsums (do it via `nice` so it will execute when server 
isn't fully utilized, as background thing) -- make it as improvement for the 
current `maintenance window`
  - [ ] Use those hashes for silent file check activity in background -- 
  specifiable time period in server config
    - [ ] Add parchives to avoid file damages on server
    - [ ] Add some kind of messages if files got corrupted on server side and 
    was unrecoverable

#### Medium:
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items for FluxDrop file manager
- [ ] Update the services (and exclude the entry in the `.gitignore`)
- [ ] Add hash (maintenance) logs to the debug category for main log file (keep 
the separate `maintenance.log` file work always, but not include the infos into 
CDN's logs if debug isn't enabled)

#### Low:
- [ ] Reduce amount of re-imports inside the code if this will add overall 
overhead
- [ ] Add checkers for external HTTP and HTTPS hosters for outage page
- [ ] Add "enhanced" previews (bg activity that makes thumbs via FFmpeg for 
any type of file that's supported, thumbs can be included into the quota, or 
excluded from quota)
- [ ] Make special player with "video preview support", aka "slow internet 
mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce 
bandwidth and resolution)
- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - [ ] Add settings to control whether group members may add/remove other
    users, set quotas, etc.

#### Lowest:
- [ ] Make separate "testing" server where I would be able to test everything 
before pushing to the real one
- [ ] (at some unnecessary point) Divide snippets to dedicated HTML, JS and CSS
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)

---

### Server-side BREAKING changes:

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

### Without category:
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else) -- merged into the rela... 
No it's not since that entry issues the JSON multi-answer instead on only 
related to fetch/question
- [ ] Reimplement the CDN path purpose, fix it's errors
- [ ] **Misc future ideas**
  - [ ] Server-side filename sanitisation for illegal characters.
  - [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths).
- [ ] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) -- WIP, low priority
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)
- [ ] Fix CSP for used domain other than `PUBLIC_DOMAIN` (e.g. accessing 
FluxDrop from fluxdrop.me, and it loads the link relative to arseniusgen.uk.to 
as specified in `PUBLIC_DOMAIN`)


---

## Items that needs additional checks or implementations:
- [ ] Missing ZIP's files may be never displayed on client
- [ ] Check the acceptance modal loader on slow internet when new terms will be 
made/applied
- [ ] Dark mode auto switch -- doesn't work
- [ ] HSTS redirect should work correctly
- [ ] Check the visualization for retry cycles
- [ ] Check that downloading the ZIP show the actual thing that happening 
behind the scene (because it showed just "Downloading via browser..." before)
- [ ] Add partial content support for CatBox API and CDN itself for it's 
static hoster -- doesn't CDN have that already?

---

## Done items that are pending for removal as finished:
*New lines means the patch version change (e.g. `Vx.y.z.0` to `Vx.y.z.1`)*

- [x] Add file info modal

- [x] Add more animations to:
  - [x] Closing the profile menu
  - [x] File selection (checkmark appearance and disappearance)
  - [x] `fd-sel-bar` animations of appearance and disappearance
  - [x] `profile-panel-overlay` closing
  - [x] `share-manager-overlay` closing
  - [x] `trash-overlay` closing
  - [x] Markdown modal closing
- [x] Markdown parser does not understand:
  - [x] `***` following with the new lines inside the text and then `***` again 
  -- still does not understand
- [ ] Fix i18n in:
  - [x] Shared links remainings
    - [x] "CDN Embed..." not fixed
    - [x] operation type (e.g. `download`, `view`, `embed`, etc.)
    - [x] Expired [date]
    - [x] "📊 Stats: [folder name]"

- [x] Add more animations to: File download and upload modals (ETA modal): When 
closed or opened by itself
- [x] Fix i18n in: Translate the `⚠ Due to server capacity demand, new items 
are kept for 7 days. Retention will return to 30 days once space is freed.` 
(not i18n, rather l10n issue with missing key -- no, it's i18n)

- [x] CDN server's HTTPS port crashes if internet is not available for long
time -- it's Websocket problem, should be fixed soon

- [x] Acceptance modal (opens via the footer buttons) displays plain HTML with 
Markdown formatting applied
- [x] File selector does not unselect after item deletion
- [x] Add `Del` key as hotkey to delete selected item(s)

- [x] Profile icon is not cached and reloads every time from the ground
- [x] Add caching for:
  - [x] Profile picture

- [x] Profile picture not loading on new machines
- [x] Dedicated buttons for upload is not showing on mobile devices (but shows 
on desktop and desktop's mobile option)
- [x] Rework the trash bin messages (drop the browser-native, rework the 
current trash deletion notifier, etc.)
- [x] No dedicated upload button for mobile and desktop

- [x] Sometimes FluxDrop makes config connections, resulting in 404 -- they are 
caused by network switch (on client device)

- [x] Add responce compession (gzip?) for:
  - [x] JSON responces that are large
  - [x] `.md` files
- [x] Hash are not moved/re-attached to a file after move

- [x] Error when making attempt to copy the files
- [x] gzip compression indeed works and not have just the `gzip` tag used

- [x] Proxy fail on copy of the large files (timeout)

- [x] Canceling the upload doesn't wait for the request to finish and displays 
the cancelled right away
- [x] Upload needs additional improvements into the slow internet mode (if 
speed probe takes 30s - divide file even into few kB chunks, because right now 
it did ~330 kB, but because upload's chunks is multi-streamed - that doesn't 
work well and may result in the timeout errors)

- [x] Interrupted uploads modal have no animations and `Esc` to exit shortcut
- [x] Moving's loading wheel modal doesn't have animations for appearing and 
disappearing

- [x] Item selection didn't catch up if done quickly (to the `Shift` problem)
- [x] Drag across rows deselects everything
- [x] Immich can't handle uploading files larger than 2GB (413 error - limited 
size)

(end of release note there)

---

*Note: **the entries inside "Done items that are pending for removal as 
finished" will be purged after the release version will be ready and released***

*Note: **additional notes is now moved to the [DEVNOTES.md](/DEVNOTES.md), 
please reach to it to acknowledge those notes***
