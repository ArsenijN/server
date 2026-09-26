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
- [ ] Starting from V0.21.0.5, the commits may start to have only 1 change per 
commit, if this practive will be better than current mix

### UI - add new features
- [ ] Add MIDI and modules player (tracker music). Inspired by modarchive.org
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API
- [ ] File preview modal may blink with light when it doesn't keep up when file 
loads/decodes 
- [ ] Make file explorer use fixed by size main modal and overflow buffer 
inside it to...
  - [ ] Make an animation for the `fd-sel-bar` as slide in (slide down with 
  some part of the UI)
- [ ] Rework the `btn-toolbar-toggle` to become as mini modal (aka menu) with 
options
- [ ] Dynamic page building (footer and header are shared, the body is 
different, if it's blogs - text of the blogs are changing, etc.)
- [ ] Add blogs page
- [ ] Add support page (tickets system)
- [ ] Add reviews
- [ ] Not always UI cancels the upload (says Cancelling... and does nothing)

### UX - fixes for existing features or new overall experience enhancements
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
- [ ] Add or fix animations in:
  - [ ] `ap-body`'s spinning wheel is still spinning in background (not visible 
  but Animations debugger sees it)
  - [ ] File copy when task is executed (button pressed)
- [ ] Add loading wheels/bars/things to:
  - [ ] Stats button for shared links manager
  - [ ] Profile infos
- [ ] Hide file selector (`fd-sel-bar`) for the mobile version of the FluxDrop 
if no keyboard is present
- [ ] Add some animation to the main file browser from the landing page
- [ ] Check the upload concurrency behavior on weak connections
- [ ] Bug with item selector when `Shift` is used (actions modal stays opened)

### Server-side non-breaking changes:

#### Critical:
- [ ] Trash bin file preview inside folders
- [ ] Maybe cancel the file hashing or avoid the ~~async~~ multithreaded file 
hash after canceling the ZIP download, or do it only if server is unused or via 
`nice`
- [ ] Do not make speed probe for small files (e.g. less than 25 MB) -- no if 
internet is bad -- if so - needs changes in how the chunks are calculated, 
maybe do a dynamic chunk size based on an speed of upload

#### High:
- [ ] Document the new proxy method that is currently used with my Immich 
instance
- [ ] Check code for security flaws/vulnerabilities
- [ ] Use the background hashsums for silent file check activity in 
background -- specifiable time period in server config
  - [ ] Add parchives to avoid file damages on server
  - [ ] Add some kind of messages if files got corrupted on server side and 
  was unrecoverable
- [ ] Backend doesn't always save all received chunks (results in reduced 
amount of completed upload data after pause)

#### Medium:
- [ ] Update the services (and exclude the entry in the `.gitignore`)

#### Low:
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
- [ ] Add code map
- [ ] Use separate email for FluxDrop
- [ ] Add proper account disable and deletion, compliances to GDPR (incl. 
"Download everything as a ZIP")
- [ ] Add a way to track IPs, auths, etc. - aka special admin page for specific 
usages, for example the abuse
- [ ] Make emails have local the same as user


---

## Items that needs additional checks or implementations:
- [ ] Fix i18n in:
  - [ ] Error-related pages -- untested

---

## Done items that are pending for removal as finished:
*New lines between chunks of finished items means the patch version change 
(e.g. `Vx.y.z.0` to `Vx.y.z.1`)*

(end of release note there)

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
