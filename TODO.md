# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### Important without category (critical before release)
- [ ] Folder upload doesn't utilize the new file strategy, leading to the 
`/tmp` dir exaustion. Needs immediate fixes before next release

### UI
- [ ] i18n support (language changes)
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
- [ ] Add ability to disallow with the terms, following by the message about 
need in the acceptance and logging out the user
- [ ] Footer versioning: make versioning system the same as the current with 
server (like v0.17.2.4)
- [ ] Add Welcome screen for new users that will explain (almost) everything 
about FluxDrop
- [ ] Upload can fail on slow internet, causing unability to upload the files 
to server
- [ ] Add fix for the timed out chunks causing full file reupload from the part 
where it's failed instead of pushing only the unloaded/wrong part of the file 
(aka reduce very large internet overhead)
- [ ] FluxDrop didn't stop the background download of ZIP if " 🚫 
shareables.zip 0 B / ? Browser dropped the download. Click Resume to start 
over." -- still there at V0.17.2.3
- [ ] Pre-load StreamSaver for ZIP downloads since otherwize FluxDrop didn't 
try to stop downloading 60GB folder into the RAM
- [ ] Show "Loading the acceptances..." for the acceptance modal if loading 
times are long, with some placeholder (like the current gradient-like for the 
main file manager UI)
- [ ] Instead of errors like "failed to fetch" after internet reconnect, 
ALWAYS catch it and DO NOT drop the hard error - RETRY until it IS successfull,
 or at least the N times
- [ ] StreamSaver and browser can get out-of-sync
- [ ] Fix StreamSaver doesn't utilize full power of the download resuming 
(browser keeps downloading again fully instead of attempt to resume)
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
FluxDrop file manager
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
- [ ] Add ability to preload the JPEG previews and for other files (contribute 
to the background media scan via FFmpeg)
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
- [ ] Add close by click on the dimmed space into the links manager
- [ ] Make "X" non-scrollable in links manager (so can be closed without need 
to scroll to the top)
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
- [ ] ZIP download modal that shows the missing from archive files may not be 
implemented due to code regression, checks are pending.
- [ ] Fix problems with the Quad9 pings "failing" and firing the external 
outage
- [ ] Fix archive streaming may fail at ~6 GB of streamed files (including few 
20+ GB in the streamed archive folder) -- should be already fixed by ZIP64, 
needs checks
- [ ] Ensure that CatBox API have file size limits


#### Medium:
- [ ] Sometimes FluxDrop makes config connections, resulting in 404, but right 
now I can't replicate it so I don't know why and I can't give any clues when 
that happens and after what


#### Low:
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else)
- [ ] Fix 206 not working in trash bin preview
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Add "enhanced" previews (bg activity that makes thumbs via FFmpeg for 
any type of file that's supported, thumbs can be included into the quota, or 
excluded from quota)
- [ ] Add partial content support for CatBox API and CDN itself for it's 
static hoster
- [ ] Make special player with "video preview support", aka "slow internet 
mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce 
bandwidth and resolution)
- [ ] Delete "CDN" path as it serves no purpose and doesn't work (line 5718 in 
`server_cdn.py`). Seems like it was made to make "shared" folder for any user 
of FluxDrop, but true usage is unknown since it's seems like undocumented and 
was introduced in one of the edit sessions without need to be made -- in the 
Terms and Policy, the same CDN may be mentioned
- [ ] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) - WIP
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)
- [ ] (not necessary) Divide snippets to dedicated HTML, JS and CSS
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)

---

## Items that needs additional checks or implementations:

- [ ] Fix HSTS redirects for FluxDrop file manager (currently doesn't work) -
means http to https on cdn (file manager) since login works ok (forwards to 
https) -- needs CDN migration to regular HTTP/HTTPS ports or single port to fix
 -- already WIP, implemented, not migrated due to some specific problems -- 
 doesn't work right now as intended to -- seems like it will work, needs 
 testing to be sure

---

## Done items that are pending for removal:
- [x] Do not allow user to exit the tab when uploading (simple thing)