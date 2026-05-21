# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### Important without category (critical before release)
- [ ] Folder upload doesn't utilize the new file strategy, leading to the 
`/tmp` dir exaustion on server. Needs immediate fixes before next release
- [ ] Fix problems with the Quad9 pings "failing" and firing the external 
outage -- critical issue before big release
- [ ] Literally "завантаження скрніів-3-001(2).zip: name '_choose_strategy' is 
not defined"? none of the upload types works, I'll temporarely revert back the 
code on the server so it will work... No I will not since that may break the DB

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
- [ ] Add MIDI and modules player (tracker music). Inspired by modarchive.org
- [ ] Footer versioning: make versioning system the same as the current with 
server (like v0.17.2.4)
- [ ] Add quota "space analyzer" (like WizTree or Filelight or whatever - it 
will display what files takes the most, where and what)
- [ ] Add file picker to file browser (checkbox-styled or as "click on the 
`border-t` to select one)
  - [ ] Add ability to use regular keyboard shortcuts (shift for multiple file 
  pick, ctrl to specific, ctrl+shift for multiple from latest pick with ctrl; 
  aka regular file browser behavior like on Windows)
  - [ ] Add ability to double-click on the `border-t` to open the file/folder
  - [ ] Optimize FluxDrop for mobile screens, regular 16:9 and other aspect 
ratios
- [ ] Add file info modal
  - [ ] Basics (file modify time, size, etc.)
  - [ ] Background hashsums (do it via `nice` so it will execute when server 
  isn't fully utilized, as background thing)
    - [ ] Use those hashes for silent file check activity in background
      - [ ] Add parchives to avoid file damages
      - [ ] Add some kind of messages if files got corrupted on server side and 
      was unrecoverable 

### UX
- [ ] Add ability to disallow with the terms, following by the message about 
need in the acceptance and logging out the user
- [ ] Add Welcome screen for new users that will explain (almost) everything 
about FluxDrop
- [ ] Upload can fail on slow internet, causing unability to upload the files 
to server
- [ ] Add fix for the timed out chunks causing full file reupload from the part 
where it's failed instead of pushing only the unloaded/wrong part of the file 
(aka reduce very large internet overhead) -- immediatelly on error, not need in 
the page reload to bring that
- [ ] FluxDrop didn't stop the background download of ZIP if " 🚫 
shareables.zip 0 B / ? Browser dropped the download. Click Resume to start 
over." -- still there at V0.17.2.3
- [ ] Show "Loading the acceptances..." for the acceptance modal if loading 
times are long, with some placeholder (like the current gradient-like for the 
main file manager UI)
- [ ] Instead of errors like "failed to fetch" after internet reconnect, 
ALWAYS catch it and DO NOT drop the hard error - RETRY until it IS successfull,
 or at least the N times (reliable way to resume whatever operation is going)
- [ ] Fix StreamSaver doesn't utilize full power of the download resuming 
(browser keeps downloading again fully instead of attempt to resume) -- will be 
kept as fallback if browser can't handle the file downloads, so browser will 
handle the download of all files, but this will make some problems I think, 
like... I think we will miss our download manager modal if we will change that 
behavior :_(
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
FluxDrop file manager
- [ ] Make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Add multiple files streaming (archive and stream to the server; one 
stream - a lot of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
- [ ] Add image placeholders between image fetch and display
- [ ] Add ability to preload the JPEG/any current format for previews like AVIF 
and for other files (contribute to the background media scan via FFmpeg)
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
on i5 8350U)
- [ ] Auto negotiation for upload type (folder or file)
- [ ] Add dark theme switch, or at least make addons work properly and test 
them
- [ ] Add close by click on the dimmed space into the links manager
- [ ] Make "X" non-scrollable in links manager (so can be closed without need 
to scroll to the top) and other modals
- [ ] Add loading wheel/bar into stats window since bad internet causes high 
wait times without knowing what it is doing
- [ ] Add progressbar for blob fetches
- [ ] Add `.7z` and `.rar` for file table previews (and other ones)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents
- [ ] Add "proper" loading wheels (1 second as least amount of time for the 
"apply" and other important features, more pleasant loadings for the file 
manager)

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
implemented due to code regression, checks are pending. -- by comments seems 
like to be implemented
- [ ] Check the CatBox API for file size limits
- [ ] Make separate "testing" server where I would be able to test everything 
before pushing to the real one


#### Medium:
- [ ] Sometimes FluxDrop makes config connections, resulting in 404, but right 
now I can't replicate it so I don't know why and I can't give any clues when 
that happens and after what


#### Low:
- [ ] Reduce amount of re-imports inside the code
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else) -- merged into the rela... 
No it's not since that entry issues the JSON multi-answer instead on only 
related to fetch/question
- [ ] Fix 206 not working in trash bin preview
- [ ] Add checkers for external HTTP and HTTPS hosters
- [ ] Add "enhanced" previews (bg activity that makes thumbs via FFmpeg for 
any type of file that's supported, thumbs can be included into the quota, or 
excluded from quota)
- [ ] Add partial content support for CatBox API and CDN itself for it's 
static hoster -- doesn't CDN have that already?
- [ ] Make special player with "video preview support", aka "slow internet 
mode" (re-convert the uploaded videos to the FluxDrop with AV1 to reduce 
bandwidth and resolution)
- [ ] Delete "CDN" path as it serves no purpose and doesn't work (line 5718 in 
`server_cdn.py`). Seems like it was made to make "shared" folder for any user 
of FluxDrop, but true usage is unknown since it's seems like undocumented and 
was introduced in one of the edit sessions without need to be made -- in the 
Terms and Policy, the same CDN may be mentioned with some explanatory of it's 
existence there
- [ ] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) -- WIP, low priority
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)
- [ ] (at some unnecessary point) Divide snippets to dedicated HTML, JS and CSS
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)

---

## Items that needs additional checks or implementations:

- [ ] Fix HSTS redirects for FluxDrop file manager - HTTP to HTTPS redirects 
that works with the FluxDrop, right now even login fails -- doesn't work, needs 
changes (v0.17.2.11)

---

## Done items that are pending for removal: