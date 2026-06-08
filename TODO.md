# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:

### Important without category (critical before release)
- [ ] Pause button may not work rn -- it's not but UI may bug so it can display 
"Missing chunks" but actually it then ends successfully
- [ ] Encryption algorithm fallbacks (for faster downloads, use the 
`TLS_CHACHA20_POLY1305_SHA256`, for regular or high important secure things use 
the default options)
- [ ] Check HTTP->HTTPS forwarding for CDN downloads/usage
- [ ] `http://arseniusgen.uk.to/api/v1/policy/status` fails with 
`NS_ERROR_NET_TIMEOUT` even if client gets it (fully)
- [ ] Client still can fail with Chunk timeout even with new retry attempts

### UI
- [ ] Markdown parser does not understand:
  - [ ] The tables
  - [ ] The new line inside code blocks
- [ ] Trash bin file preview inside folders
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API
- [ ] Make avatar support (pre-scale down to 64x64 px, compress via AVIF and 
JPG as fallback)
- [ ] Custom right-click menu for folders and files (reduce amount of options 
with files)
  - [ ] Add "..." (vertical) as "fallback"
- [ ] Make proper header and footer for the main FluxDrop UI
- [ ] Add MIDI and modules player (tracker music). Inspired by modarchive.org
- [ ] Footer versioning: make versioning system the same as the current with 
server (like v0.17.2.4)
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
- [ ] Redesign the move/rename/copy/delete modals

### UX
- [ ] Click on the "quota usage" should open the quota space analyzer
- [ ] Ability to download the shared folders without JS (fallback option)
- [ ] Instead of errors like "failed to fetch" after internet reconnect, 
ALWAYS catch it and DO NOT drop the hard error - RETRY until it IS successfull,
 or at least the N times (reliable way to resume whatever operation is going) 
 -- should be already fixed by resumable file downloads, but not after when 
 internet is resolved -- will be rephrased:
- [ ] ~~Ensure that FluxDrop will retry whatever operation is failed because of 
the internet switch~~
- [ ] Catch 'failed to fetch' errors - retry until success or N times (reliable 
resume). It should be already fixed for resumable downloads, but ensure it will
work after internet reconnect
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
FluxDrop file manager
- [ ] Make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Add multiple files streaming (archive and stream to the server; one 
stream - a lot of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make file upload multithreaded (2+ files processing simultaneously on 
upload)
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
- [ ] Add ability to preload the JPEG/any current format for previews like AVIF 
and for other files (contribute to the background media scan via FFmpeg)
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
on i5 8350U)
- [ ] Add `.7z`, `.rar` and other archive types for file table previews
- [ ] Add `.docx`, `.pptx`, `.odt`, `.odf`, `.ods`, and other for previews
- [ ] Add `.dng` and other raw image formats support for previews

- [ ] **Family/Group accounts**
  - [ ] Let two or more usernames share a common root directory with mutual
    read/write privileges.
  - [ ] Add settings to control whether group members may add/remove other
    users, set quotas, etc.

- [ ] **Misc future ideas**
  - [ ] Server-side filename sanitisation for illegal characters.
  - [ ] Explicit **move** and **copy** endpoints (avoid awkward rename paths).

### Server-side changes:

#### Critical:
- [ ] Make separate "testing" server where I would be able to test everything 
before pushing to the real one

#### Medium:

#### Low:
- [ ] Reduce amount of re-imports inside the code
- [ ] Add server ability to push the additional data before client will request 
them (pre-caching; like folder structures, quota, file properties, download 
tokens (pre-generate the download tokens for files to fasten up the ping 
issues (aka preview tokens), or resolve the issues that FluxDrop is very 
unstable in bad internet areas) or something else) -- merged into the rela... 
No it's not since that entry issues the JSON multi-answer instead on only 
related to fetch/question
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
existence there -- aha! The CDN is made so user can separate it's drive and not 
clog the own drive with hosting materials, and also, I think that it can be 
easily managed via API (or will be). The next patch will change that "delete" 
to "implement"
- [ ] Migration to other host platform for HTTP and HTTPS efficiency and 
optimizations (Python; go to gunicorn or something else) -- WIP, low priority
- [ ] (future) Replace the server hardware (aka FluxDrop + home NAS with proper 
storage media)
- [ ] (at some unnecessary point) Divide snippets to dedicated HTML, JS and CSS
- [ ] Discover ways to build own page via modules (zero-code; not necessary 
since I can just remember CSS and HTML, and do that by hands)

---

## Items that needs additional checks or implementations:
- [ ] Missing ZIP's files may be never displayed on client
- [ ] Check the acceptance modal loader on slow internet when new terms will be 
made/applied
- [ ] Sometimes FluxDrop makes config connections, resulting in 404, but right 
now I can't replicate it so I don't know why and I can't give any clues when 
that happens and after what
- [ ] Dark mode auto switch
- [ ] HSTS redirect should work correctly

---

## Done items that are pending for removal as finished:
- [x] Add Welcome screen for new users that will explain (almost) everything 
about FluxDrop
- [x] Add image placeholders between image fetch and display
- [x] Add progressbar for blob fetches
- [x] Add "proper" loading wheels (1 second as least amount of time for the 
"apply" and other important features, more pleasant loadings for the file 
manager). That means that for important things it will display at least 1 
second and will look like it is indeed "loads"
- [x] Add fix for the timed out chunks causing full file reupload from the part 
where it's failed instead of pushing only the unloaded/wrong part of the file 
(aka reduce very large internet overhead) -- immediatelly on error, not need in 
the page reload to bring that
- [x] Upload can fail on slow internet, causing unability to upload the files 
to server
- [x] Fully fix the logs duplication issue

- [x] i18n support (languages for FluxDrop UI and other things)

- [x] Add "view background connectivity debug console" in settings to see small 
one-liner somewhere at the bottom of the UI that will say what site currently 
try to fetch or do (at least via Internet)
- [x] Add trash bin folder preview
- [x] Add quota "space analyzer" (like WizTree or Filelight or whatever - it 
will display what files takes the most, where and what)

- [x] Add dark theme switch, or at least make addons work properly and test 
them
- [x] Add loading wheel/bar into stats window since bad internet causes high 
wait times without knowing what it is doing
- [x] Fix 206 (Partial content) not working in trash bin preview

- [x] Show "Loading the acceptances..." for the acceptance modal if loading 
times are long, with some placeholder (like the current gradient-like for the 
main file manager UI)
- [x] Auto negotiation for upload type (folder or file) -- doesn't work properly

- [x] Fix text not being reverted back to the dark when changed from light to 
dark to light mode

Also I think the server just can't get the hashes from the DB at some point and 
just do that fail silently -- fixed

- [x] **Legacy usage without JS** — at minimum, users should be able to
  download shared files without JavaScript enabled. -- works for files but not 
  "Download folder as ZIP" -- will be moved as separate TODO entry for ZIP 
  folder download ability without the JS being enabled or accessible (e.g. 2010 
  Samsung S5250 Wave 525 on bada OS inside the built-in browser (because it may 
  not support some JS) or K-Meleon with JS disabled?)

(end of release note there)

- [x] Fix HSTS redirects for FluxDrop file manager - HTTP to HTTPS redirects 
that works with the FluxDrop, right now even login fails -- doesn't work, needs 
changes (v0.17.2.11) -- `Location` header have 
`https://127.0.0.1:64800/auth/login` inside it, this cause the problem with the 
HSTS redirect, maybe caused because of the multiple 
`_redirect_to_https_if_needed` definitions inside `server_cdn.py` or something 
else

- [x] Check the captcha implementation

---

*Note: **the "Done items that are pending for removal as finished" will purge 
the items inside it when the release version will be ready***

*Note: **additional notes is now moved to the [DEVNOTES.md](/DEVNOTES.md), 
please reach to it to acknowledge those notes***