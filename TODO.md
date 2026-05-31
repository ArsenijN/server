# TODO

This file collects planned enhancements for FluxDrop.  Many items may arise from
user feedback or ideas for future development.

---

## Items that are pending for implementations:
- [ ] Show "Loading the acceptances..." for the acceptance modal if loading 
times are long, with some placeholder (like the current gradient-like for the 
main file manager UI)
- [ ] Auto negotiation for upload type (folder or file)


### Important without category (critical before release)

### UI
- [ ] i18n support (languages for FluxDrop UI and other things)
- [ ] Add "landing page" for CatBox API to use it from the browser, and also
- [ ] Add "CatBox API usage" page for CatBox API
- [ ] Make avatar support (pre-scale down to 64x64 px, compress via AVIF and 
JPG as fallback)
- [ ] Custom right-click menu for folders and files (reduce amount of options 
with files)
  - [ ] Add "..." (vertical) as "fallback"
- [ ] Add "view background connectivity debug console" in settings to see small 
one-liner somewhere at the bottom of the UI that will say what site currently 
try to fetch or do (at least via Internet)
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
- [ ] Redesign the move/rename/copy modals; delete modal

### UX
- [ ] Instead of errors like "failed to fetch" after internet reconnect, 
ALWAYS catch it and DO NOT drop the hard error - RETRY until it IS successfull,
 or at least the N times (reliable way to resume whatever operation is going)
- [ ] Make caching or optimize the quota size counting for reducing the time 
that is needed to process the 150k+ items -- made for status page, later for 
FluxDrop file manager
- [ ] Make an mobile version of the FluxDrop as an installable app 
via Chrome or as "native" Android Material Design one
- [ ] Add multiple files streaming (archive and stream to the server; one 
stream - a lot of files) feature to site UI from `batch_tar_upload.py`
- [ ] Make AJAX-like updates for the file manager (no visual reloads of the 
content)
- [ ] Add ability to preload the JPEG/any current format for previews like AVIF 
and for other files (contribute to the background media scan via FFmpeg)
- [ ] Check why HEIF files are slow to decode (on client, it takes ~5 seconds 
on i5 8350U)
- [ ] Add dark theme switch, or at least make addons work properly and test 
them
- [ ] Add loading wheel/bar into stats window since bad internet causes high 
wait times without knowing what it is doing
- [ ] Add `.7z` and `.rar` for file table previews (and other ones)
- [ ] Add .docx, .pptx, .odt, .odf, .ods, and so on documents

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
- [ ] Make separate "testing" server where I would be able to test everything 
before pushing to the real one


#### Medium:
- [ ] Sometimes FluxDrop makes config connections, resulting in 404, but right 
now I can't replicate it so I don't know why and I can't give any clues when 
that happens and after what


#### Low:
- [ ] Fully fix the logs duplication issue
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

- [ ] Fix HSTS redirects for FluxDrop file manager - HTTP to HTTPS redirects 
that works with the FluxDrop, right now even login fails -- doesn't work, needs 
changes (v0.17.2.11)
- [ ] Missing ZIP's files may be never displayed on client

---

## Done items that are pending for removal:
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


## Additional notes
Note to myself: this is weird
```
...
[2026-05-22 01:15:15] 2026-05-22 01:15:15,526 [INFO] (Thread-654 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:15:15] 2026-05-22 01:15:15,526 [INFO] (Thread-654 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:15:21] Updating blacklist...
[2026-05-22 01:15:21] Updating blacklist...
[2026-05-22 01:15:21] Blacklist loaded: 79 entries.
[2026-05-22 01:15:21] Blacklist loaded: 79 entries.
[2026-05-22 01:15:58] 2026-05-22 01:15:58,044 [WARNING] (Thread-655 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:15:58] 2026-05-22 01:15:58,044 [WARNING] (Thread-655 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:15:58] 2026-05-22 01:15:58,049 [INFO] (Thread-655 (process_request_thread)) 127.0.0.1 - "GET /api/.env HTTP/1.1" 404 -
[2026-05-22 01:15:58] 2026-05-22 01:15:58,049 [INFO] (Thread-655 (process_request_thread)) 127.0.0.1 - "GET /api/.env HTTP/1.1" 404 -
[2026-05-22 01:16:02] 2026-05-22 01:16:02,801 [WARNING] (Thread-656 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:16:02] 2026-05-22 01:16:02,801 [WARNING] (Thread-656 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:16:02] 2026-05-22 01:16:02,802 [INFO] (Thread-656 (process_request_thread)) 127.0.0.1 - "GET /api/test HTTP/1.1" 404 -
[2026-05-22 01:16:02] 2026-05-22 01:16:02,802 [INFO] (Thread-656 (process_request_thread)) 127.0.0.1 - "GET /api/test HTTP/1.1" 404 -
[2026-05-22 01:16:15] 2026-05-22 01:16:15,649 [INFO] (Thread-657 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:16:15] 2026-05-22 01:16:15,649 [INFO] (Thread-657 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:16:21] Updating blacklist...
[2026-05-22 01:16:21] Updating blacklist...
[2026-05-22 01:16:21] Blacklist loaded: 79 entries.
[2026-05-22 01:16:21] Blacklist loaded: 79 entries.
[2026-05-22 01:17:15] 2026-05-22 01:17:15,791 [INFO] (Thread-658 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:17:15] 2026-05-22 01:17:15,791 [INFO] (Thread-658 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
```
Is that the "config" 404s caused on client that was mentioned in the TODO?
Maybe it's when it drops the internet?


At some point CDN starts to dup the output:
```
[2026-05-27 19:33:56] 2026-05-27 19:33:56,889 [INFO] (Thread-205 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/LOxWqcPBBEDfPEfEYxf
[REDACTED]/chunk/0 HTTP/1.1" 200 -
[2026-05-27 19:33:56] 2026-05-27 19:33:56,888 [INFO] (Thread-205 (process_request_thread)) Chunk received: token=LOxWqcPBBEDf… idx=0 (25600KB) 1/261
[2026-05-27 19:33:56] 2026-05-27 19:33:56,888 [INFO] (Thread-205 (process_request_thread)) Chunk received: token=LOxWqcPBBEDf… idx=0 (25600KB) 1/261
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/init HTTP/1.1" 200 
-
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/init HTTP/1.1" 200 
-
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… file=Hacksaw Ridge 
(2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv chunks=261 owner=user
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… file=Hacksaw Ridge 
(2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv chunks=261 owner=user
[2026-05-27 19:33:54] 2026-05-27 19:33:54,066 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… strategy=direct fil
e='Hacksaw Ridge (2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv' size=6834559158 chunks=261
[2026-05-27 19:33:54] 2026-05-27 19:33:54,066 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… strategy=direct fil
e='Hacksaw Ridge (2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv' size=6834559158 chunks=261
[2026-05-27 19:33:53] 2026-05-27 19:33:53,384 [INFO] (Thread-203 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/speed_probe HTTP/1.
1" 200 -
[2026-05-27 19:33:53] 2026-05-27 19:33:53,340 [INFO] (Thread-202 (process_request_thread)) 127.0.0.1 - "GET /api/v1/upload_session/config HTTP/1.1" 200
 -
[2026-05-27 19:33:50] Blacklist loaded: 79 entries.
[2026-05-27 19:33:50] Updating blacklist...
[2026-05-27 19:33:43] 2026-05-27 19:33:43,538 [INFO] (Thread-201 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/tmp/METALLICA%20._Best%2
0Magnetic_ HTTP/1.1" 200 -
[2026-05-27 19:33:43] 2026-05-27 19:33:43,457 [INFO] (Thread-200 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/tmp/%D0%A1%D0%B5%D1%81%D
1%96%D1%8F%201%20%E2%80%93%20%D0%BA%D0%BE%D0%BF%D1%96%D1%8F HTTP/1.1" 200 -
[2026-05-27 19:33:43] 2026-05-27 19:33:43,425 [INFO] (Thread-199 (process_request_thread)) 127.0.0.1 - "GET /api/v1/list/tmp HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,957 [INFO] (Thread-198 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/xair HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,877 [INFO] (Thread-197 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/tmp HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,801 [INFO] (Thread-196 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/sort%20later HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,720 [INFO] (Thread-195 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/shareables HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,636 [INFO] (Thread-194 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/sdfsf HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,558 [INFO] (Thread-193 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/Phone HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,481 [INFO] (Thread-192 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/ocr HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,399 [INFO] (Thread-191 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/NewFolder77 HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,318 [INFO] (Thread-190 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/linlap HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,289 [INFO] (Thread-189 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/From_CDN HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,157 [INFO] (Thread-188 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/from%2016GB%20USB%20Thumb HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,081 [INFO] (Thread-187 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/.trash HTTP/1.1" 200 -
:
```
Also CDN should lock the files so it will never re-read the same folder if worker (for ZIP creation/generation) is started, and the main thing - do not spawn new worker on the same job
Also, need to implement so if ping isn't coming for more than 3 seconds, or otherwise - client cancels the download of ZIP - stop the worker or do something so it will add the files to pending list, and the computed hashes will be saved anyway
Also I think the server just can't get the hashes from the DB at some point and just do that fail silently