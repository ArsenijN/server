# Changelog — 2026-08-25

Commentary: this changelog may be not up-to-date always, strong recomendation 
to use Readme's patch notes across Git commits

## For one sesstion:

FILE SELECTION / UI BUGS

- Fixed: single-item delete via context menu left a stale entry in the 
selection set forever (deleteItem never removed the path from _selectedPaths).
- Added Del key hotkey to trash the current selection; extracted the repeated 
confirm-then-trash logic (sel-bar button, context-menu action, hotkey) into 
one shared _trashSelectedPaths() helper.
- Fixed Shift-click range selection: the anchor was tracked as a raw array 
index, which went stale the moment row order changed between clicks (sorting, 
folders-first toggle, a rename shifting alphabetical order) even without the 
selection itself being touched. This silently collapsed the "range" down to a 
single row. Replaced with a path-based anchor that's re-resolved at click time.
- Fixed a related race: fast repeated selection/deselection could leave a stale 
animation timeout that fired after a row was already re-selected, wiping the 
checkbox visual back to unselected even though the real selection state was 
correct. Added cancellation of pending dot-animation callbacks before starting 
a new one.
- Fixed drag-and-drop text selection across rows wiping the whole file 
selection. user-select:none was only set on individual rows (siblings, so it 
left gaps at row boundaries); moved it to the whole file-list container.
- File-info floating panel now explicitly closes on any row-select action 
instead of relying only on a delayed outside-click listener.

MODALS / ANIMATIONS

- Interrupted Uploads modal: added entrance/exit animations and Esc-to-close.
- Fixed the "Moving..."/"Renaming..." spinner overlay: the entrance animation 
referenced a keyframe name that didn't exist anywhere in the stylesheet (a typo 
- "fadeIn" instead of "fd-fade-in"), so it silently did nothing; the exit was 
an instant removal with no animation at all. Fixed both, added a reusable panel 
entrance animation class along the way.
- Replaced native browser prompt()/confirm() dialogs with custom-styled modals 
(folder creation, single/multi trash delete, empty trash, permanent delete), 
with Enter/Escape support.

TOASTS / NOTIFICATIONS

- Built a bottom-center toast/snackbar system (success/info/error/progress 
types, sticky variant, optional action buttons) to replace blocking full-screen 
messages for routine confirmations (moved to trash, folder created).
- Copy operations now show a sticky "Copying..." toast with real Cancel and 
Hide buttons instead of a blocking spinner.

COPY FEATURE

- The Copy feature was completely non-functional - the server had no /copy 
endpoint at all (client always got a 404). Implemented it from scratch: quota 
check, destination-collision guard, self-containment guard (can't copy a folder 
into itself).
- Converted it to a background job: the initial request only validates and 
returns a job id immediately, instead of blocking the whole HTTP request (and 
the reverse proxy's timeout) for the entire transfer of a large file/folder. 
Client polls a status endpoint.
- Added real mid-transfer cancellation: chunked copy with a cancel-flag check 
between chunks (not just between whole files), so cancelling a multi-GB copy 
actually takes effect within seconds instead of only being checked after the 
whole file finishes.
- Copied checksums now carry over to the new path (were previously lost, 
forcing a full recompute) for both moves/renames and copies.

UPLOADS

- Fixed upload progress inflating past the real uploaded amount after a retry 
(could show "8MB of 8MB" while the upload wasn't actually done). The root 
cause: a failed chunk attempt credited its bytes to the progress total, and 
nothing ever rolled that credit back on failure/timeout/abort, so repeated 
retries kept stacking fake progress on top of each other. Fixed by rolling back 
credited bytes on every non-success outcome.
- Fixed adaptive chunk sizing: the client measured upload speed via a probe but 
never actually used it to size chunks, always using a static server default. 
Now computes a chunk size targeting a safe transfer time at the measured speed.
- Fixed upload concurrency: the formula that seeds how many chunks upload in 
parallel was backwards for slow connections - a small chunk size (correctly 
picked for a slow link) used to seed maximum concurrency, splitting an 
already-thin connection across up to 6 simultaneous streams and making each 
individual chunk far slower than intended. Now concurrency is seeded from the 
actual measured speed, consistent with the chunk-size calculation.
- Upload cancel now shows an honest "Cancelling..." transitional state 
immediately, and the server-side cleanup call is actually waited on before the 
UI declares the upload cancelled (was fire-and-forget before).

PROFILE / AVATAR

- Fixed the profile avatar never being cached: every render built a fresh 
cache-busting URL (?t=Date.now()), defeating the browser cache on every single 
load. Replaced with a stable, versioned URL that only changes when the avatar 
actually changes.
- Fixed avatar sometimes loading the wrong (id 0 / placeholder) image on a first-ever login: the user's numeric id was only cached from two unreliable places (a login response field that isn't always present, or opening the Profile panel). Added a backfill check on every authenticated app load.

STATIC FILE SERVING / PROXY ROUTING

- Fixed .md files (policy/ToS documents) 404ing on the root domain (fluxdrop.me) - they were missing from the extension list that decides "this is a real file" vs "this is an app navigation route," so requests fell through to the app shell instead of the actual document.
- Fixed HEAD requests to API endpoints always 404ing - the HEAD handler in both the public-facing proxy and the internal backend never routed through the same logic GET requests use, so any HEAD-based request (like the client's connectivity probe) hit a generic static-file handler instead of the real API.
- Added gzip compression for .md files - this didn't exist at all before for static markdown files (the existing compression only covered dynamically generated JSON API responses).
- Fixed a real bug affecting large downloads: if reading from the upstream/backend failed partway through a proxied response - after headers were already sent to the browser - the code used to send a second, duplicate response status line into the middle of what the client thought was still file data, corrupting the transfer. This had already been fixed once in the Immich proxy function but was never copied over to the two other, nearly-identical proxy functions used for FluxDrop's own API and download traffic. Fixed in all three.
- Raised the Immich proxy's max upload size from 2GB to 16GB, and turned it into a clearly labeled, easy-to-find setting for future changes.

RELIABILITY / RESOURCE EXHAUSTION AUDIT

- The main backend process (which does the heaviest per-request work of the three server processes) was using an unbounded threading model - one new OS thread per connection, no limit at all - while the public-facing proxy already had a proper capped worker pool. Brought it in line: bounded pool, connections queue under heavy load instead of spawning unlimited threads.
- Found and fixed a connection-timeout bug: after successfully reading an uploaded chunk, the code cleared the connection's timeout entirely instead of restoring the normal default. This meant a connection that went silent afterward (phone sleeping mid-session, network dropping) could hang a worker thread forever instead of being detected and cleaned up.
- Audited every place the backend reads a request body sized by a client-supplied header, and found 14 places with no upper limit at all before reading the body into memory - including two reachable with little or no authentication. A request with a deliberately huge declared size could have forced the server to try to buffer an enormous amount of data. Added the same size cap already used correctly elsewhere in the codebase to all 14.

One thing flagged but intentionally not done: migrating off the current hand-rolled HTTP server framework. Recommended against gunicorn specifically (wrong tool - it's built around a request/response model that doesn't fit the raw streaming, WebSocket, and low-level socket control this app already depends on) in favor of what the project's own notes already pointed toward, but treated that as a deliberate future decision rather than something to rush into this session.