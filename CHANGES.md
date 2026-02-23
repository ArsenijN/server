# Changelog

**FluxDrop / Self-Host Server** — current vs. previous version (by commit version)

---

## `server_cdn.py`

### ✨ New Features

#### 1. Shared Link: `allow_preview` Flag
- New `allow_preview` column added to the `shared_links` database table.
- When enabled on a folder share, files in the listing show a 👁 preview button alongside the download button.
- Clicking the button opens an inline preview modal without navigating away.
- Supported via a `?preview=1` query parameter on any file URL within the share.
- Exposed in the create-share API (`POST` body: `allow_preview: true`) and patchable via the existing share-update endpoint.

#### 2. Shared Link: `allow_cdn_embed` Flag
- New `allow_cdn_embed` column for single-file shares.
- When set, the share URL serves the file inline (correct MIME type, no `Content-Disposition: attachment`), allowing it to be embedded directly in `<img>`, `<video>`, Discord unfurls, external websites, etc.
- The share URL itself acts as a public CDN URL — no authentication required.
- Access is logged with `action = "embed"` instead of `"download"`.
- The share-creation UI gains a **CDN Embed URL** copy box when this option is active.

#### 3. Inline File Preview Modal on Public Share Pages
- A lightweight preview overlay is injected into the server-side-rendered share folder HTML.
- Supports images, video, audio, and text/code files — detected by extension.
- ESC key and clicking outside the modal close the overlay.
- Media elements (video/audio) are properly stopped and cleared on close to avoid background playback.
- Text files are truncated at 50,000 characters with a visible `…(truncated)` notice.

#### 4. Create Subfolder on Public Share — `POST /share/<token>/mkdir`
- Visitors with upload permission can now create subfolders inside a shared folder.
- New endpoint: `POST /share/<token>/mkdir` — body: `{ "subpath": "parent/NewFolder" }`.
- A **📁 New Folder** button appears in the upload area of any writable share page.
- Path traversal protection: the resolved directory must remain inside the share's base directory (`realpath` check).

#### 5. Upload Into Subfolders of a Public Share
- `POST /share/<token>/upload` now accepts an optional `?subpath=<relative>` query parameter.
- Files are deposited into the specified subfolder rather than the root of the share.
- The share page passes the current browsed sub-path automatically, so uploading while inside a subdirectory works transparently.
- Path traversal protection applies (same `realpath` check as mkdir).
- Upload log now includes the `subpath` field for easier auditing.

#### 6. Download-Token Auth for Media Elements (`<img>`, `<video>`, `<audio>`)
- The `/cdn/<command>/<path>` handler now performs an early `dl_token` lookup before the normal session-token auth check.
- A valid (non-expired) `dl_token` in the `?dl_token=` query parameter is enough to establish the `user_id` for a download, even when the browser sends no `Authorization` header.
- This allows HTML media tags to load protected CDN files by embedding the token in the `src` URL.

### 🔧 Improvements & Bug Fixes

- **RFC 5987/8187 `Content-Disposition` for non-ASCII filenames** — new `_content_disposition()` helper correctly encodes Cyrillic, spaces, and other special characters using both `filename=` and `filename*=UTF-8''` parameters.
- **Percent-encoded share paths decoded before filesystem resolution** — fixes 404 errors for files with spaces or non-ASCII names in share URLs.
- **Breadcrumb and entry URLs now use `quote()` per path segment** — produces valid percent-encoded hrefs for all folder and file links.
- **DB migration refactored into a single loop** — `expires_at`, `allow_preview`, and `allow_cdn_embed` are all migrated in one place, making future column additions trivial.
- **`download_tokens` query now returns `user_id`** — enables the early `dl_token` auth described above.
- **`quote` imported from `urllib.parse`** — added to support URL encoding in the new path-building code.

---

## `index.html` (Frontend UI)

### ✨ New Features

#### 1. Full Media & Text Preview Modal
- Replaced the old plain-text-only `previewText()` with a universal `previewFile()` function.
- Detects file type by extension and renders:
  - **Images** — `<img>` tag (`jpg`, `jpeg`, `png`, `gif`, `webp`, `bmp`, `svg`, `ico`, `avif`, `tiff`, …)
  - **Video** — `<video autoplay controls>` (`mp4`, `webm`, `ogg`, `mov`, `mkv`, `avi`, …)
  - **Audio** — large music-note icon + `<audio autoplay controls>` (`mp3`, `wav`, `flac`, `aac`, `opus`, …)
  - **Text/code** — `<pre>` block truncated at 50,000 chars (30+ supported extensions)
  - **Binary/unknown** — friendly "No preview" placeholder with a Download button
- Dedicated `#preview-modal` with a dark overlay, ✕ close button, and inline Download button.
- ESC key closes the preview modal (or the message modal if preview is not open).
- Video and audio elements are stopped and cleared when the modal closes.
- `previewText` aliased to `previewFile` for backwards compatibility.

#### 2. `allow_preview` and `allow_cdn_embed` Options in Share Dialog
- Two new checkboxes in the **Create Share** dialog:
  - **Allow file preview** — enables `?preview=1` mode for visitors browsing a folder share.
  - **Allow CDN embedding** *(single-file shares only)* — makes the link serve the file inline.
- Both flags are sent to the server in the create-share `POST` body.
- The share management panel shows live toggles for both flags that `PATCH` the share via the API.
- When CDN embed is active, a highlighted box shows the **CDN Embed URL** with a one-click copy button and a usage hint.

#### 3. Clickable File/Folder Names in the File Listing
- File and folder names are now rendered as clickable `<a>` links instead of plain text.
- Clicking a **folder name** is equivalent to clicking **Open**.
- Clicking a **file name** opens the preview modal (same as the Preview button).
- 📁 and 📄 icons are prepended to names for quick visual distinction.

### 🔧 Improvements & Bug Fixes

- **`escapeHtml()` utility added** — replaces scattered inline `.replace()` calls throughout the rendering code. All dynamic HTML now uses this helper consistently.
- **`showMessage()` accepts an optional `isHtml` flag** — when `true`, content is inserted via `innerHTML` instead of `textContent`, fixing the share stats table rendering.
- **`open-btn` and `preview-btn` handlers call `e.preventDefault()`** — prevents default `<a>` navigation when the element is a link.

---

## Other Files

No changes in any of the following files:

| File | Status |
|---|---|
| `server_http.py` | Unchanged |
| `server_https.py` | Unchanged |
| `shared.py` | Unchanged |
| `config.py` | Unchanged |

---

*Generated by comparing current vs. `_old` file pairs.*