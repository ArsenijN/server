// ======================================================================
        // --- DEBUG ---
        // ======================================================================
// Current version of script.js is: fluxdrop-v-604d7592

        // ======================================================================
        // --- CONFIGURATION ---
        // ======================================================================
// Prefer HTTPS, but fall back to HTTP if HTTPS is unreachable
const API_HTTPS = `https://${window.location.hostname}`;
const API_HTTP  = `http://${window.location.hostname}`;

const SCRIPT_VERSION_RAW = 'v-604d7592'; // Replaced by your build script
const SCRIPT_VERSION = SCRIPT_VERSION_RAW.replace(/^(?:fluxdrop-)?(?:v-)?/, '');

// Pick a sensible base URL depending on how the page was loaded.  We
// default to the same protocol in order to avoid mixed‑content issues when
// the UI is served over plain HTTP, and we also provide a fallback helper
// that can switch protocols if the HTTPS endpoint is unreachable.
let API_BASE_URL = (window.location.protocol === 'https:' ? API_HTTPS : API_HTTP);

// helpers ----------------------------------------------------------------
// convert an internal path (which may contain ?, ', etc.) into a portion of
// a URL without confusing the browser.  This leaves leading slashes intact.
function encodePath(p) {
    if (p === '/') return '/';
    return p.split('/').map(encodeURIComponent).join('/');
}

// helpers for escaping values used in HTML attributes and JS code
function escapeHtmlAttr(str) {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
}

// safely produce a JavaScript string literal for use inside JS code (not
// attributes).  JSON.stringify already escapes as needed, and we also escape
// apostrophes so the result is safe inside either quote style.
function safeJs(str) {
    return JSON.stringify(str).replace(/'/g, "\\'");
}

async function fetchWithFallback(url, options) {
    // If the body is an ArrayBuffer, snapshot it now before the first fetch
    // consumes/detaches the buffer — the fallback retry needs a fresh copy.
    let bodySnapshot = null;
    if (options && options.body instanceof ArrayBuffer) {
        bodySnapshot = options.body.slice(0);
    }
    try {
        return await fetch(url, options);
    } catch (err) {
        // Network-level failure.
        // If the page itself is loaded over HTTPS, don't attempt an HTTP fallback (browser will block mixed content).
        console.warn('Fetch failed:', err);
        if (window.location.protocol === 'http:') {
            try {
                API_BASE_URL = API_HTTP;
                const altUrl = url.replace(API_HTTPS, API_HTTP);
                const retryOptions = bodySnapshot
                    ? { ...options, body: bodySnapshot }
                    : options;
                return await fetch(altUrl, retryOptions);
            } catch (err2) {
                throw err2;
            }
        }
        throw err;
    }
}

// P9: New version banner ─────────────────────────────────────────────────
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', event => {
        if (event.data && event.data.type === 'SW_UPDATED') {
            _showUpdateBanner();
        }
    });
}

function _showUpdateBanner() {
    if (document.getElementById('fd-update-banner')) return; // already shown
    const banner = document.createElement('div');
    banner.id = 'fd-update-banner';
    banner.style.cssText = [
        'position:fixed', 'bottom:1rem', 'left:50%', 'transform:translateX(-50%)',
        'background:#1e40af', 'color:#fff', 'padding:0.6rem 1.2rem',
        'border-radius:0.75rem', 'font-size:0.9rem', 'z-index:99999',
        'display:flex', 'align-items:center', 'gap:0.75rem',
        'box-shadow:0 4px 12px rgba(0,0,0,0.25)'
    ].join(';');
    banner.innerHTML = `
        <span>🔄 A new version of FluxDrop is available.</span>
        <button onclick="_fdHardReload()" style="
            background:#fff;color:#1e40af;border:none;border-radius:0.5rem;
            padding:0.3rem 0.8rem;font-weight:600;cursor:pointer;">
            Reload
        </button>
        <button onclick="this.parentElement.remove()" style="
            background:none;border:none;color:#fff;cursor:pointer;font-size:1.1rem;">
            ✕
        </button>`;
    document.body.appendChild(banner);
}
// Hard reload: asks the SW to evict only OLD caches (not the current one),
// then reloads the page.  Keeping the current cache means the SW won't
// re-run install/activate on the reloaded page and won't fire SW_UPDATED
// on a page that is already running the latest code.
async function _fdHardReload() {
    try {
        if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
            await new Promise((resolve) => {
                const ch = new MessageChannel();
                ch.port1.onmessage = resolve;
                navigator.serviceWorker.controller.postMessage(
                    { type: 'SKIP_AND_CLEAR' }, [ch.port2]
                );
                // Safety timeout — reload even if SW doesn't respond
                setTimeout(resolve, 5000);
            });
        }
    } catch { /* non-fatal */ }
    // Set a flag so the staleness check on the next page load knows this is
    // a deliberate update-reload and skips the banner immediately.
    try { sessionStorage.setItem('fd_just_updated', '1'); } catch (_) {}
    location.reload();
}

        // ======================================================================
        // --- GLOBAL STATE & DOM ELEMENTS ---
        // ======================================================================
const appRoot = document.getElementById('app-root');
const authControls = document.getElementById('auth-controls');

let authToken = localStorage.getItem('fluxdrop_token');
let currentUsername = localStorage.getItem('fluxdrop_username');
let isAdmin = localStorage.getItem('fluxdrop_is_admin') === '1';
// Track the currently viewed path in the file browser (always starts at root)
let currentPath = '/';
// Best-effort cache of the current Trash retention period, kept up to date
// from every server response that mentions it (trash list, delete response).
// Used to word the "Delete N items?" confirmation dialog realistically
// without a dedicated round-trip before every delete — defaults to the
// standard 30-day period until we learn otherwise.
let _lastKnownRetentionDays = 30;
let _lastUploadBatchCount = 0;  // P10: tracks file count in the current upload batch
// When a multi-file upload queue hits a paused item, draining stops and the
// continuation is parked here; the tray's Resume/Cancel handlers call it to
// pick the queue back up. null when no queue is waiting on a pause.
let _pausedQueueDrain = null;
// Set right before programmatically opening the file picker from the mobile
// upload FAB (see _initMobileUploadFab). There's no visible upload form on
// touch-only devices to press "Upload" on, so the resulting file selection
// should submit immediately instead of just updating a label nobody can see.
let _mobileUploadPending = false;
// P11: URL-path navigation ────────────────────────────────────────────────

// P11: Derive the app's base directory from the current page URL at runtime.
// Works whether the app lives at "/" or "/fluxdrop_pp/" or any other subpath —
// no hardcoded path needed. Strips "index.html" if present.
const _APP_BASE = (() => {
    // Strip index.html, then strip /files and everything after it so that
    // reloading on a deep-link URL like /fluxdrop_pp/files/foo doesn't make
    // _APP_BASE include "/files/foo" and cause double-/files on next render.
    let base = window.location.pathname
        .replace(/\/index\.html$/, '')
        .replace(/\/files(\/.*)?$/, '');
    // Ensure no trailing slash (we add one when building URLs below)
    return base.endsWith('/') ? base.slice(0, -1) : base;
})();

// Push a new folder path into the browser history and navigate to it.
function navigateTo(path) {
    if (path === currentPath) return;
    // Clear the multi-selection on a real folder change, unless the user
    // opted into "keep selection while browsing" via the fd-sel-bar
    // checkbox. Must happen here, before currentPath is reassigned below —
    // loadDirectory() itself can't tell "new navigation" from "same-folder
    // refresh" once currentPath already matches the incoming path.
    if (!window._fdKeepSelectionOnNav) {
        _selectedPaths.clear();
        _lastClickedPath = null;
    }
    currentPath = path;
    const urlPath = _APP_BASE + '/files' + (path === '/' ? '' : encodePath(path));
    history.pushState({ fdPath: path }, '', urlPath);
    loadDirectory(path);
}

// Replace the current history entry (used on initial load, not for user clicks).
function _syncUrlToPath(path) {
    const urlPath = _APP_BASE + '/files' + (path === '/' ? '' : encodePath(path));
    history.replaceState({ fdPath: path }, '', urlPath);
}

// Restore path when user clicks Back/Forward
window.addEventListener('popstate', event => {
    const path = (event.state && event.state.fdPath) ? event.state.fdPath : '/';
    if (path !== currentPath && !window._fdKeepSelectionOnNav) {
        _selectedPaths.clear();
        _lastClickedPath = null;
    }
    currentPath = path;
    loadDirectory(path);
});


// Sorting state — persisted across page reloads via localStorage
let currentSort = (() => {
    try { return JSON.parse(localStorage.getItem('fluxdrop_sort')) || { key: 'name', dir: 'asc' }; }
    catch { return { key: 'name', dir: 'asc' }; }
})();
// Whether folders are sorted together with files (false = folders always first)
let sortFoldersMixed = (() => {
    try { return JSON.parse(localStorage.getItem('fluxdrop_sort_mixed')) || false; }
    catch { return false; }
})();

        // ======================================================================
        // --- UTILITY FUNCTIONS ---
        // ======================================================================
// Enforce a minimum perceived duration for important async operations.
function withMinDelay(promise, minMs = 1000) {
    const t0 = Date.now();
    return promise.then(
        value => {
            const elapsed = Date.now() - t0;
            const wait    = Math.max(0, minMs - elapsed);
            if (wait === 0) return value;
            return new Promise(resolve => setTimeout(() => resolve(value), wait));
        },
        err => {
            const elapsed = Date.now() - t0;
            const wait    = Math.max(0, minMs - elapsed);
            if (wait === 0) throw err;
            return new Promise((_, reject) => setTimeout(() => reject(err), wait));
        }
    );
}

// Show a loading spinner overlay with a message. Returns a dismiss function.
function showSpinnerOverlay(message = 'Loading…', opts = {}) {
    const minMs = opts.minMs != null ? opts.minMs : 1000;
    const id    = opts.id || ('fd-spinner-' + Date.now());
    const overlay = document.createElement('div');
    overlay.id = id;
    overlay.style.cssText = [
        'position:fixed;top:0;left:0;width:100%;height:100%;z-index:10400',
        'background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center',
        'animation:fd-fade-in .15s ease',  // was 'fadeIn' — that keyframe doesn't exist anywhere
                                            // in the stylesheet (only fd-fade-in does), so this
                                            // was silently a no-op the whole time.
    ].join(';');
    overlay.innerHTML = '<div class="fd-modal-panel-in" style="background:#1e293b;border-radius:1rem;padding:2rem 2.5rem;display:flex;' +
        'flex-direction:column;align-items:center;gap:1rem;' +
        'box-shadow:0 16px 48px rgba(0,0,0,.5);min-width:180px;text-align:center">' +
        '<div style="width:44px;height:44px;border-radius:50%;border:4px solid #334155;' +
        'border-top-color:#3b82f6;animation:fd-spin .7s linear infinite"></div>' +
        '<div style="color:#e2e8f0;font-size:.93rem;font-weight:500">' + escapeHtml(message) + '</div></div>';
    if (!document.getElementById('fd-spin-style')) {
        const st = document.createElement('style');
        st.id = 'fd-spin-style';
        st.textContent = '@keyframes fd-spin{to{transform:rotate(360deg)}}';
        document.head.appendChild(st);
    }
    document.body.appendChild(overlay);
    const shown = Date.now();
    return function dismiss() {
        const wait = Math.max(0, minMs - (Date.now() - shown));
        // fdCloseOverlay plays the same fade-out + panel-scale-out exit
        // every other overlay in the app uses, instead of an instant
        // .remove() with no animation at all.
        const _rm = function() { const el = document.getElementById(id); if (el) window.fdCloseOverlay(el); };
        if (wait <= 0) _rm(); else setTimeout(_rm, wait);
    };
}

function showModal(id) {
    const modal = document.getElementById(id);
    // Defensive cleanup in case the modal is being re-shown while a previous
    // hideModal() animation hasn't finished yet.
    modal.classList.remove('hidden', 'fd-overlay-closing');
    delete modal.dataset.fdClosing;
    const content = modal.querySelector('.modal-content');
    if (content) content.classList.remove('fd-panel-closing');
}
function hideModal(id) {
    const modal = document.getElementById(id);
    if (!modal || modal.classList.contains('hidden') || modal.dataset.fdClosing) {
        _detachModalKeys();   // P12: always clean up keyboard handler on close
        return;
    }
    _detachModalKeys();   // P12: always clean up keyboard handler on close

    modal.dataset.fdClosing = '1';
    modal.classList.add('fd-overlay-closing');
    const content = modal.querySelector('.modal-content');
    if (content) content.classList.add('fd-panel-closing');

    let done = false;
    const finish = () => {
        if (done) return;
        done = true;
        modal.classList.remove('fd-overlay-closing');
        if (content) content.classList.remove('fd-panel-closing');
        delete modal.dataset.fdClosing;
        modal.classList.add('hidden');
    };
    modal.addEventListener('animationend', finish, { once: true });
    setTimeout(finish, 200); // safety net if animationend doesn't fire
}

// P12: Enter confirms / Escape cancels any open modal.
// capture:true intercepts the keydown before it reaches background list rows.
let _modalKeyHandler = null;

function _attachModalKeys(confirmFn, cancelFn) {
    _detachModalKeys();
    _modalKeyHandler = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            e.stopPropagation();
            _detachModalKeys();
            if (confirmFn) confirmFn();
        } else if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            _detachModalKeys();
            if (cancelFn) cancelFn();
        }
    };
    document.addEventListener('keydown', _modalKeyHandler, true);
}

function _detachModalKeys() {
    if (_modalKeyHandler) {
        document.removeEventListener('keydown', _modalKeyHandler, true);
        _modalKeyHandler = null;
    }
}

function stripInternalPrefix(path) {
    return path.replace(/^\/FluxDrop\/\d+\//, '/');
}

// ── Avatar URL (cacheable) ───────────────────────────────────────────────────
// Every avatar <img> render site used to build its own `?t=${Date.now()}`
// cache-buster inline — which made the URL unique on *every single render*
// (page load, opening the profile menu, opening the profile panel), so the
// browser could never cache the avatar even though it rarely changes.
// Fix: the cache-buster is now a stored "version" that only advances when the
// avatar is actually uploaded or removed (see _bumpAvatarVersion below), so a
// normal render reuses the same URL and the browser's HTTP cache applies.
const _AVATAR_VERSION_KEY = 'fd-avatar-v';

function _avatarUrl(userId) {
    const uid = userId || localStorage.getItem('fluxdrop_user_id') || '0';
    const v = localStorage.getItem(_AVATAR_VERSION_KEY) || '0';
    return `${API_BASE_URL}/api/v1/avatar/${encodeURIComponent(uid)}?v=${v}`;
}

// Call this exactly when the avatar content actually changes (upload/remove)
// to force every subsequent render to fetch the new image instead of a
// cached copy of the old one.
function _bumpAvatarVersion() {
    localStorage.setItem(_AVATAR_VERSION_KEY, String(Date.now()));
}

function escapeHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showMessage(title, content, isHtml = false) {
    document.getElementById('message-modal-title').textContent = title;
    const el = document.getElementById('message-modal-content');
    if (isHtml) { el.innerHTML = content; } else { el.textContent = content; }
    showModal('message-modal');
    // P12: Enter or Escape both dismiss the OK-only message modal
    _attachModalKeys(
        () => hideModal('message-modal'),
        () => hideModal('message-modal')
    );
}

// ── Bottom-center toast/snackbar ─────────────────────────────────────────────
// For quick, self-explanatory confirmations (item moved to Trash, folder
// created, etc.) that don't need the user to stop and read/dismiss a
// full-screen modal every single time. Reserve showMessage() for things that
// genuinely need acknowledgement: errors, failures, and anything requiring a
// decision or careful reading.
//
// Stacks multiple toasts (newest at the bottom), auto-dismisses each on its
// own timer, and reuses the existing fd-tray-slide-in/out keyframes (already
// defined in the stylesheet for the upload/download ETA tray) rather than
// introducing a new animation.
function _getToastStack() {
    let stack = document.getElementById('fd-toast-stack');
    if (!stack) {
        stack = document.createElement('div');
        stack.id = 'fd-toast-stack';
        stack.className = 'fd-toast-stack';
        document.body.appendChild(stack);
    }
    return stack;
}

function showToast(message, opts = {}) {
    const { type = 'success', duration = 3200, sticky = false, actions = [] } = opts;
    const stack = _getToastStack();

    const el = document.createElement('div');
    el.className = `fd-toast fd-toast-${type} fd-tray-in`;
    const iconHtml = type === 'progress'
        ? '<span class="fd-toast-spinner"></span>'
        : `<span class="fd-toast-icon">${type === 'error' ? '⚠' : type === 'info' ? 'ℹ' : '✓'}</span>`;
    const actionsHtml = actions.length
        ? `<span class="fd-toast-actions">${actions.map((a, i) =>
            `<button type="button" class="fd-toast-action" data-fd-action-idx="${i}">${a.label}</button>`
          ).join('')}</span>`
        : '';
    el.innerHTML = `${iconHtml}<span class="fd-toast-msg"></span>${actionsHtml}`;
    el.querySelector('.fd-toast-msg').textContent = message;
    stack.appendChild(el);

    let dismissed = false;
    const dismiss = () => {
        if (dismissed || !el.isConnected) return;
        dismissed = true;
        el.classList.remove('fd-tray-in');
        el.classList.add('fd-tray-closing');
        el.addEventListener('animationend', () => el.remove(), { once: true });
    };
    actions.forEach((a, i) => {
        const btn = el.querySelector(`[data-fd-action-idx="${i}"]`);
        if (!btn) return;
        btn.addEventListener('click', e => {
            e.stopPropagation(); // don't also trigger the toast's own click-to-dismiss below
            a.onClick(dismiss);
        });
    });
    el.addEventListener('click', dismiss);
    if (!sticky) setTimeout(dismiss, duration);

    // Returned so long-running operations (e.g. background copy-job polling)
    // can update a single sticky "in progress" toast in place and dismiss it
    // themselves once the real result is known, instead of every caller
    // having to reach back into the DOM.
    return {
        dismiss,
        setMessage(newMsg) {
            const m = el.querySelector('.fd-toast-msg');
            if (m) m.textContent = newMsg;
        },
    };
}

// ── Custom prompt/confirm modals ─────────────────────────────────────────────
// Replacements for the browser-native prompt()/confirm() dialogs — those
// can't be styled, don't match the rest of the app, and (on some
// browsers/embedded webviews) can be suppressed or look completely different
// from platform to platform. Both are dynamically-created one-off overlays,
// closed via the existing window.fdCloseOverlay() fade/scale-out, and wired
// to the same Enter-confirms/Escape-cancels handler already used by
// showMessage() (_attachModalKeys), so keyboard behaviour stays consistent
// across every modal in the app.

// Returns a Promise<string|null> — the trimmed input value, or null if the
// user cancelled (Escape, backdrop click, or the Cancel button).
function showPromptModal({ title, label = '', placeholder = '', defaultValue = '',
                            confirmLabel = t('ok'), cancelLabel = t('cancel') } = {}) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-content" style="max-width:380px">
                <h3 style="font-size:1.15rem;font-weight:700;margin-bottom:.75rem;color:#1e293b"></h3>
                ${label ? `<label style="display:block;font-size:13px;color:#64748b;margin-bottom:6px"></label>` : ''}
                <input type="text" id="fd-prompt-input"
                       style="width:100%;padding:9px 12px;border:1px solid #cbd5e1;border-radius:8px;
                              font-size:14px;margin-bottom:1.1rem;box-sizing:border-box"
                       autocomplete="off" spellcheck="false">
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button id="fd-prompt-cancel" class="btn" style="background:#6b7280"></button>
                    <button id="fd-prompt-ok" class="btn"></button>
                </div>
            </div>
        `;
        overlay.querySelector('h3').textContent = title || '';
        if (label) overlay.querySelector('label').textContent = label;
        const input = overlay.querySelector('#fd-prompt-input');
        input.value = defaultValue;
        input.placeholder = placeholder;
        overlay.querySelector('#fd-prompt-cancel').textContent = cancelLabel;
        overlay.querySelector('#fd-prompt-ok').textContent = confirmLabel;
        document.body.appendChild(overlay);

        let settled = false;
        function finish(value) {
            if (settled) return;
            settled = true;
            _detachModalKeys();
            window.fdCloseOverlay(overlay);
            resolve(value);
        }
        overlay.querySelector('#fd-prompt-ok').addEventListener('click', () => finish(input.value.trim() || null));
        overlay.querySelector('#fd-prompt-cancel').addEventListener('click', () => finish(null));
        overlay.addEventListener('click', e => { if (e.target === overlay) finish(null); });
        _attachModalKeys(
            () => finish(input.value.trim() || null),
            () => finish(null)
        );
        input.focus();
        input.select();
    });
}

// Returns a Promise<boolean> — true if confirmed, false if cancelled/dismissed.
function showConfirmModal({ title, message = '', confirmLabel = t('yes'), cancelLabel = t('no'), danger = true } = {}) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-content text-center" style="max-width:380px">
                <h3 style="font-size:1.15rem;font-weight:700;margin-bottom:.6rem;color:#1e293b"></h3>
                <p style="color:#64748b;font-size:13.5px;line-height:1.55;margin-bottom:1.25rem;white-space:pre-line"></p>
                <div style="display:flex;gap:8px;justify-content:center">
                    <button id="fd-confirm-no" class="btn" style="background:#6b7280"></button>
                    <button id="fd-confirm-yes" class="btn"></button>
                </div>
            </div>
        `;
        overlay.querySelector('h3').textContent = title || '';
        overlay.querySelector('p').textContent = message;
        const noBtn  = overlay.querySelector('#fd-confirm-no');
        const yesBtn = overlay.querySelector('#fd-confirm-yes');
        noBtn.textContent  = cancelLabel;
        yesBtn.textContent = confirmLabel;
        if (danger) yesBtn.style.background = '#ef4444';
        document.body.appendChild(overlay);

        let settled = false;
        function finish(value) {
            if (settled) return;
            settled = true;
            _detachModalKeys();
            window.fdCloseOverlay(overlay);
            resolve(value);
        }
        yesBtn.addEventListener('click', () => finish(true));
        noBtn.addEventListener('click', () => finish(false));
        overlay.addEventListener('click', e => { if (e.target === overlay) finish(false); });
        _attachModalKeys(() => finish(true), () => finish(false));
        yesBtn.focus();
    });
}

// Starts tracking a background copy job (see server-side copy_jobs): shows a
// sticky "Copying…" progress toast with Cancel/Hide actions and polls for
// the result.
//   - Cancel: requests server-side cancellation (see /api/v1/copy/cancel) —
//     the background thread checks for this between chunks, not just
//     between whole files, so it takes effect within seconds even mid-file.
//   - Hide: stops polling and dismisses immediately. The user explicitly
//     said they don't want further updates, so no further toast is shown
//     even once the job eventually finishes.
// A single failed poll (network hiccup) doesn't give up on its own — only an
// actual terminal status from the server, Hide, or a very long stretch of no
// resolution, stops the polling.
function _startCopyJobTracking(jobId, fname) {
    const POLL_MS = 1500;
    const MAX_ATTEMPTS = Math.ceil(60 * 60 * 1000 / POLL_MS); // ~1h safety ceiling
    let attempts = 0;
    let stopped = false;
    let cancelRequested = false;

    const progress = showToast(`Copying "${fname}"…`, {
        type: 'progress',
        sticky: true,
        actions: [
            {
                label: 'Cancel',
                onClick: async () => {
                    if (cancelRequested) return;
                    cancelRequested = true;
                    progress.setMessage(`Cancelling "${fname}"…`);
                    try {
                        await apiCall(`/api/v1/copy/cancel/${jobId}`, 'POST');
                    } catch (err) {
                        // If the cancel request itself fails (e.g. the job
                        // already finished a moment earlier), just let the
                        // next poll reveal the real outcome instead of
                        // surfacing this as a separate error.
                        logging_warn('copy cancel request failed', err);
                    }
                },
            },
            {
                label: 'Hide',
                onClick: (dismiss) => {
                    stopped = true;
                    dismiss();
                },
            },
        ],
    });

    const tick = async () => {
        if (stopped) return;
        attempts++;
        try {
            const job = await apiCall(`/api/v1/copy/status/${jobId}`, 'GET');
            if (job.status === 'done') {
                progress.dismiss();
                showToast(`Copied "${fname}"`);
                loadDirectory(currentPath);
                return;
            }
            if (job.status === 'cancelled') {
                progress.dismiss();
                showToast(`Copy of "${fname}" cancelled`, { type: 'info' });
                return;
            }
            if (job.status === 'error') {
                progress.dismiss();
                showToast(`Copy of "${fname}" failed: ${job.error_msg || 'unknown error'}`,
                          { type: 'error', duration: 6000 });
                return;
            }
            // 'pending' or 'running' — keep polling.
        } catch (err) {
            logging_warn('copy job poll failed, retrying', err);
        }
        if (stopped) return;
        if (attempts < MAX_ATTEMPTS) {
            setTimeout(tick, POLL_MS);
        } else {
            progress.dismiss();
            showToast(`Copy of "${fname}" is taking unusually long — check manually`,
                      { type: 'info', duration: 6000 });
        }
    };
    setTimeout(tick, POLL_MS);
}

async function apiCall(endpoint, method = 'GET', body = null, requiresAuth = true) {
    const headers = new Headers({ 'Content-Type': 'application/json' });
    if (requiresAuth) {
        if (!authToken) throw new Error("Authentication token not found.");
        headers.set('Authorization', `Bearer ${authToken}`);
    }
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);
    try {
        const response = await fetchWithFallback(`${API_BASE_URL}${endpoint}`, options);
        const responseData = await response.json();
        if (!response.ok) {
            // Token expired or invalidated — force re-login
            if (response.status === 401 && requiresAuth) {
                authToken = null;
                currentUsername = null;
                localStorage.removeItem('fluxdrop_token');
                localStorage.removeItem('fluxdrop_username');
                renderApp('login');
                // Show a gentle notice instead of a raw error
                showMessage('Session expired', 'Your session has expired. Please log in again.');
                throw new Error('SESSION_EXPIRED');
            }
            throw new Error(responseData.error || `HTTP error! status: ${response.status}`);
        }
        return responseData;
    } catch (error) {
        if (error.message !== 'SESSION_EXPIRED') console.error('API Call Error:', error);
        throw error;
    }
}
// Read dismiss delay from settings (0 = never auto-dismiss)
function getTrayDismissDelay() {
    const v = parseInt(localStorage.getItem('fluxdrop_tray_dismiss_ms') || '0', 10);
    return isNaN(v) ? 0 : v;
}

// P10: Upload-finished notification ──────────────────────────────────────
function _requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

function _notifyUploadDone(okCount, failCount = 0) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    if (document.hasFocus()) return; // user is watching — no need for OS notification
    const n = x => `${x} file${x !== 1 ? 's' : ''}`;
    let title, body;
    if (failCount > 0 && okCount === 0) {
        title = 'FluxDrop — Upload failed';
        body  = `${n(failCount)} could not be uploaded.`;
    } else if (failCount > 0) {
        title = 'FluxDrop — Upload finished with errors';
        body  = `${n(okCount)} uploaded, ${failCount} failed.`;
    } else {
        title = 'FluxDrop — Upload complete';
        body  = `${n(okCount)} uploaded successfully.`;
    }
    new Notification(title, {
        body,
        icon: '/icon.svg',
        tag: 'fluxdrop-upload-done',  // replaces previous notification if still showing
    });
}

        // ======================================================================
        // --- UI RENDERING & ROUTING ---
        // ======================================================================
function renderAuthControls() {
    if (authToken) {
        authControls.innerHTML = `
            <div class="flex items-center gap-2" style="min-width:0">
                <span class="font-medium text-blue-900 fd-welcome-text"
                      style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
                             max-width:min(220px,40vw);font-size:14px"
                      title="${escapeHtmlAttr(currentUsername)}">
                    ${t('welcome_text')} ${escapeHtml(currentUsername)}!
                </span>
                <button id="profile-btn" title="Profile & Settings"
                    style="width:36px;height:36px;border-radius:50%;background:#3b82f6;border:2px solid #93c5fd;
                            color:white;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;
                            flex-shrink:0;transition:background .2s;overflow:hidden;padding:0"
                    onmouseenter="this.style.background='#2563eb'" onmouseleave="this.style.background='#3b82f6'">
                    <img id="header-avatar"
                         src="${_avatarUrl()}"
                         style="width:36px;height:36px;border-radius:50%;object-fit:cover;display:block"
                         onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"
                         alt="">
                    <span id="header-avatar-fallback"
                          style="display:none;width:100%;height:100%;align-items:center;justify-content:center;font-size:16px">👤</span>
                </button>
            </div>
        `;
        document.getElementById('profile-btn').addEventListener('click', openProfileMenu);
    } else {
        authControls.innerHTML = `
            <div class="flex items-center gap-4">
                <button id="show-login-btn" class="btn text-sm">${t('login')}</button>
                <button id="show-register-btn" class="btn bg-green-500 hover:bg-green-600 text-sm">${t('register')}</button>
            </div>
        `;
        document.getElementById('show-login-btn').addEventListener('click', () => renderApp('login'));
        document.getElementById('show-register-btn').addEventListener('click', () => renderApp('register'));
    }
}

let _renderAppBusy = false;
async function renderApp(route = null) {
    // Guard against re-entrant calls (e.g. a 401 inside checkAndShowPolicies
    // calling renderApp('login') while a previous renderApp is still awaiting
    // the policy/status fetch — without this the policy fetch loop runs again
    // immediately, hammering the server with requests on every bad token.
    if (_renderAppBusy) return;
    _renderAppBusy = true;
    try {
        renderAuthControls();
        if (!authToken) {
            if (route === 'register') renderRegisterView();
            else if (route === 'login') renderLoginView();
            else renderLandingView();   // ← default: show landing page
            return;
        }
        // Backfill the cached user id if it's missing. It's normally set by
        // handleLogin() (only when /auth/login's response happens to include
        // an `id` field) or when the user opens their Profile panel (which
        // fetches /api/v1/me). A session that never hit either of those —
        // e.g. a login response without an id field, on a device that's
        // never opened Profile — would have every avatar render permanently
        // fall back to _avatarUrl()'s hardcoded '0', fetching the wrong
        // user's avatar. Checking here means it's fixed on the very next load
        // instead of staying wrong until Profile happens to be opened.
        if (!localStorage.getItem('fluxdrop_user_id')) {
            try {
                const me = await apiCall('/api/v1/me');
                if (me && me.id) localStorage.setItem('fluxdrop_user_id', String(me.id));
            } catch (_) { /* non-fatal — header just falls back as before */ }
        }
        _requestNotificationPermission();
        checkAndShowPolicies(() => renderFileBrowserView());
    } finally {
        _renderAppBusy = false;
    }
}

function renderLandingView() {
    appRoot.dataset.fdLanding = '1';
    appRoot.innerHTML = `
        <div style="display:flex;flex-direction:column;gap:2rem;animation:fd-fade-in-up .35s ease both">

            <!-- Hero -->
            <div class="card" style="text-align:center;padding:3rem 2rem">
                <img src="icon.svg" style="width:72px;height:72px;margin:0 auto 1rem" alt="FluxDrop">
                <h2 style="font-size:2.2rem;font-weight:800;color:#1e40af;margin-bottom:.75rem">
                    ${t('home_slogan')}
                </h2>
                <p style="font-size:1.1rem;color:#475569;max-width:560px;margin:0 auto 2rem;line-height:1.7">
                    ${t('home_slogan_desc1')}
                    ${t('home_slogan_desc2')}
                </p>
                <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap">
                    <button class="btn" style="font-size:1rem;padding:0.85rem 2rem"
                            onclick="renderApp('login')">${t('login')}</button>
                    <button class="btn" style="font-size:1rem;padding:0.85rem 2rem;background:#16a34a"
                            onclick="renderApp('register')">${t('home_create_account')}</button>
                </div>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.25rem">
                ${[
                    ['📁', t('home_card_lable1'), t('home_card_desc1')],
                    ['🔗', t('home_card_lable2'), t('home_card_desc2')],
                    ['👁', t('home_card_lable3'), t('home_card_desc3')],
                    ['⚡', t('home_card_lable4'), t('home_card_desc4')],
                    ['🗑', t('home_card_lable5'), t('home_card_desc5')],
                    ['🔒', t('home_card_lable6'), t('home_card_desc6')],
                    ['👆', t('home_card_lable7_hold'), t('home_card_desc7_hold')],
                ].map(([icon, title, desc]) => `
                    <div class="card" style="padding:1.5rem">
                        <div style="font-size:2rem;margin-bottom:.5rem">${icon}</div>
                        <h3 style="font-weight:700;color:#1e40af;margin-bottom:.4rem">${title}</h3>
                        <p style="color:#64748b;font-size:.92rem;line-height:1.6">${desc}</p>
                    </div>
                `).join('')}
            </div>

            <!-- How it works -->
            <div class="card" style="padding:2rem">
                <h3 style="font-size:1.4rem;font-weight:700;color:#1e40af;margin-bottom:1.25rem;text-align:center">
                    ${t('home_card_lable_desc')}
                </h3>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;text-align:center">
                    ${[
                        ['1', t('home_card_lable7'), t('home_card_desc7')],
                        ['2', t('home_card_lable8'), t('home_card_desc8')],
                        ['3', t('home_card_lable9'), t('home_card_desc9')],
                        ['4', t('home_card_lable10'), t('home_card_desc10')],
                    ].map(([n, title, desc]) => `
                        <div>
                            <div style="width:40px;height:40px;border-radius:50%;background:#dbeafe;color:#1d4ed8;
                                        font-weight:800;font-size:1.1rem;display:flex;align-items:center;
                                        justify-content:center;margin:0 auto .6rem">${n}</div>
                            <div style="font-weight:600;color:#1e293b;margin-bottom:.25rem">${title}</div>
                            <div style="font-size:.88rem;color:#64748b">${desc}</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Footer links -->
            <div style="text-align:center;padding-bottom:1rem;font-size:.85rem;color:#94a3b8">
                <button onclick="showPolicyModal('tos')"
                    style="background:none;border:none;color:#94a3b8;cursor:pointer;text-decoration:underline;font-size:.85rem">
                    ${t('footer_tos')}</button>
                &nbsp;·&nbsp;
                <button onclick="showPolicyModal('pp')"
                    style="background:none;border:none;color:#94a3b8;cursor:pointer;text-decoration:underline;font-size:.85rem">
                    ${t('footer_pp')}</button>
            </div>
        </div>
    `;
}

// ── Policy / TOS / PP modal ───────────────────────────────────────────────
const POLICY_LABELS = { tos: 'Terms of Service', pp: 'Privacy Policy' };

// Active language code — persisted in localStorage.
// Falls back to 'eng' if the stored value isn't available for a document.
let _policyLang = localStorage.getItem('fluxdrop_policy_lang') || 'eng';

// Fetch versions.json and return the full parsed object (cached for the
// lifetime of this page load — the file is tiny and changes only on deploy).
let _versionsCache = null;
async function _fetchVersions() {
    if (_versionsCache) return _versionsCache;
    try {
        const r = await fetch('./policies/versions.json', { cache: 'no-cache' });
        if (r.ok) _versionsCache = await r.json();
    } catch { /* use fallback */ }
    return _versionsCache || {};
}

// Build the relative URL for a policy Markdown file.
// versions.json shape: { "languages": {"eng":"English","ukr":"Ukrainian"},
//                        "tos": {"eng":"1.2e","ukr":"0.0.0"},
//                        "pp":  {"eng":"1.0", "ukr":"0.0.0"} }
function _policyUrl(type, lang, version) {
    const folder = type === 'tos' ? 'TOS' : 'PP';
    return `./policies/${folder}/${lang}/v${version}.md`;
}

// Build the language selector <select> HTML for the modal header.
// availableLangs: array of lang codes that actually have a file for this
// type+version. languages: the full {code: name} map from versions.json.
function _langSelectorHtml(availableLangs, languages, currentLang, selectId) {
    if (availableLangs.length <= 1) return ''; // no point showing a 1-item selector
    const opts = availableLangs.map(code => {
        const name = (languages && languages[code]) || code;
        const sel  = code === currentLang ? ' selected' : '';
        return `<option value="${code}"${sel}>${name}</option>`;
    }).join('');
    return `<select id="${selectId}"
        style="font-size:.8rem;padding:3px 6px;border-radius:6px;border:1px solid #cbd5e1;
               color:#475569;background:#f8fafc;cursor:pointer;margin-left:.5rem">
        ${opts}
    </select>`;
}

// Show a read-only view of one policy document (no agreement required).
async function showPolicyModal(type) {
    const label    = POLICY_LABELS[type] || type.toUpperCase();
    const versions = await _fetchVersions();
    const languages = versions.languages || {};

    // Determine which languages are available for this doc type
    const versionMap = versions[type] || {};   // { eng: '1.2e', ukr: '0.0.0' }
    const availableLangs = Object.keys(versionMap).length ? Object.keys(versionMap) : ['eng'];

    // Pick best language: user preference → first available
    let lang = availableLangs.includes(_policyLang) ? _policyLang : availableLangs[0];
    let version = versionMap[lang] || '0.0.0';
    const url = _policyUrl(type, lang, version);

    const overlay = document.createElement('div');
    overlay.style.cssText = [
        'position:fixed;top:0;left:0;width:100%;height:100%;z-index:10000',
        'background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:1rem',
    ].join(';');

    overlay.innerHTML = `
        <div style="background:#fff;border-radius:1rem;width:100%;max-width:720px;
                    max-height:88vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 24px 48px rgba(0,0,0,.3)">
            <div style="padding:1.25rem 1.5rem;border-bottom:1px solid #e2e8f0;
                        display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem">
                <div style="display:flex;align-items:center;flex-wrap:wrap;gap:.4rem">
                    <h2 style="font-size:1.15rem;font-weight:700;color:#1e40af;margin:0">
                        ${label}
                    </h2>
                    <span id="pm-version" style="font-size:.8rem;color:#94a3b8;font-weight:400">v${version}</span>
                    ${_langSelectorHtml(availableLangs, languages, lang, 'pm-lang')}
                </div>
                <button id="pm-close" style="background:none;border:none;font-size:1.4rem;
                        cursor:pointer;color:#64748b;line-height:1">✕</button>
            </div>
            <div id="pm-body" class="fd-md-body" data-fd-notranslate style="padding:1.5rem;overflow-y:auto;flex:1;
                                     font-size:.93rem;line-height:1.7;color:#1e293b">
                <div style="text-align:center;padding:2rem;color:#94a3b8">Loading…</div>
            </div>
        </div>`;

    document.body.appendChild(overlay);
    overlay.querySelector('#pm-close').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

    async function loadDoc(loadLang) {
        const loadVer = versionMap[loadLang] || '0.0.0';
        overlay.querySelector('#pm-version').textContent = `v${loadVer}`;
        const bodyEl = overlay.querySelector('#pm-body');
        bodyEl.innerHTML = '<div style="text-align:center;padding:2rem;color:#94a3b8">Loading…</div>';
        try {
            const resp = await fetch(_policyUrl(type, loadLang, loadVer), { cache: 'no-cache' });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();
            try {
                // Same engine used for file-preview Markdown (GFM tables,
                // links, code fences, blockquotes) — the old hand-rolled
                // _mdToHtml() below only understood headings/bold/italic/
                // lists, so any policy doc using a link or table rendered
                // as literal, unformatted Markdown text.
                await _loadMarked();
                bodyEl.innerHTML = _mdParseAndSanitize(text);
            } catch (mdErr) {
                // marked.js failed to load (CDN blocked/offline) — we already
                // have the document text, so fall back to the tiny renderer
                // rather than showing a hard error for a doc we did fetch.
                bodyEl.innerHTML = _mdToHtml(text);
            }
        } catch (err) {
            bodyEl.innerHTML =
                `<p style="color:#dc2626">Could not load the document. Please try again later.<br>
                 <small style="color:#94a3b8">${err.message}</small></p>`;
        }
    }

    const langSel = overlay.querySelector('#pm-lang');
    if (langSel) {
        langSel.addEventListener('change', () => {
            _policyLang = langSel.value;
            localStorage.setItem('fluxdrop_policy_lang', _policyLang);
            loadDoc(_policyLang);
        });
    }
    loadDoc(lang);
}

// Tiny built-in Markdown renderer — headings, bold, italic, lists, paragraphs
// only (no links, tables, code fences, or blockquotes). This used to be the
// only renderer for policy docs, which is why a ToS/PP file using a link or
// table would show up as literal, unformatted Markdown text. Both policy
// modals now render via the full marked.js-based _mdParseAndSanitize()
// instead; this function is kept only as a fallback for when marked.js
// itself fails to load (CDN blocked/offline) — degraded formatting is still
// better than a hard "could not load" error for a document we already fetched.
function _mdToHtml(md) {
    return md
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        // headings
        .replace(/^### (.+)$/gm, '<h3 style="font-size:1rem;font-weight:700;color:#1e40af;margin:1.2em 0 .3em">$1</h3>')
        .replace(/^## (.+)$/gm,  '<h2 style="font-size:1.15rem;font-weight:700;color:#1e40af;margin:1.4em 0 .4em">$1</h2>')
        .replace(/^# (.+)$/gm,   '<h1 style="font-size:1.35rem;font-weight:800;color:#1e40af;margin:1.5em 0 .5em">$1</h1>')
        // bold+italic (*** or ___) — must come BEFORE bold and italic
        // [\s\S]+? allows the span to cross line breaks (e.g. ***First\nSecond***)
        .replace(/\*\*\*([\s\S]+?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/___([\s\S]+?)___/g,        '<strong><em>$1</em></strong>')
        // bold (** or __)
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/__(.+?)__/g,      '<strong>$1</strong>')
        // italic (* or _)
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/_(.+?)_/g,    '<em>$1</em>')
        // unordered list items (- or *)
        .replace(/^[-*] (.+)$/gm, '<li style="margin-left:1.5em;margin-bottom:.3em;list-style-type:disc">$1</li>')
        // ordered list items
        .replace(/^\d+\. (.+)$/gm, '<li style="margin-left:1.5em;margin-bottom:.3em;list-style-type:decimal">$1</li>')
        // wrap consecutive <li> runs in <ul>/<ol> so bullets actually render
        .replace(/((?:<li[^>]*>.*?<\/li>\n?)+)/g, '<ul style="margin:.4em 0;padding-left:.5em">$1</ul>')
        // blank lines → paragraph breaks
        .replace(/\n{2,}/g, '</p><p style="margin:.6em 0">')
        .replace(/\n/g, '<br>');
}

// Called after login / on page load for authenticated users.
// Checks with the server which policies still need acceptance, then
// shows them one at a time.  Calls onAllAccepted() when done (or if nothing needed).
async function checkAndShowPolicies(onAllAccepted) {
    let status;
    try {
        const resp = await apiCall('/api/v1/policy/status', 'GET', null, true);
        status = resp;
    } catch (err) {
        // SESSION_EXPIRED: apiCall already handled the redirect + message, don't proceed.
        if (err.message === 'SESSION_EXPIRED') return;
        // If the endpoint doesn't exist yet (server not updated), skip gracefully
        onAllAccepted();
        return;
    }

    const queue = [];
    // token_valid: false means the bearer token was missing or rejected by the
    // server.  In this case needs_tos/needs_pp are meaningless (the server
    // compared against null accepted versions), so we must not show the policy
    // modal — instead treat it identically to a SESSION_EXPIRED error.
    if (status.token_valid === false) {
        // Clear the stale/invalid token BEFORE calling renderApp — otherwise
        // renderApp sees a truthy authToken, calls checkAndShowPolicies again,
        // gets token_valid:false again, and loops indefinitely (DoS on server).
        authToken = null;
        currentUsername = null;
        localStorage.removeItem('fluxdrop_token');
        localStorage.removeItem('fluxdrop_username');
        renderApp('login');
        showMessage('Session expired', 'Your session has expired. Please log in again.');
        return;
    }
    if (status.needs_tos) queue.push({ type: 'tos', version: status.current_tos });
    if (status.needs_pp)  queue.push({ type: 'pp',  version: status.current_pp  });

    if (queue.length === 0) { onAllAccepted(); return; }

    // We're about to block on a full-screen policy modal instead of rendering
    // the app. Every other path clears #app-root (and with it the boot spinner)
    // via appRoot.innerHTML — this one doesn't until the user accepts, so the
    // fd-boot-spin animation would otherwise run forever behind the modal.
    document.getElementById('fd-boot-loading')?.remove();

    async function showNext() {
        if (queue.length === 0) { onAllAccepted(); return; }
        const { type, version } = queue.shift();
        await _showPolicyAgreementModal(type, version, showNext);
    }
    showNext();
}

// Like showPolicyModal but forces the user to scroll to the bottom and click "I agree".
// version here is the server-required version string (from policy/status).
async function _showPolicyAgreementModal(type, version, onAccepted) {
    const label    = POLICY_LABELS[type] || type.toUpperCase();
    const versions = await _fetchVersions();
    const languages = versions.languages || {};
    const versionMap = versions[type] || {};
    const availableLangs = Object.keys(versionMap).length ? Object.keys(versionMap) : ['eng'];
    let lang = availableLangs.includes(_policyLang) ? _policyLang : availableLangs[0];

    // Helper: enable/disable the agree button
    function _enableAgree() {
        agreeBtn.disabled = false;
        agreeBtn.style.opacity = '1';
        agreeBtn.style.cursor = 'pointer';
    }

    const overlay = document.createElement('div');
    overlay.style.cssText = [
        'position:fixed;top:0;left:0;width:100%;height:100%;z-index:10001',
        'background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:1rem',
    ].join(';');

    overlay.innerHTML = `
        <div style="background:#fff;border-radius:1rem;width:100%;max-width:720px;
                    max-height:92vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 24px 48px rgba(0,0,0,.4)">
            <div style="padding:1.25rem 1.5rem;background:#eff6ff;border-bottom:1px solid #bfdbfe;
                        display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem">
                <div>
                    <h2 style="font-size:1.1rem;font-weight:700;color:#1e40af;margin:0 0 .25rem;display:flex;align-items:center;gap:.5rem">
                        ${t('policy_review_title', { label })}
                        ${_langSelectorHtml(availableLangs, languages, lang, 'pam-lang')}
                    </h2>
                    <p style="font-size:.85rem;color:#3730a3;margin:0">
                        ${t('policy_version_note', { version })}
                    </p>
                </div>
            </div>
            <div id="pam-body" class="fd-md-body" data-fd-notranslate style="padding:1.5rem;overflow-y:auto;flex:1;
                                      font-size:.92rem;line-height:1.7;color:#1e293b">
                <div id="pam-skeleton" style="padding:.5rem 0">
                    ${Array.from({length: 18}, (_, i) => {
                        const w = [92,78,85,65,88,70,95,60,82,74,90,55,87,72,80,68,93,63][i] + '%';
                        return `<div style="height:13px;border-radius:4px;margin-bottom:10px;width:${w};background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`;
                    }).join('')}
                </div>
            </div>
            <div style="padding:1rem 1.5rem;border-top:1px solid #e2e8f0;
                        display:flex;align-items:center;justify-content:space-between;gap:1rem;background:#f8fafc">
                <span id="pam-scroll-hint" style="font-size:.82rem;color:#94a3b8">
                    ${t('policy_scroll_hint')}
                </span>
                <div style="display:flex;gap:8px">
                    <button id="pam-decline-btn" class="btn" style="background:#e2e8f0;color:#1e293b">
                        ${t('policy_decline_btn')}
                    </button>
                    <button id="pam-agree-btn" class="btn" disabled style="opacity:.45;cursor:not-allowed;white-space:nowrap">
                        ${t('policy_agree_btn', { label })}
                    </button>
                </div>
            </div>
        </div>`;

    document.body.appendChild(overlay);

    const bodyEl   = overlay.querySelector('#pam-body');
    const agreeBtn = overlay.querySelector('#pam-agree-btn');
    const hint     = overlay.querySelector('#pam-scroll-hint');

    // Enable the agree button once scrolled near the bottom.
    // Switching language resets the scroll requirement.
    bodyEl.addEventListener('scroll', () => {
        if (bodyEl.scrollHeight - bodyEl.scrollTop - bodyEl.clientHeight < 40) {
            _enableAgree();
            hint.textContent = t('policy_scroll_done');
        }
    });

    agreeBtn.addEventListener('click', async () => {
        agreeBtn.disabled = true;
        agreeBtn.textContent = t('policy_saving');
        const _paDismiss = showSpinnerOverlay('Saving your agreement…', { minMs: 1000 });
        try {
            await withMinDelay(apiCall('/api/v1/policy/accept', 'POST', { [type]: version }), 1000);
            _paDismiss();
            overlay.remove();
            onAccepted();
        } catch (err) {
            _paDismiss();
            if (err.message === 'SESSION_EXPIRED') {
                overlay.remove();
                return;
            }
            agreeBtn.disabled = false;
            agreeBtn.textContent = t('policy_agree_btn', { label });
            showMessage('Error', 'Could not save your agreement: ' + err.message);
        }
    });

    const declineBtn = overlay.querySelector('#pam-decline-btn');
    declineBtn.addEventListener('click', () => {
        overlay.remove();
        showMessage('Policy not accepted',
            t('policy_logout_msg'));
        handleLogout();
    });

    // Language switch: reload document, reset scroll requirement
    const langSel = overlay.querySelector('#pam-lang');
    if (langSel) {
        langSel.addEventListener('change', () => {
            lang = langSel.value;
            _policyLang = lang;
            localStorage.setItem('fluxdrop_policy_lang', lang);
            // Require re-scroll for the newly loaded language
            agreeBtn.disabled = true;
            agreeBtn.style.opacity = '.45';
            agreeBtn.style.cursor = 'not-allowed';
            hint.textContent = t('policy_scroll_hint');
            loadDoc(lang);
        });
    }

    async function loadDoc(loadLang) {
        // Use the version for the selected language; fall back to the server-required version
        const loadVer = versionMap[loadLang] || version;
        bodyEl.innerHTML = `<div id="pam-skeleton" style="padding:.5rem 0">
            ${Array.from({length: 18}, (_, i) => {
                const w = [92,78,85,65,88,70,95,60,82,74,90,55,87,72,80,68,93,63][i] + '%';
                return `<div style="height:13px;border-radius:4px;margin-bottom:10px;width:${w};background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`;
            }).join('')}
        </div>`;
        bodyEl.scrollTop = 0;
        try {
            // On a slow/stalled connection this fetch previously had no timeout
            // at all — the shimmer skeleton could sit there indefinitely with
            // no fallback ever appearing. Bound it so the user always lands on
            // an actionable state (retry or agree-anyway) within a few seconds.
            const resp = await fetch(_policyUrl(type, loadLang, loadVer), {
                cache: 'no-cache',
                signal: AbortSignal.timeout(15000),
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();
            try {
                await _loadMarked();
                bodyEl.innerHTML = _mdParseAndSanitize(text);
            } catch (mdErr) {
                bodyEl.innerHTML = _mdToHtml(text);
            }
            // Short doc that doesn't need scrolling — enable immediately
            if (bodyEl.scrollHeight <= bodyEl.clientHeight + 40) {
                _enableAgree();
                hint.textContent = '';
            }
        } catch (err) {
            const isTimeout = err.name === 'TimeoutError' || err.name === 'AbortError';
            const reason = isTimeout
                ? 'The document is taking too long to load — your connection may be slow or unstable.'
                : `Could not load the document: ${err.message}`;
            bodyEl.innerHTML = `
                <p style="color:#dc2626">${escapeHtml(reason)}</p>
                <p>
                    <button id="pam-retry-btn" class="btn" style="background:#3b82f6;margin-right:8px">Retry</button>
                    You can also agree by clicking the button below, or try reloading the page.
                </p>`;
            const retryBtn = bodyEl.querySelector('#pam-retry-btn');
            if (retryBtn) retryBtn.addEventListener('click', () => loadDoc(loadLang));
            _enableAgree();
            hint.textContent = '';
        }
    }

    loadDoc(lang);
}

function renderLoginView() {
    // Keep the landing page visible — show login as an overlay modal
    if (!appRoot.dataset.fdLanding) renderLandingView();
    _showAuthModal('login');
}

function renderRegisterView() {
    if (!appRoot.dataset.fdLanding) renderLandingView();
    _showAuthModal('register');
}

// ── Auth modal: Login / Register overlay on landing page ─────────────────────
// Keeps the landing page visible in the background.
// Includes a visual-only Google OAuth button (backend not yet implemented).
function _showAuthModal(initialMode) {
    document.getElementById('fd-auth-modal')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'fd-auth-modal';
    overlay.style.cssText =
        'position:fixed;inset:0;background:rgba(15,23,42,.48);display:flex;' +
        'align-items:center;justify-content:center;z-index:9500;padding:1rem;' +
        'backdrop-filter:blur(4px);animation:fd-fade-in .18s ease';

    overlay.innerHTML = `
        <div id="fd-auth-card"
             style="background:var(--fd-surface,#fff);border-radius:1.25rem;width:100%;
                    max-width:400px;box-shadow:0 24px 64px rgba(0,0,0,.3);overflow:hidden;
                    animation:fd-modal-in .22s cubic-bezier(.22,1,.36,1)">

            <!-- Tabs -->
            <div style="display:flex;border-bottom:2px solid var(--fd-border,#e2e8f0)">
                <button id="fd-tab-login" data-tab="login"
                    style="flex:1;padding:.85rem 1rem;background:none;border:none;
                           font-weight:700;font-size:.93rem;cursor:pointer;font-family:inherit;
                           color:#3b82f6;border-bottom:2px solid #3b82f6;margin-bottom:-2px;
                           transition:color .15s,border-color .15s">
                    ${t('login')}
                </button>
                <button id="fd-tab-register" data-tab="register"
                    style="flex:1;padding:.85rem 1rem;background:none;border:none;
                           font-weight:600;font-size:.93rem;cursor:pointer;font-family:inherit;
                           color:#94a3b8;border-bottom:2px solid transparent;margin-bottom:-2px;
                           transition:color .15s,border-color .15s">
                    ${t('register')}
                </button>
            </div>

            <div style="padding:1.5rem">
                <!-- Google OAuth (visual-only placeholder) -->
                <button id="fd-google-btn" disabled title="${t('google_coming_soon')}"
                    style="width:100%;display:flex;align-items:center;justify-content:center;
                           gap:.65rem;padding:.72rem 1rem;border:1.5px solid var(--fd-border,#e2e8f0);
                           border-radius:.75rem;background:var(--fd-surface,#fff);font-size:.9rem;
                           font-weight:600;color:var(--fd-text,#374151);cursor:not-allowed;
                           opacity:.6;margin-bottom:1rem;font-family:inherit">
                    <svg width="18" height="18" viewBox="0 0 18 18" style="flex-shrink:0" aria-hidden="true">
                        <path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.716v2.259h2.908C16.658 14.016 17.64 11.707 17.64 9.2z"/>
                        <path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/>
                        <path fill="#FBBC05" d="M3.964 10.706A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.706V4.962H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.038l3.007-2.332z"/>
                        <path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.962L3.964 6.294C4.672 4.167 6.656 3.58 9 3.58z"/>
                    </svg>
                    ${t('continue_with_google')}
                    <span style="font-size:.75rem;color:#94a3b8;font-weight:400">(${t('google_coming_soon')})</span>
                </button>

                <!-- Divider -->
                <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:1rem">
                    <div style="flex:1;height:1px;background:var(--fd-border,#e2e8f0)"></div>
                    <span style="font-size:.8rem;color:#94a3b8">${t('auth_or')}</span>
                    <div style="flex:1;height:1px;background:var(--fd-border,#e2e8f0)"></div>
                </div>

                <!-- Login form -->
                <form id="fd-login-form"
                      style="display:${initialMode==='login'?'flex':'none'};flex-direction:column;gap:.75rem">
                    <input type="text" id="username" class="w-full p-3 border rounded-lg"
                           placeholder="${t('username')}" required autocomplete="username">
                    <input type="password" id="password" class="w-full p-3 border rounded-lg"
                           placeholder="${t('password')}" required autocomplete="current-password">
                    <button type="submit" class="btn w-full">${t('login')}</button>
                </form>

                <!-- Register form -->
                <form id="fd-register-form"
                      style="display:${initialMode==='register'?'flex':'none'};flex-direction:column;gap:.75rem">
                    <input type="text" id="reg-username" class="w-full p-3 border rounded-lg"
                           placeholder="${t('placeholder_username')}" required autocomplete="username">
                    <input type="text" id="reg-nickname" class="w-full p-3 border rounded-lg"
                           placeholder="${t('placeholder_nickname')}" required autocomplete="nickname">
                    <input type="email" id="reg-email" class="w-full p-3 border rounded-lg"
                           placeholder="${t('placeholder_email')}" required autocomplete="email">
                    <input type="password" id="reg-password" class="w-full p-3 border rounded-lg"
                           placeholder="${t('password')}" required autocomplete="new-password">
                    <button type="submit" class="btn w-full">${t('register')}</button>
                </form>
            </div>
        </div>`;

    document.body.appendChild(overlay);

    // Tab switching
    overlay.querySelectorAll('#fd-tab-login, #fd-tab-register').forEach(tab => {
        tab.addEventListener('click', () => {
            const mode = tab.id === 'fd-tab-login' ? 'login' : 'register';
            ['login','register'].forEach(m => {
                const btn  = overlay.querySelector('#fd-tab-' + m);
                const form = overlay.querySelector('#fd-' + m + '-form');
                const active = m === mode;
                btn.style.color           = active ? '#3b82f6' : '#94a3b8';
                btn.style.fontWeight      = active ? '700' : '600';
                btn.style.borderBottomColor = active ? '#3b82f6' : 'transparent';
                form.style.display        = active ? 'flex' : 'none';
            });
        });
    });

    // Close on backdrop click
    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });

    // Form submissions
    overlay.querySelector('#fd-login-form').addEventListener('submit', handleLogin);
    overlay.querySelector('#fd-register-form').addEventListener('submit', handleRegister);
}

function renderFileBrowserView() {
    // Simple file browser UI: listing, upload, create folder, rename, delete, preview
    appRoot.innerHTML = `
        <div class="card" style="min-height:520px">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:1rem;flex-wrap:wrap">
                <h2 class="text-2xl font-semibold text-blue-800" style="flex-shrink:0">${t('file_browser_title')}</h2>
                <div style="display:flex;gap:6px;align-items:center;min-width:0;flex-wrap:wrap;justify-content:flex-end">
                    <!-- Mobile-only collapse toggle -->
                    <button id="btn-toolbar-toggle" class="fd-toolbar-toggle btn text-sm"
                        style="display:none;padding:.4rem .6rem;font-size:15px" title="Toolbar">⋯</button>
                    <!-- Toolbar buttons — collapsible on mobile -->
                    <div id="fd-toolbar-btns" style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">
                        <button id="btn-up" class="btn bg-gray-300 text-black text-sm" style="padding:.45rem .9rem">${t('up')}</button>
                        <button id="btn-refresh" class="btn text-sm" style="padding:.45rem .9rem">${t('refresh')}</button>
                        <button id="btn-create-folder" class="btn bg-gray-200 text-black text-sm" style="padding:.45rem .9rem">${t('create_a_folder')}</button>
                        <button id="btn-browse-cdn" class="btn bg-yellow-300 text-black text-sm" style="padding:.45rem .9rem">${t('browse_cdn')}</button>
                        <button id="btn-trash" class="btn text-sm" style="background:#dc2626;color:#fff;padding:.45rem .9rem" title="${t('trash_title')}">${t('trash_bin_button')}</button>
                        <button id="btn-folders-mixed" class="btn text-sm" style="padding:.45rem .9rem" title="${t('folder_sort_first')}"></button>
                    </div>
                </div>
            </div>

            <div id="path-breadcrumb" class="text-sm text-gray-600 mb-4"></div>

            <!-- Selection action bar — always in the DOM so activating it never
                 shifts the file list.  Invisible when nothing is selected.
                 Ghost content (opacity:0 buttons) is injected by _updateSelBar()
                 immediately after this template is set as innerHTML. -->
            <div id="fd-sel-bar"
                 style="border-radius:8px;padding:7px 12px;margin-bottom:8px;
                        display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px;
                        background:var(--fd-accent-bg,#eff6ff);border:1px solid var(--fd-accent-border,#bfdbfe)">
            </div>

            <!-- Outer drag-and-drop zone — covers both the upload toolbar and the
                 file list so the entire content area accepts drops.
                 fd-upload-wrap defaults to hidden; JS reveals it when a fine pointer
                 (mouse/trackpad) is detected, so the form is never shown on touch-only
                 devices even if the CSS is cached or overridden. -->
            <div id="fd-drop-zone"
                 style="border:2px dashed transparent;border-radius:10px;
                        transition:border-color .15s,background .15s">

                <div class="mb-4 fd-upload-wrap" id="fd-upload-wrap" style="display:none">
                    <!-- Hidden real file input — triggered programmatically -->
                    <input type="file" id="upload-file" multiple style="display:none" />
                    <form id="upload-form" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;row-gap:6px">
                        <button type="button" id="btn-file-choose" class="btn text-sm"
                            style="background:#e2e8f0;color:#374151;font-weight:500;flex-shrink:0">
                            📎 <span id="upload-file-label">${t('no_file_selected') !== 'no_file_selected' ? t('no_file_selected') : 'Choose files…'}</span>
                        </button>
                        <button type="button" id="btn-folder-toggle" class="btn text-sm"
                            style="background:#0ea5e9;flex-shrink:0;padding:.45rem .75rem" title="${t('folder_mode')}">${t('folder_button')}</button>
                        <label class="text-sm" style="flex-shrink:0;white-space:nowrap"><input type="checkbox" id="upload-protected" /> ${t('protected')}</label>
                        <button class="btn" id="btn-upload-submit" type="submit" style="flex-shrink:0;padding:.45rem .9rem">${t('upload')}</button>
                        <span id="upload-spinner" style="display:none;font-size:18px;animation:spin 0.8s linear infinite">⏳</span>
                        <button type="button" id="btn-show-queue"
                            class="btn text-sm hidden"
                            style="background:#6366f1;flex-shrink:0"
                            title="${t('upload_queue')}">
                            📋 ${t('upload_queue')} (<span id="queue-count">0</span>)
                        </button>
                        <button type="button" id="btn-resume-interrupted"
                            class="btn text-sm hidden"
                            style="background:#f59e0b;flex-shrink:0"
                            title="${t('interrupted')}">
                            ⟳ ${t('interrupted')} (<span id="interrupted-count">0</span>)
                        </button>
                    </form>
                </div>

                <!-- Drop hint — appears in the file-list gap while dragging over -->
                <div id="fd-drop-hint"
                     style="display:none;padding:14px 0 8px;text-align:center;
                            color:var(--fd-accent,#3b82f6);font-size:13px;
                            font-weight:500;pointer-events:none">
                    ⬆ Drop files or folders here to upload
                </div>

                <div id="file-list" class="mt-4" style="min-height:320px;user-select:none"></div>

            </div>

            <!-- Mobile-only floating upload button. Hidden by default;
                 _initMobileUploadFab() reveals it on touch-only devices —
                 the exact inverse of fd-upload-wrap's own visibility check,
                 since that toolbar hides itself there and nothing replaced it.
                 Bottom-LEFT to match #ul-tray's side (renderUploadTray, same
                 corner makes sense for an upload trigger) and to avoid sitting
                 under #dl-tray on the right; z-index above both trays (9000)
                 so it stays reachable even while a transfer is in progress. -->
            <button id="fd-mobile-upload-fab" type="button" title="${t('upload')}"
                style="display:none;position:fixed;left:18px;bottom:22px;width:52px;height:52px;
                       border-radius:50%;background:#3b82f6;color:#fff;border:none;
                       align-items:center;justify-content:center;font-size:22px;
                       box-shadow:0 6px 16px rgba(0,0,0,.3);z-index:9100;cursor:pointer">⬆</button>
        </div>
    `;

    document.getElementById('btn-refresh').addEventListener('click', () => loadDirectory(currentPath));
    document.getElementById('btn-up').addEventListener('click', () => {
        if (currentPath === '/' || currentPath === '/cdn') return;
        // strip trailing slash
        let p = currentPath.replace(/\/+$/, '');
        let idx = p.lastIndexOf('/');
        if (idx <= 0) p = '/'; else p = p.slice(0, idx);
        navigateTo(p);   // P11: push history entry
    });
    document.getElementById('btn-create-folder').addEventListener('click', promptCreateFolder);
    document.getElementById('btn-browse-cdn').addEventListener('click', () => navigateTo('/cdn'));  // P11
    document.getElementById('btn-trash').addEventListener('click', openTrashView);

    // Toolbar collapse toggle (mobile)
    document.getElementById('btn-toolbar-toggle').addEventListener('click', () => {
        const box = document.getElementById('fd-toolbar-btns');
        box.classList.toggle('fd-toolbar-open');
    });

    // Hidden file input — "Choose files" button triggers it
    document.getElementById('btn-file-choose').addEventListener('click', () => {
        document.getElementById('upload-file').click();
    });
    document.getElementById('upload-file').addEventListener('change', function () {
        const n   = this.files ? this.files.length : 0;
        const lbl = document.getElementById('upload-file-label');
        if (lbl) {
            lbl.textContent = n === 0
                ? (t('no_file_selected') !== 'no_file_selected' ? t('no_file_selected') : 'Choose files…')
                : n === 1 ? this.files[0].name : `${n} files selected`;
        }
        if (_mobileUploadPending) {
            _mobileUploadPending = false;
            if (n > 0) handleUploadForm({ preventDefault(){} });
        }
    });
    // Folders-first toggle
    function updateFoldersMixedBtn() {
        const btn = document.getElementById('btn-folders-mixed');
        if (!btn) return;
        btn.textContent = sortFoldersMixed ? t('folder_sort_mix') : t('folder_sort_first');
        btn.style.background = sortFoldersMixed ? '#6b7280' : '#0ea5e9';
    }
    updateFoldersMixedBtn();
    document.getElementById('btn-folders-mixed').addEventListener('click', () => {
        sortFoldersMixed = !sortFoldersMixed;
        localStorage.setItem('fluxdrop_sort_mixed', JSON.stringify(sortFoldersMixed));
        updateFoldersMixedBtn();
        loadDirectory(currentPath);
    });
    document.getElementById('upload-form').addEventListener('submit', handleUploadForm);

    // Folder upload toggle — switches the file input between file-mode and directory-mode
    let _folderMode = false;
    const _folderBtn = document.getElementById('btn-folder-toggle');
    const _fileInput = document.getElementById('upload-file');
    _folderBtn.addEventListener('click', () => {
        _folderMode = !_folderMode;
        if (_folderMode) {
            _fileInput.setAttribute('webkitdirectory', '');
            _fileInput.setAttribute('mozdirectory', '');
            _fileInput.removeAttribute('multiple');
            _folderBtn.textContent = t('file_button');
            _folderBtn.style.background = '#6366f1';
            _folderBtn.title = t('files_mode');
        } else {
            _fileInput.removeAttribute('webkitdirectory');
            _fileInput.removeAttribute('mozdirectory');
            _fileInput.setAttribute('multiple', '');
            _folderBtn.textContent = t('folder_button');
            _folderBtn.style.background = '#0ea5e9';
            _folderBtn.title = t('folder_mode');
        }
        _fileInput.value = '';
    });

    // ── Mobile: reveal file picker only when a fine pointer is available ────
    // fd-upload-wrap defaults to display:none (set in the HTML above).
    // We show it only when the device has a fine pointer (mouse/trackpad).
    // Using `removeProperty` means the CSS media-query rule is the final
    // arbiter on change — we never fight it with an inline !important.
    //
    // Two separate media queries are checked as a belt-and-suspenders guard
    // against browsers that mis-report one but not both:
    //   (pointer: fine)  — primary pointer is a mouse/trackpad
    //   (hover: hover)   — device supports hover (non-touch)
    // If EITHER is true we treat the device as having a mouse attached.
    (function _initUploadWrapVisibility() {
        const wrap = document.getElementById('fd-upload-wrap');
        if (!wrap) return;
        const mqFine  = window.matchMedia('(pointer: fine)');
        const mqHover = window.matchMedia('(hover: hover)');
        function apply() {
            if (mqFine.matches || mqHover.matches) {
                wrap.style.removeProperty('display');   // let CSS decide (default block)
            } else {
                wrap.style.display = 'none';            // force-hide on touch-only
            }
        }
        apply();
        mqFine.addEventListener('change',  apply);
        mqHover.addEventListener('change', apply);
    })();

    // ── Mobile: dedicated upload button when no fine pointer is available ───
    // _initUploadWrapVisibility (above) hides the desktop upload toolbar on
    // touch-only devices, but nothing replaced it — touch users had no way to
    // trigger an upload at all (drag-and-drop is also fine-pointer-only; see
    // _initDragDrop below, which bails out early on touch devices). This FAB
    // is the visual inverse of that same check, PLUS a viewport-width
    // fallback: (pointer: fine)/(hover: hover) turned out to be unreliable on
    // real mobile Chrome/Firefox (both reported as if a mouse were attached,
    // hiding the FAB) even though Chrome DevTools' mobile emulation — which
    // forces these media features deterministically — showed it correctly.
    // Width doesn't have that inconsistency, so the FAB shows if EITHER
    // signal says "this looks like a touch/mobile device".
    (function _initMobileUploadFab() {
        const fab = document.getElementById('fd-mobile-upload-fab');
        if (!fab) return;
        const mqFine  = window.matchMedia('(pointer: fine)');
        const mqHover = window.matchMedia('(hover: hover)');
        const mqWidth = window.matchMedia('(max-width: 820px)');
        function apply() {
            const looksTouchOrMobile = !(mqFine.matches || mqHover.matches) || mqWidth.matches;
            fab.style.display = looksTouchOrMobile ? 'flex' : 'none';
        }
        apply();
        mqFine.addEventListener('change',  apply);
        mqHover.addEventListener('change', apply);
        mqWidth.addEventListener('change', apply);

        fab.addEventListener('click', () => {
            _mobileUploadPending = true;
            document.getElementById('upload-file').click();
        });
    })();

    // ── Drag-and-drop upload ───────────────────────────────────────────────────
    // Drop zone covers the whole fd-drop-zone div (upload row + hint line).
    // Files and folders are both supported; type is auto-detected from the dropped
    // DataTransferItems and the folder-toggle button is kept in sync.
    //
    // Folder traversal uses the FileSystem Access API (webkitGetAsEntry) to read
    // directory trees recursively.  webkitRelativePath is injected onto each File
    // object so the existing handleUploadForm / uploadChunked pipeline works
    // without any modification.
    ;(function _initDragDrop() {
        const dropZone = document.getElementById('fd-drop-zone');
        const dropHint = document.getElementById('fd-drop-hint');
        if (!dropZone) return;

        // Only activate on fine-pointer devices — touch drag-and-drop is unreliable
        if (!window.matchMedia('(pointer: fine)').matches) return;

        let dragDepth = 0;   // counter avoids false dragleave on child elements

        function _setActive(on) {
            dragDepth = on ? Math.max(dragDepth, 1) : 0;
            dropZone.style.borderColor  = on ? 'var(--fd-accent,#3b82f6)' : 'transparent';
            dropZone.style.background   = on ? 'var(--fd-accent-bg,#eff6ff)' : '';
            if (dropHint) dropHint.style.display = on ? 'block' : 'none';
        }

        dropZone.addEventListener('dragenter', e => { e.preventDefault(); dragDepth++; _setActive(true); });
        dropZone.addEventListener('dragleave', () => { if (--dragDepth <= 0) _setActive(false); });
        dropZone.addEventListener('dragover',  e => e.preventDefault());

        // ── Recursive FileSystemEntry reader ──────────────────────────────────
        // Returns [{ file, rel }] where rel is the path relative to the drop root.
        async function _readEntries(dataTransferItemList) {
            const results = [];
            let hasDir = false;

            async function traverse(entry, pathPrefix) {
                if (entry.isFile) {
                    const file = await new Promise((res, rej) => entry.file(res, rej));
                    // Inject relative path so uploadChunked sees the folder structure
                    try {
                        Object.defineProperty(file, 'webkitRelativePath',
                            { value: pathPrefix + entry.name, configurable: true, writable: false });
                    } catch (_) { /* read-only on some browsers — fall back to flat name */ }
                    results.push({ file, rel: pathPrefix + entry.name });
                } else if (entry.isDirectory) {
                    hasDir = true;
                    const reader = entry.createReader();
                    let batch;
                    // readEntries returns at most 100 items per call — loop until empty
                    do {
                        batch = await new Promise((res, rej) => reader.readEntries(res, rej));
                        for (const child of batch) {
                            await traverse(child, pathPrefix + entry.name + '/');
                        }
                    } while (batch.length > 0);
                }
            }

            const topLevel = [];
            for (let i = 0; i < dataTransferItemList.length; i++) {
                const item = dataTransferItemList[i];
                if (item.kind !== 'file') continue;
                const entry = item.webkitGetAsEntry?.();
                if (entry) topLevel.push(entry);
                else {
                    const f = item.getAsFile();
                    if (f) results.push({ file: f, rel: f.name });
                }
            }
            // Traverse all top-level entries in parallel
            await Promise.all(topLevel.map(e => traverse(e, '')));
            return { results, hasDir };
        }

        dropZone.addEventListener('drop', async e => {
            e.preventDefault();
            _setActive(false);

            const { results, hasDir } = await _readEntries(e.dataTransfer.items);
            if (!results.length) return;

            // Auto-sync the folder-toggle button to match what was dropped
            if (hasDir && !_folderMode) {
                _folderMode = true;
                if (_folderBtn) {
                    _folderBtn.textContent = t('file_button') || '📄 Files';
                    _folderBtn.style.background = '#6366f1';
                    _folderBtn.title = t('files_mode') || 'Switch to file mode';
                }
            } else if (!hasDir && _folderMode) {
                _folderMode = false;
                if (_folderBtn) {
                    _folderBtn.textContent = t('folder_button') || '📁 Folder';
                    _folderBtn.style.background = '#0ea5e9';
                    _folderBtn.title = t('folder_mode') || 'Switch to folder mode';
                }
            }

            // Update the "Choose files…" label for visual feedback
            const lbl = document.getElementById('upload-file-label');
            if (lbl) {
                lbl.textContent = results.length === 1
                    ? results[0].file.name
                    : `${results.length} items dropped`;
            }

            // Feed directly into the upload pipeline (same path as the form submit)
            const isProtected = document.getElementById('upload-protected')?.checked || false;
            const ownerType   = currentPath.startsWith('/cdn') ? 'catbox' : 'user';
            const basePath    = currentPath.endsWith('/') ? currentPath : currentPath + '/';

            window.addEventListener('beforeunload', windowLock);
            const items = results.map(({ file, rel }) => ({
                file,
                destRel: basePath + rel,
                ownerType,
                isProtected,
            }));

            if (items.length === 1) {
                try {
                    await uploadChunked(items[0].file, items[0].destRel, { ownerType });
                    _notifyUploadDone(1);
                    showMessage('Upload successful', `${items[0].file.name} uploaded.`);
                    loadDirectory(currentPath);
                } catch (err) {
                    if (err.name !== 'PauseSignal' && err.message !== 'Upload cancelled')
                        showMessage('Upload failed', err.message || String(err));
                } finally {
                    window.removeEventListener('beforeunload', windowLock);
                }
            } else {
                const [first, ...rest] = items;
                window._uploadQueue = [...(window._uploadQueue || []), ...rest];
                const refreshQ = () => {
                    const btn = document.getElementById('btn-show-queue');
                    const countEl = document.getElementById('queue-count');
                    if (btn && countEl) {
                        const q = window._uploadQueue;
                        if (q.length > 0) { btn.classList.remove('hidden'); countEl.textContent = q.length; }
                        else btn.classList.add('hidden');
                    }
                };
                refreshQ();
                _lastUploadBatchCount += items.length;
                let _dropOk = 0, _dropFail = 0;
                function _finishDrop() {
                    window.removeEventListener('beforeunload', windowLock);
                    _notifyUploadDone(_dropOk, _dropFail);
                    // No extra loadDirectory() here — the loop's own per-item
                    // refresh (above) already covers the last completed item;
                    // this used to unconditionally re-fetch the same listing a
                    // second time right after it (matches drainQueue's pattern,
                    // which never had this duplicate).
                }
                async function drainDrop(item) {
                    while (item) {
                        try {
                            await uploadChunked(item.file, item.destRel, { ownerType: item.ownerType });
                            _dropOk++;
                            loadDirectory(currentPath);
                        } catch (err) {
                            if (err.name === 'PauseSignal') {
                                // Queue waits here — the next file doesn't start
                                // until the user resumes or cancels the paused
                                // one (tray handlers call _pausedQueueDrain).
                                _pausedQueueDrain = () => {
                                    _pausedQueueDrain = null;
                                    let next = null;
                                    if (window._uploadQueue?.length > 0) { next = window._uploadQueue.shift(); refreshQ(); }
                                    if (next) drainDrop(next); else _finishDrop();
                                };
                                return;
                            }
                            if (err.message !== 'Upload cancelled') {
                                _dropFail++;
                                showMessage('Upload failed', `${item.file.name}: ${err.message || String(err)}`);
                                window.removeEventListener('beforeunload', windowLock);
                            }
                        }
                        if (window._uploadQueue?.length > 0) { item = window._uploadQueue.shift(); refreshQ(); }
                        else { item = null; }
                    }
                    _finishDrop();
                }
                drainDrop(first);
            }
        });
    })();

    // ── Upload queue state ──────────────────────────────────────────
    // Holds { file, destRel, ownerType, isProtected } waiting to upload.
    window._uploadQueue = window._uploadQueue || [];

    function refreshQueueBtn() {
        const btn = document.getElementById('btn-show-queue');
        const countEl = document.getElementById('queue-count');
        if (!btn || !countEl) return;
        const q = window._uploadQueue;
        if (q.length > 0) { btn.classList.remove('hidden'); countEl.textContent = q.length; }
        else { btn.classList.add('hidden'); }
    }

    function refreshInterruptedBtn() {
        const btn = document.getElementById('btn-resume-interrupted');
        const countEl = document.getElementById('interrupted-count');
        if (!btn || !countEl) return;
        const pending = getAllInterruptedUploads();
        if (pending.length > 0) { btn.classList.remove('hidden'); countEl.textContent = pending.length; }
        else { btn.classList.add('hidden'); }
    }

    refreshQueueBtn();
    refreshInterruptedBtn();

    document.getElementById('btn-show-queue').addEventListener('click', () => {
        openUploadQueuePanel(refreshQueueBtn);
    });

    // --- old refreshResumeBtn stub (kept for call compatibility below) ---
    function refreshResumeBtn() { refreshInterruptedBtn(); }

    document.getElementById('btn-resume-interrupted').addEventListener('click', () => {
        openInterruptedManager(refreshInterruptedBtn);
    });

    // P11: parse path from URL if arriving via deep-link or back-navigation.
    // Matches  <_APP_BASE>/files  or  <_APP_BASE>/files/<subpath>
    (function _initPathFromUrl() {
        const escapedBase = _APP_BASE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const match = window.location.pathname.match(
            new RegExp('^' + escapedBase + '\/files(\/.*)?$')
        );
        if (match) {
            // Browsers percent-encode spaces/special chars in pathname before
            // JS sees it (e.g. "My Folder" becomes "My%20Folder").  Decode
            // back to the raw path so encodePath() doesn't double-encode
            // (%20 → %2520) when building API URLs → "Directory not found".
            try {
                currentPath = decodeURIComponent(match[1] || '/');
            } catch (_) {
                currentPath = match[1] || '/'; // malformed % sequence — use as-is
            }
        }
        _syncUrlToPath(currentPath);
    })();
    // Initial load
    loadDirectory(currentPath);
}

// Helper: build API path segment
function apiPathFor(path) {
    // path should start with '/'
    if (!path) path = '/';
    if (!path.startsWith('/')) path = '/' + path;
    return `/api/v1/list${encodePath(path)}`;
}


// ── Skeleton loader helpers ──────────────────────────────────────────────
// Returns an HTML string of N animated skeleton table rows that mimic
// the real file-list table layout, preventing UI flash on directory loads.
function skeletonRows(n = 6) {
    // Use CSS vars so the shimmer matches whatever theme is active.
    // --fd-skel-base / --fd-skel-shine are defined in fd_dark.css.
    // Fallback values cover the case where fd_dark.css hasn't loaded yet.
    const shimmer = [
        'background:linear-gradient(90deg,var(--fd-skel-base,#e2e8f0) 25%,var(--fd-skel-shine,#f1f5f9) 50%,var(--fd-skel-base,#e2e8f0) 75%)',
        'background-size:200% 100%',
        'animation:fd-shimmer 1.4s infinite',
        'border-radius:4px',
        'display:inline-block',
    ].join(';');

    // Inject keyframes once
    if (!document.getElementById('fd-shimmer-style')) {
        const st = document.createElement('style');
        st.id = 'fd-shimmer-style';
        st.textContent = '@keyframes fd-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}';
        document.head.appendChild(st);
    }

    const widths = [
        ['55%','8%','14%'],
        ['40%','10%','14%'],
        ['62%','7%','14%'],
        ['48%','9%','14%'],
        ['35%','11%','14%'],
        ['58%','8%','14%'],
    ];
    // Name widths vary to look natural; size/mtime are fixed; actions are right-aligned
    const nameWidths = ['55%','40%','65%','48%','35%','60%'];
    return Array.from({ length: n }, (_, i) => {
        const nw = nameWidths[i % nameWidths.length];
        return `<tr class="border-t">
            <td style="padding:9px 8px;vertical-align:middle">
                <span style="${shimmer};width:${nw};height:14px"></span>
            </td>
            <td style="padding:9px 8px;vertical-align:middle">
                <span style="${shimmer};width:70%;height:13px"></span>
            </td>
            <td style="padding:9px 8px;vertical-align:middle" class="fd-col-mtime">
                <span style="${shimmer};width:80%;height:13px"></span>
            </td>
            <td style="padding:9px 8px;vertical-align:middle;text-align:right">
                <span style="${shimmer};width:64px;height:24px;border-radius:6px;margin-left:4px"></span>
                <span style="${shimmer};width:52px;height:24px;border-radius:6px;margin-left:4px"></span>
                <span style="${shimmer};width:48px;height:24px;border-radius:6px;margin-left:4px"></span>
            </td>
        </tr>`;
    }).join('');
}

async function loadDirectory(path) {
    const fileList = document.getElementById('file-list');
    const breadcrumb = document.getElementById('path-breadcrumb');
    // Normalize path
    if (!path) path = '/';
    if (!path.startsWith('/')) path = '/' + path;
    // NOTE: multi-selection clearing on real navigation happens in
    // navigateTo() / the popstate handler, BEFORE they call this function —
    // by the time loadDirectory() runs, currentPath already equals `path`
    // for both a genuine navigation and a same-folder refresh, so this
    // function has no reliable way to tell the two apart itself.
    currentPath = path;
    // Render clickable breadcrumb
    (function renderBreadcrumb(p) {
        const segs = p.replace(/\/+$/, '').split('/').filter((_, i) => i === 0 ? true : Boolean(_));
        // segs[0] is always '' (from leading slash); replace with 'root'
        let html = '';
        let built = '';
        segs.forEach((seg, idx) => {
            if (idx === 0) {
                built = '/';
                html += `<button onclick="navigateTo('/')" style="background:none;border:none;color:#3b82f6;cursor:pointer;font-weight:600;padding:0 2px">${t('fluxdrop_file_manager_path_root')}</button>`;
            } else {
                built = built.endsWith('/') ? built + seg : built + '/' + seg;
                const bp = built;
                html += ` <span style="color:#94a3b8">/</span> `;
                const isLast = idx === segs.length - 1;
                if (isLast) {
                    // data-fd-notranslate: this is a user-supplied folder/file name —
                    // prevent the MutationObserver from auto-translating it.
                    html += `<span style="color:#1e293b;font-weight:600" data-fd-notranslate>${escapeHtml(seg)}</span>`;
                } else {
                    html += `<button onclick="navigateTo('${escapeHtmlAttr(bp)}')" style="background:none;border:none;color:#3b82f6;cursor:pointer;padding:0 2px" data-fd-notranslate>${escapeHtml(seg)}</button>`;
                }
            }
        });
        breadcrumb.innerHTML = html;
    })(path);
    // Build sortable column headers — shows arrow on the active column
    function sortHeaders() {
        const cols = [
            { key: 'name',  label: 'Name',     align: 'left'  },
            { key: 'size',  label: 'Size',      align: 'left'  },
            { key: 'mtime', label: 'Modified',  align: 'left', cls: 'fd-col-mtime'  },
        ];
        const thStyle = (align, cls) =>
            `padding:8px;font-size:12px;font-weight:600;color:#64748b;text-align:${align};` +
            `user-select:none;white-space:nowrap;` + (cls ? '' : '');
        const btnStyle =
            `background:none;border:none;cursor:pointer;font-size:12px;font-weight:700;` +
            `color:#64748b;padding:0;display:inline-flex;align-items:center;gap:3px;`;
        const ths = cols.map(c => {
            const arrow = currentSort.key === c.key
                ? (currentSort.dir === 'asc' ? ' ▲' : ' ▼')
                : ' ⇅';
            const activeStyle = currentSort.key === c.key
                ? 'color:#2563eb;' : '';
            const clsAttr = c.cls ? ` class="${c.cls}"` : '';
            return `<th style="${thStyle(c.align)}"${clsAttr}>
                <button onclick="window._sortBy('${c.key}')"
                    style="${btnStyle}${activeStyle}">${c.label}<span style="font-size:10px;opacity:.7">${arrow}</span></button>
            </th>`;
        }).join('');
        return `<thead><tr style="border-bottom:2px solid #e2e8f0">
            ${ths}
            <th style="padding:4px 2px;font-size:14px;font-weight:400;color:#94a3b8;text-align:right;width:1px;white-space:nowrap">⋮</th>
        </tr></thead>`;
    }

    const TABLE_WRAP = `<table style="width:100%;table-layout:fixed;border-collapse:collapse">
        <colgroup>
            <col style="width:auto">
            <col style="width:8%">
            <col class="fd-col-mtime" style="width:17%">
            <col style="width:72px">
        </colgroup>`;

    // Show skeleton rows immediately so the table shape appears while fetching
    fileList.innerHTML = TABLE_WRAP + sortHeaders() +
        `<tbody>${skeletonRows(7)}</tbody></table>`;

    try {
        const endpoint = path === '/' ? '/api/v1/list/' : `/api/v1/list${encodePath(path)}`;
        const data = await apiCall(endpoint, 'GET', null, true);
        const entries = data.entries || [];
        if (entries.length === 0) {
            fileList.innerHTML = `<p class="text-sm text-gray-600" style="padding:1rem">${t('empty_folder')}</p>`;
            return;
        }
        const sorted = sortEntries(entries);
        const rows = sorted.map(e => renderEntryRow(e)).join('');
        fileList.innerHTML = TABLE_WRAP + sortHeaders() +
            `<tbody>${rows}</tbody></table>`;
        attachRowListeners();
        // Re-apply checkmarks (exact selected paths) and dash indicators
        // (folders containing a selected descendant) to the freshly-rendered
        // rows — a fresh loadDirectory() render always starts with plain,
        // unselected row markup, so this is what makes persisted selections
        // (see _fdKeepSelectionOnNav) actually visible again.
        _applySelectionVisuals();
        // Populate the pre-rendered fd-sel-bar with ghost buttons so its height
        // is stable before any selection is made.  _clearSelection() will call
        // _updateSelBar() again but the bar may not yet be in the DOM on first load.
        _updateSelBar();
    } catch (err) {
        // SESSION_EXPIRED: apiCall already cleared the token and called
        // renderApp('login') — don't overwrite the login view with an error.
        if (err.message === 'SESSION_EXPIRED') return;
        fileList.innerHTML = `<p class="text-sm text-red-600" style="padding:1rem">Failed to load directory: ${escapeHtml(err.message)}</p>`;
    }
}

// Sort an array of entry objects according to currentSort + sortFoldersMixed.
// The original array is not mutated.
function sortEntries(entries) {
    const { key, dir } = currentSort;
    const mul = dir === 'asc' ? 1 : -1;

    function cmp(a, b) {
        // Folders-first grouping (unless mixed mode)
        if (!sortFoldersMixed && a.is_dir !== b.is_dir) {
            return a.is_dir ? -1 : 1;
        }
        let va, vb;
        if (key === 'size') {
            va = a.is_dir ? -1 : (a.size || 0);
            vb = b.is_dir ? -1 : (b.size || 0);
            return mul * (va - vb);
        } else if (key === 'mtime') {
            va = a.mtime || '';
            vb = b.mtime || '';
            return mul * va.localeCompare(vb);
        } else { // name
            return mul * (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' });
        }
    }
    return entries.slice().sort(cmp);
}

// Global handler called by inline onclick in sort headers
window._sortBy = function(key) {
    if (currentSort.key === key) {
        currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort = { key, dir: 'asc' };
    }
    localStorage.setItem('fluxdrop_sort', JSON.stringify(currentSort));
    loadDirectory(currentPath);
};


// Compact action button style used inside the file-list table.
// Much smaller than the global .btn so all buttons fit on one row.
function _ab(label, cls, color, dataAttrs) {
    const attrs = Object.entries(dataAttrs).map(([k,v]) => `data-${k}="${v}"`).join(' ');
    return `<button class="${cls}"
        style="background:${color};color:white;border:none;border-radius:6px;
               padding:3px 8px;font-size:11px;font-weight:600;cursor:pointer;
               white-space:nowrap;line-height:1.6"
        ${attrs}>${label}</button>`;
}

function renderEntryRow(e) {
    const nameEsc = escapeHtml(e.name);
    const path    = e.path;
    const safePA  = escapeHtmlAttr(path);

    // The list endpoint now embeds each folder's cached size directly (no
    // more one fetch per visible folder) — but the cache can still be cold
    // for a folder nobody's opened before, in which case e.size is null and
    // we fall back to the old lazy per-row fetch via loadFolderSize().
    const folderWarm = e.is_dir && e.size != null;
    const folderTitle = folderWarm && e.file_count != null
        ? ` title="${e.file_count} file${e.file_count !== 1 ? 's' : ''}"` : '';
    const sizeStr = e.is_dir
        ? `<span class="folder-size-cell" data-path="${safePA}" ${folderWarm ? 'data-warm="1"' : ''}${folderTitle}
               style="color:#94a3b8">${folderWarm ? formatBytes(e.size) : '…'}</span>`
        : formatBytes(e.size);

    const TD_NAME = 'style="padding:9px 8px;vertical-align:middle;overflow:hidden;max-width:0"';

    // File name: natural width (not stretched) so dead-click area is minimised.
    const nameBtn = e.is_dir
        ? `<button class="open-btn fd-entry-name" data-path="${safePA}"
               style="background:none;border:none;cursor:pointer;font-weight:600;
                      color:var(--fd-accent,#2563eb);font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block"
               data-fd-notranslate title="${safePA}">📁 ${nameEsc}</button>`
        : `<button class="preview-btn fd-entry-name" data-path="${safePA}"
               style="background:none;border:none;cursor:pointer;font-weight:500;
                      color:var(--fd-text,#1e293b);font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block"
               data-fd-notranslate title="${safePA}">📄 ${nameEsc}</button>`;

    const uploaderLine = e.uploader
        ? `<div style="font-size:11px;color:#94a3b8;margin-top:2px">by ${escapeHtml(e.uploader)}</div>`
        : '';

    // "⋮" is the sole action trigger on both mobile and desktop
    const moreBtn = `<button class="fd-more-btn" data-path="${safePA}" data-is-dir="${e.is_dir ? '1' : '0'}"
        style="background:none;border:1px solid var(--fd-border,#e2e8f0);border-radius:5px;
               padding:2px 7px;cursor:pointer;font-size:16px;line-height:1.3;
               color:var(--fd-muted,#64748b);vertical-align:middle;flex-shrink:0"
        title="Actions">⋮</button>`;

    const TD_COMMON  = 'style="padding:9px 8px;vertical-align:middle;white-space:nowrap"';
    const TD_ACTIONS = 'style="padding:4px 2px;vertical-align:middle;text-align:right;width:1px;white-space:nowrap"';

    return `<tr class="border-t fd-file-row"
                data-path="${safePA}"
                data-is-dir="${e.is_dir ? '1' : '0'}"
                data-name="${escapeHtmlAttr(e.name)}"
                data-size="${e.size || 0}"
                data-mtime="${escapeHtmlAttr(e.mtime || '')}"
                data-uploader="${escapeHtmlAttr(e.uploader || '')}"
                style="transition:background 0.12s;user-select:none">
        <td ${TD_NAME}>
            <div style="display:flex;align-items:center;gap:5px;overflow:hidden">
                <span class="fd-sel-dot" style="display:none;width:14px;height:14px;flex-shrink:0;
                    border:2px solid var(--fd-accent,#3b82f6);border-radius:3px;align-items:center;
                    justify-content:center;font-size:9px;background:transparent"></span>
                <div style="min-width:0;flex:1;overflow:hidden">${nameBtn}${uploaderLine}</div>
            </div>
        </td>
        <td ${TD_COMMON} class="text-sm text-gray-500">${sizeStr}</td>
        <td ${TD_COMMON} class="text-sm text-gray-500 fd-col-mtime"
            style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${escapeHtmlAttr(e.mtime || '')}">${formatMtime(e.mtime)}</td>
        <td ${TD_ACTIONS}>${moreBtn}</td>
    </tr>`;
}

// Expose some functions globally for callers; listeners will invoke these.
window.enterDir = function(path) {
    // Navigate into a directory, update currentPath AND push a browser history
    // entry so the URL reflects the folder and F5 / back-button work correctly.
    navigateTo(path);
}


        // ======================================================================
        // --- DOWNLOAD MANAGER (resumable, progress-tracked) ---
        // NOTE: renderDownloadTray uses stable DOM patching so button clicks are
        // never lost mid-stream (no full innerHTML replacement while downloading).
        // ======================================================================

function formatBytes(b) {
    // 3 significant digits without scientific notation.
    // e.g. 1.04 GB, 23.5 MB, 135 kB, 1004 MB (stays MB until exactly 1 GiB).
    function fmt3(v) {
        if (v >= 100) return Math.round(v).toString();
        if (v >= 10)  return v.toFixed(1);
        return v.toFixed(2);
    }
    if (b < 1024)        return b + ' B';
    if (b < 1048576)     return fmt3(b / 1024)      + ' kB';
    if (b < 1073741824)  return fmt3(b / 1048576)   + ' MB';
    return                      fmt3(b / 1073741824) + ' GB';
}

/**
 * Format an ISO mtime string to a human-friendly label.
 *   Same calendar day  → "Today at 14:30"
 *   Previous day       → "Yesterday at 14:30"
 *   Older              → "15 Jan 2024 at 14:30"
 * Falls back to the raw string on parse failure.
 */
function formatMtime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const now  = new Date();
    const sameDay = (a, b) =>
        a.getFullYear() === b.getFullYear() &&
        a.getMonth()    === b.getMonth()    &&
        a.getDate()     === b.getDate();
    if (sameDay(d, now)) return t('fmt_today_at', { time });
    const yesterday = new Date(now);
    yesterday.setDate(now.getDate() - 1);
    if (sameDay(d, yesterday)) return t('fmt_yesterday_at', { time });
    return d.toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) + ' ' + t('fmt_at_time', { time });
}


        // ======================================================================
        // --- STREAMING DOWNLOAD ENGINE ...
        // ======================================================================

// Lazily load StreamSaver (only if needed and showSaveFilePicker absent)
let _streamSaverLoaded = false;
function _loadStreamSaver() {
    if (_streamSaverLoaded) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        // Load from local assets — no CDN dependency, no base-path breakage
        s.src = _APP_BASE + '/assets/streamsaver/StreamSaver.js';
        s.onload = () => {
            _streamSaverLoaded = true;
            // Tell StreamSaver where mitm.html lives using an absolute URL.
            // Without this it resolves relative to the script's own location,
            // which breaks on any page that isn't at the app root.
            if (typeof streamSaver !== 'undefined') {
                streamSaver.mitm = window.location.origin
                    + _APP_BASE
                    + '/assets/streamsaver/mitm.html';
            }
            resolve();
        };
        s.onerror = () => reject(new Error('StreamSaver unavailable'));
        document.head.appendChild(s);
    });
}

// Detect streaming-to-disk capability once
const _CAN_PICK = (typeof window.showSaveFilePicker === 'function');

// Active downloads: path → dl state object (shared by tray renderer)
// (replaces the old activeDownloads Map — same variable name kept for compat)
// dl = {
//   filename, totalSize, bytesReceived, status,
//   speed, eta, error,
//   _writer,       // FileSystemWritableFileStream | null
//   _abort,        // AbortController for current fetch
//   _resumeFrom,   // byte offset for next Range request
//   _chunks,       // [] only used in blob-fallback mode
//   _mode,         // 'picker' | 'streamsaver' | 'blob'
// }

/**
 * Primary entry point.  Call for both file and ZIP downloads.
 *
 * @param {string} path         - user-relative path (for dl token)
 * @param {object} [opts]
 * @param {string} [opts.directUrl]  - if set, skip token mint (ZIP endpoint)
 * @param {string} [opts.filename]   - override filename
 * @param {number} [opts.totalSize]  - hint for progress (ZIP: Content-Length)
 */
window.downloadFile = async function(path, opts = {}) {
    // Deduplicate: if already tracked, surface tray
    if (activeDownloads.has(path)) { renderDownloadTray(); return; }

    const filename = opts.filename || path.split('/').pop() || 'download';

    // ── Step 1: resolve write mode ────────────────────────────────────────────
    // This must happen BEFORE any await so that showSaveFilePicker() can be
    // called while the browser user-gesture is still active.  Any await
    // (including mintDownloadToken) consumes the gesture flag, causing
    // showSaveFilePicker to throw SecurityError which silently falls back to blob.
    //
    // StreamSaver is loaded lazily, so typeof streamSaver is *always* undefined
    // here on first call — we can't use it in the sync mode check.  Instead we
    // try picker first (Chrome/Edge), then load StreamSaver after the dialog
    // (Firefox/Safari path), then fall back to blob.

    let _earlyFileHandle = null;  // pre-opened FSAA handle (picker path only)
    let mode;

    if (typeof window.showSaveFilePicker === 'function') {
        // ── Picker path (Chrome 86+, Edge 86+) ───────────────────────────────
        // Open Save dialog NOW while the gesture is still live.
        // Any await before this call (including mintDownloadToken) would expire
        // the browser user-activation flag, causing SecurityError → blob fallback.
        const ext  = filename.split('.').pop() || '';
        const mime = _mimeForExt(ext);
        try {
            _earlyFileHandle = await window.showSaveFilePicker({
                suggestedName: filename,
                types: mime ? [{ description: 'File', accept: { [mime]: ['.' + ext] } }] : undefined,
            });
            mode = 'picker';
        } catch (err) {
            if (err.name === 'AbortError') return;  // user cancelled dialog
            // FSAA blocked in this context (sandboxed iframe etc.) — fall through.
            logging_warn('showSaveFilePicker failed, falling to native:', err);
        }
    }

    if (!mode) {
        // ── Native browser download (Firefox, Safari, all other browsers) ────
        // Trigger a plain <a href download> click after minting the token.
        // The browser's own download manager receives the file with
        // Accept-Ranges / Content-Disposition headers and handles pause/resume
        // automatically — no JS involvement needed after the click.
        //
        // This is strictly better than StreamSaver for Firefox because:
        //   • Resume works natively (browser sends Range: bytes=N- on resume)
        //   • No 2 GB RAM limit
        //   • No service worker pipe overhead
        //   • Downloads survive tab closes / refreshes
        //
        // StreamSaver is NOT used as a fallback here.  It gives JS progress
        // bars but silently breaks browser-native resume — a bad trade.
        // It remains available for explicit opt-in (see _loadStreamSaver).
        mode = 'native';
    }

    // ── Step 2: mint download token ───────────────────────────────────────────
    let dlUrl, totalSize;
    if (opts.directUrl) {
        dlUrl     = opts.directUrl;
        totalSize = opts.totalSize || null;
    } else {
        try {
            const td  = await mintDownloadToken(path);
            const enc = path.split('/').map(encodeURIComponent).join('/');
            dlUrl     = `${API_BASE_URL}/api/v1/download${enc}?dl_token=${encodeURIComponent(td.download_token)}`;
            totalSize = td.total_size || null;
        } catch (err) {
            showMessage('Download failed', err.message);
            return;
        }
    }

    // ── Native mode: trigger browser download and show tray entry ──────────────
    // The browser download manager handles everything from here — Range-based
    // resume, disk writes, progress.  We just show a tray entry so the user
    // knows something happened, then auto-dismiss it after a short delay.
    if (mode === 'native') {
        const dl = {
            filename, totalSize, bytesReceived: 0,
            status: 'downloading', speed: null, eta: null, error: null,
            _writer: null, _abort: new AbortController(),
            _resumeFrom: 0, _chunks: [], _mode: 'native',
            _dlUrl: dlUrl, _path: path, _fileHandle: null,
        };
        activeDownloads.set(path, dl);
        renderDownloadTray();

        // Trigger the download via a temporary <a> element.
        // The browser sees Content-Disposition: attachment and handles it.
        const a = document.createElement('a');
        a.href     = dlUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        // We have no visibility into browser-side progress, so just show
        // "Downloading via browser" and auto-dismiss after a few seconds.
        dl.status = 'done';
        const delay = getTrayDismissDelay();
        setTimeout(() => { activeDownloads.delete(path); renderDownloadTray(); },
                   Math.max(delay, 4000));
        renderDownloadTray();
        return;
    }

    // ── Blob mode warning ─────────────────────────────────────────────────────
    if (mode === 'blob' && totalSize && totalSize > 512 * 1024 * 1024) {
        const proceed = confirm(
            `⚠ Your browser doesn't support streaming downloads to disk.\n\n` +
            `Downloading ${formatBytes(totalSize)} will be buffered entirely in RAM ` +
            `before saving, which may freeze or crash the tab.\n\n` +
            `Use Chrome or Edge for large files. Continue anyway?`
        );
        if (!proceed) return;
    }

    const dl = {
        filename, totalSize, bytesReceived: 0,
        status: 'downloading', speed: null, eta: null, error: null,
        _writer: null, _abort: new AbortController(),
        _resumeFrom: 0, _chunks: [], _mode: mode,
        _dlUrl: dlUrl, _path: path,
        // Pre-opened FSAA handle — _runDownload uses this directly so it never
        // needs to call showSaveFilePicker() a second time (gesture already spent).
        _fileHandle: _earlyFileHandle,
    };
    activeDownloads.set(path, dl);
    renderDownloadTray();

    await _runDownload(path, dl);
};

/** Internal: open writer then stream. Separated so resume can re-enter. */
async function _runDownload(path, dl) {
    // 3. Open write destination (only on first run, not resume)
    if (!dl._writer && dl._mode !== 'blob') {
        try {
            if (dl._mode === 'picker') {
                const ext  = dl.filename.split('.').pop() || '';
                const mime = _mimeForExt(ext);
                const isResume = dl._resumeFrom > 0;
                if (!isResume) {
                    // First open: dl._fileHandle was pre-opened in downloadFile()
                    // while the user gesture was still active — just open the
                    // writable from it.  No second showSaveFilePicker() needed.
                    // Fallback: if handle is absent for some reason, open now.
                    if (!dl._fileHandle) {
                        const fh = await window.showSaveFilePicker({
                            suggestedName: dl.filename,
                            types: mime ? [{ description: 'File', accept: { [mime]: ['.' + ext] } }] : undefined,
                        });
                        dl._fileHandle = fh;
                    }
                    dl._writer = await dl._fileHandle.createWritable({ keepExistingData: false });
                } else {
                    // Resume: re-open the same handle with keepExistingData:true
                    // and seek to the byte offset so we append correctly.
                    // If the handle was lost (page reload), re-prompt and restart.
                    if (!dl._fileHandle) {
                        dl._resumeFrom   = 0;
                        dl.bytesReceived = 0;
                        const fh = await window.showSaveFilePicker({
                            suggestedName: dl.filename,
                            types: mime ? [{ description: 'File', accept: { [mime]: ['.' + ext] } }] : undefined,
                        });
                        dl._fileHandle = fh;
                        dl._writer = await dl._fileHandle.createWritable({ keepExistingData: false });
                    } else {
                        dl._writer = await dl._fileHandle.createWritable({ keepExistingData: true });
                        await dl._writer.seek(dl._resumeFrom);
                    }
                }
            } else {
                // StreamSaver
                const ws   = streamSaver.createWriteStream(dl.filename, {
                    size: dl.totalSize || undefined,
                });
                dl._writer = ws.getWriter();
            }
        } catch (err) {
            if (err.name === 'AbortError') {
                // User dismissed the save dialog → cancel cleanly
                activeDownloads.delete(path);
                renderDownloadTray();
                return;
            }
            // Fall back to blob
            dl._mode   = 'blob';
            dl._writer = null;
            logging_warn('showSaveFilePicker/StreamSaver failed, falling back to blob:', err);
        }
    }

    dl.status  = 'downloading';
    dl._abort  = new AbortController();
    renderDownloadTray();

    const headers = { ...(dl._authHeader || {}) };
    if (authToken && !headers['Authorization']) headers['Authorization'] = `Bearer ${authToken}`;
    if (dl._resumeFrom > 0) headers['Range'] = `bytes=${dl._resumeFrom}-`;

    // ── Transient-error retry ─────────────────────────────────────────────
    // On network-level failures (TypeError: failed to fetch), retry up to
    // MAX_RETRIES times with exponential backoff before surfacing an error.
    // AbortError (user pause/cancel) is never retried.
    const MAX_RETRIES   = 3;
    const RETRY_BASE_MS = 2000;

    try {

    let resp;
    for (let attempt = 0; ; attempt++) {
        try {
            resp = await fetchWithFallback(dl._dlUrl, {
                headers,
                signal: dl._abort.signal,
            });
            break; // success
        } catch (fetchErr) {
            if (fetchErr.name === 'AbortError') throw fetchErr; // re-throw; caught below
            if (attempt >= MAX_RETRIES) throw fetchErr;
            const wait = RETRY_BASE_MS * Math.pow(2, attempt);
            dl.status    = 'downloading';
            dl._retrying = true;
            // Per-second countdown so the tray shows a live timer
            for (let s = Math.round(wait / 1000); s > 0; s--) {
                dl.error = `Network error — retrying in ${s}s (${attempt + 1}/${MAX_RETRIES})`;
                renderDownloadTray();
                await new Promise((resolve, reject) => {
                    const t = setTimeout(resolve, 1000);
                    dl._abort.signal.addEventListener('abort',
                        () => { clearTimeout(t); reject(new DOMException('Aborted', 'AbortError')); },
                        { once: true });
                });
            }
            dl._retrying = false;
            dl.error = null;
            renderDownloadTray();
        }
    }

    if (!resp.ok && resp.status !== 206) {
        throw new Error(`Server returned HTTP ${resp.status}`);
    }

    // Update total from Content-Range on resume
    const cr = resp.headers.get('Content-Range');
    if (cr) {
        const m = cr.match(/bytes \d+-\d+\/(\d+)/);
        if (m) dl.totalSize = parseInt(m[1]);
    } else if (!dl.totalSize) {
        const cl = resp.headers.get('Content-Length');
        if (cl) dl.totalSize = parseInt(cl);
    }
    renderDownloadTray();

    // 4. Stream pipe
    const reader = resp.body.getReader();
    let lastLoaded = dl.bytesReceived;
    let lastTime   = Date.now();

    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            // Write chunk to destination
            if (dl._mode === 'blob') {
                dl._chunks.push(value);
            } else {
                await dl._writer.write(value);
            }

            dl.bytesReceived  += value.byteLength;
            dl._resumeFrom    += value.byteLength;   // advance resume cursor

            // ETA / speed
            const now = Date.now(), dt = (now - lastTime) / 1000;
            if (dt >= 0.4) {
                dl.speed     = (dl.bytesReceived - lastLoaded) / dt;
                dl.eta       = (dl.speed > 0 && dl.totalSize)
                    ? (dl.totalSize - dl.bytesReceived) / dl.speed : null;
                lastLoaded   = dl.bytesReceived;
                lastTime     = now;
            }
            renderDownloadTray();
        }
    } catch (streamErr) {
        // ── StreamSaver channel death detection ───────────────────────────
        // When the browser drops/cancels the download from its download
        // manager (e.g. Firefox pausing then aborting), StreamSaver's internal
        // MessageChannel gets nulled.  The next writer.write() throws something
        // like "can't access property 'port1', channel is null".
        // This is NOT resumable via Range — the browser's download entry is
        // gone.  Mark as 'cancelled' so Resume restarts from byte 0.
        if (streamErr.name !== 'AbortError' &&
            (streamErr.message?.includes('channel') ||
             streamErr.message?.includes('port1')   ||
             streamErr.message?.includes('port2'))) {
            if (dl._writer) {
                try { dl._writer.abort?.(); } catch (_) {}
                dl._writer = null;
            }
            // Stop the in-flight fetch — without this the browser keeps
            // buffering bytes even though nothing is consuming them.
            try { reader.cancel('channel closed'); } catch (_) {}
            dl._abort.abort();
            
            dl.status      = 'cancelled';
            dl._resumeFrom = 0;            // must restart — browser lost the download
            dl.bytesReceived = 0;
            dl.error = 'Browser dropped the download. Click Resume to start over.';
            renderDownloadTray();
            return;
        }
        throw streamErr; // re-throw for the outer catch
    }

    // 5. Finalise
    if (dl._mode === 'blob') {
        // Last-resort: trigger browser save from memory
        const blob = new Blob(dl._chunks);
        dl._chunks = [];  // free ASAP
        const a    = document.createElement('a');
        a.href     = URL.createObjectURL(blob);
        a.download = dl.filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 60_000);
    } else {
        await dl._writer.close();
        dl._writer = null;
    }

    dl.status = 'done';
    dl.speed  = null;
    dl.eta    = null;
    const delay = getTrayDismissDelay();
    if (delay > 0 && !dl._dismissScheduled) {
        dl._dismissScheduled = true;
        setTimeout(() => { activeDownloads.delete(path); renderDownloadTray(); }, delay);
    }
    renderDownloadTray();

} catch (err) {
    if (err.name === 'AbortError') {
        // Distinguish user-initiated cancel (via Cancel button → abort()) from
        // the browser pausing a download (also triggers AbortError).
        // We use dl._userCancelled flag set by cancelDownload() to tell them apart.
        dl.status = dl._userCancelled ? 'cancelled' : 'paused';
        if (dl._userCancelled) {
            dl.error = 'Download cancelled.';
            dl._userCancelled = false;
        }
    } else {
        dl.status = 'error';
        dl.error  = err.message;
        // Close writer so the partial file is flushed/discarded cleanly
        if (dl._writer) {
            try { await dl._writer.abort?.() ?? dl._writer.close(); } catch (_) {}
            dl._writer = null;
        }
    }
    renderDownloadTray();
}
}

// ── Resume ────────────────────────────────────────────────────────────────────
window.resumeDownload = async function(safePath) {
    const path = decodeURIComponent(safePath);
    const dl   = activeDownloads.get(path);
    if (!dl) return;

    // 'cancelled' means the browser dropped the download (StreamSaver channel
    // death) — the write stream is gone and we must start completely over.
    // _resumeFrom and bytesReceived were already reset to 0 at cancel time.
    if (dl.status === 'cancelled') {
        dl.error        = null;
        dl.speed        = null;
        dl.eta          = null;
        dl._writer      = null;
        dl._resumeFrom  = 0;
        dl.bytesReceived = 0;
        dl.totalSize    = null;
        dl._chunks      = [];
        // ZIP: re-enter downloadFolderZip so the writer is re-created properly
        if (dl._isZip) {
            activeDownloads.delete(path);
            renderDownloadTray();
            const folderPath = path.startsWith('__zip__') ? path.slice('__zip__'.length) : path;
            window.downloadFolderZip(folderPath);
            return;
        }
        // Non-ZIP: fall through — _runDownload will re-open the writer.
        // For picker mode: keep dl._fileHandle so _runDownload can seek instead
        // of asking the user to pick the file again. The writer itself is always
        // null here (it was closed or aborted), so _runDownload will re-create it.
    }

    // Re-mint token so it's still valid after a long pause
    if (!dl._isZip) {
        try {
            const td  = await mintDownloadToken(path);
            const enc = path.split('/').map(encodeURIComponent).join('/');
            dl._dlUrl = `${API_BASE_URL}/api/v1/download${enc}?dl_token=${encodeURIComponent(td.download_token)}`;
            // Sync server-confirmed offset as a floor
            const sc = td.bytes_confirmed || 0;
            if (sc < dl._resumeFrom) dl._resumeFrom = sc;
        } catch (err) {
            showMessage('Resume failed', err.message);
            return;
        }
    }

    dl.error  = null;
    dl.speed  = null;
    dl.eta    = null;

    // ZIP resume (non-cancelled): re-enter the stream loop via _runDownload.
    // _runDownload supports Range headers so it will continue from _resumeFrom.
    // Re-open StreamSaver writer if it was closed.
    if (dl._isZip && !dl._writer && dl._mode === 'streamsaver') {
        try {
            const ws   = streamSaver.createWriteStream(dl.filename);
            dl._writer = ws.getWriter();
        } catch (_) {
            dl._mode   = 'blob';
            dl._writer = null;
        }
    }

    dl._writer = dl._isZip ? dl._writer : null; // let _runDownload re-open picker/SS for files
    await _runDownload(path, dl);
};

// ── Cancel ────────────────────────────────────────────────────────────────────
window.cancelDownload = function(path) {
    try { path = decodeURIComponent(path); } catch (_) {}
    const dl = activeDownloads.get(path);
    if (dl) {
        dl._userCancelled = true;
        dl._abort?.abort();
        if (dl._writer) {
            dl._writer.abort?.().catch(() => {});
            dl._writer = null;
        }
        dl._fileHandle = null;   // release FSAA handle on full cancel
    }
    activeDownloads.delete(path);
    renderDownloadTray();
};

// ── ZIP folder download — now also streaming ──────────────────────────────────
window.downloadFolderZip = async function(path) {
    const zipKey = '__zip__' + path;
    if (activeDownloads.has(zipKey)) { renderDownloadTray(); return; }

    const folderName = path.split('/').filter(Boolean).pop() || 'download';
    const filename   = folderName + '.zip';
    const metaUrl    = `${API_BASE_URL}/api/v1/zip_meta${path.split('/').map(encodeURIComponent).join('/')}`;
    const authHdr    = authToken ? { Authorization: `Bearer ${authToken}` } : {};

    // Register a tray entry immediately so the user sees feedback
    const dl = {
        filename,
        totalSize:     null,
        bytesReceived: 0,
        status:        'downloading',
        speed:         null,
        eta:           null,
        error:         null,           // status text shows "Building…"/"Hashing…"
        _writer:       null,
        _abort:        new AbortController(),
        _resumeFrom:   0,
        _chunks:       [],
        _mode:         'native',       // ZIP always uses native <a> download
        _dlUrl:        null,
        _path:         zipKey,
        _isZip:        true,
        _authHeader:   authHdr,
        _needsHashing: false,
        _jobId:        null,           // set after zip_meta responds
    };
    activeDownloads.set(zipKey, dl);
    renderDownloadTray();

    // ── Phase 1: kick off async job ────────────────────────────────────────
    // Server returns {job_id, status:'scanning', poll_url} immediately —
    // no waiting for the CRC32 scan to finish.
    let jobResp;
    try {
        const r = await fetchWithFallback(metaUrl, {
            headers: authHdr,
            signal:  dl._abort.signal,
        });
        jobResp = await r.json();
        if (!r.ok) throw new Error(jobResp.error || `HTTP ${r.status}`);
    } catch (err) {
        dl.status = err.name === 'AbortError'
            ? (dl._userCancelled ? 'cancelled' : 'paused')
            : 'error';
        dl.error  = err.name === 'AbortError' ? null : err.message;
        renderDownloadTray();
        return;
    }

    dl._jobId = jobResp.job_id;
    const pollUrl = `${API_BASE_URL}${jobResp.poll_url}`;
    renderDownloadTray();

    // ── Phase 2: poll zip_status until ready ───────────────────────────────
    // Ping every second.  The tray shows progress (N / total files scanned).
    let metaData = null;
    while (true) {
        if (dl._abort.signal.aborted) {
            dl.status = dl._userCancelled ? 'cancelled' : 'paused';
            renderDownloadTray();
            return;
        }
        await new Promise(resolve => {
            const t = setTimeout(resolve, 1000);
            dl._abort.signal.addEventListener('abort',
                () => { clearTimeout(t); resolve(); }, { once: true });
        });
        if (dl._abort.signal.aborted) {
            dl.status = dl._userCancelled ? 'cancelled' : 'paused';
            renderDownloadTray();
            return;
        }
        let statusResp;
        try {
            const r = await fetchWithFallback(pollUrl, {
                headers: authHdr,
                signal:  dl._abort.signal,
            });
            statusResp = await r.json();
            if (!r.ok) throw new Error(statusResp.error || `HTTP ${r.status}`);
        } catch (err) {
            if (err.name === 'AbortError') continue;
            dl.status = 'error';
            dl.error  = err.message;
            renderDownloadTray();
            return;
        }
        if (statusResp.status === 'error') {
            dl.status = 'error';
            dl.error  = statusResp.error || 'Server error building archive';
            renderDownloadTray();
            return;
        }
        if (statusResp.status === 'scanning') {
            // Update progress in tray (files scanned / total)
            const prog  = statusResp.progress ?? 0;
            const total = statusResp.total;
            dl._needsHashing = true;  // if we're polling, at least some files needed hashing
            dl._scanProgress = { prog, total };
            renderDownloadTray();
            continue;
        }
        if (statusResp.status === 'ready') {
            metaData = statusResp;
            break;
        }
    }

    // ── Phase 3: trigger native browser download ───────────────────────────
    // The stream endpoint sends Content-Length + Accept-Ranges so the browser
    // can pause and resume the download natively via its download manager.
    // We don't use StreamSaver here — native <a href> downloads support
    // Range requests directly; StreamSaver can't pass Range headers.
    dl._needsHashing = !!metaData.needs_hashing;
    dl.totalSize     = metaData.size || null;
    dl.filename      = metaData.filename || dl.filename;
    dl.error         = (metaData.missing && metaData.missing.length > 0)
        ? `\u26a0 ${metaData.missing.length} file(s) skipped (unreadable)`
        : null;

    // Build the stream URL with auth token as query param so the <a> tag works
    // (fetch headers can't be set on a plain link click).
    // _check_token_auth on the server already accepts ?token= as a fallback.
    const streamBase = `${API_BASE_URL}${metaData.url}`;
    const streamUrl  = authToken
        ? `${streamBase}?token=${encodeURIComponent(authToken)}`
        : streamBase;

    const a       = document.createElement('a');
    a.href        = streamUrl;
    a.download    = dl.filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    if (metaData.missing && metaData.missing.length > 0) {
        const list = metaData.missing.map(f => `<li style="font-family:monospace;font-size:12px">${f}</li>`).join('');
        const mo = document.createElement('div');
        mo.className = 'modal-overlay';
        mo.innerHTML = `<div class="modal-content" style="max-width:480px">
            <h3 style="font-size:16px;font-weight:700;margin-bottom:8px">⚠ ${metaData.missing.length} file(s) will be skipped</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:10px">These files could not be read and will be absent from the ZIP:</p>
            <ul style="max-height:200px;overflow-y:auto;padding-left:18px;margin-bottom:16px">${list}</ul>
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="zip-missing-cancel" class="btn" style="background:#e2e8f0;color:#1e293b">Cancel</button>
                <button id="zip-missing-ok" class="btn">Download anyway</button>
            </div>
        </div>`;
        document.body.appendChild(mo);
        await new Promise(resolve => {
            mo.querySelector('#zip-missing-ok').addEventListener('click', () => { mo.remove(); resolve(true); });
            mo.querySelector('#zip-missing-cancel').addEventListener('click', () => { mo.remove(); resolve(false); dl.status = 'cancelled'; renderDownloadTray(); });
        }).then(proceed => { if (!proceed) return; /* falls through to a.click() */ });
        if (dl.status === 'cancelled') return;
    }
    a.click();
    document.body.removeChild(a);

    // Mark done — browser's download manager owns the rest from here
    dl.status = 'done';
    renderDownloadTray();
    const delay = getTrayDismissDelay();
    if (delay > 0) {
        setTimeout(() => { activeDownloads.delete(zipKey); renderDownloadTray(); }, delay);
    }
};

// ── Tiny MIME helper ──────────────────────────────────────────────────────────
function _mimeForExt(ext) {
    const m = {
        mp4:'video/mp4', webm:'video/webm', mkv:'video/x-matroska',
        mp3:'audio/mpeg', flac:'audio/flac', wav:'audio/wav', m4a:'audio/mp4',
        jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', gif:'image/gif',
        webp:'image/webp', svg:'image/svg+xml', pdf:'application/pdf',
        zip:'application/zip', tar:'application/x-tar',
        txt:'text/plain', md:'text/markdown', json:'application/json',
        js:'text/javascript', css:'text/css', html:'text/html',
    };
    return m[ext.toLowerCase()] || null;
}

// Suppress console noise in production
function logging_warn(...args) { console.warn('[FluxDrop]', ...args); }


// Active downloads map: path → dl state object
// Declared here so downloadFile, renderDownloadTray, resumeDownload,
// cancelDownload, and downloadFolderZip can all share it.
const activeDownloads = new Map();

// Mint a download token from the server.
// Used by downloadFile, previewFile, and the archive-tree preview.
async function mintDownloadToken(path) {
    const data = await apiCall('/api/v1/download_token', 'POST', { path });
    return data; // { download_token, path, expires_in, total_size, bytes_confirmed }
}

// Render (or update) the floating download tray.
// Uses stable DOM patching: container and rows are created once;
// subsequent calls only update text/bar values so buttons are never
// re-created mid-click.
function renderDownloadTray() {
    let tray = document.getElementById('dl-tray');
    if (!tray) {
        tray = document.createElement('div');
        tray.id = 'dl-tray';
        tray.style.cssText = `
            position:fixed; bottom:0; right:1rem; width:340px; max-height:60vh;
            overflow-y:auto; background:#1e293b; border-radius:12px 12px 0 0;
            box-shadow:0 -4px 24px rgba(0,0,0,0.4); z-index:9000;
            font-family:Inter,sans-serif; font-size:13px; color:#e2e8f0;
        `;
        document.body.appendChild(tray);
        tray.classList.add('fd-tray-in');
        tray.addEventListener('animationend', () => tray.classList.remove('fd-tray-in'), { once: true });
    }

    if (activeDownloads.size === 0) {
        // Auto-hide (all downloads finished/cleared) gets the same slide-out
        // as the manual ✕ button, instead of an instant innerHTML wipe.
        if (tray.innerHTML.trim() !== '') {
            window.fdCollapseTray(tray).then(() => {
                // A new download may have started while this was animating —
                // only actually clear if the tray is still meant to be empty.
                if (activeDownloads.size === 0) tray.innerHTML = '';
            });
        }
        return;
    }
    // A new download can start mid auto-hide-animation (see above) — cancel
    // any pending collapse so the tray doesn't fade out from under the rows
    // we're about to (re)populate below.
    tray.classList.remove('fd-tray-closing');

    // Header (created once)
    let header = tray.querySelector('.dl-tray-header');
    if (!header) {
        header = document.createElement('div');
        header.className = 'dl-tray-header';
        header.style.cssText = 'padding:10px 14px 6px;font-weight:700;font-size:14px;' +
            'border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;';
        header.innerHTML = `<span class="dl-count"></span>` +
            `<span style="cursor:pointer;opacity:.6" id="dl-tray-close">✕</span>`;
        tray.prepend(header);
        header.querySelector('#dl-tray-close').addEventListener('click', async () => {
            await window.fdCollapseTray(tray);
            tray.innerHTML = '';
        });
    }
    header.querySelector('.dl-count').textContent = `📥 Downloads (${activeDownloads.size})`;

    // Remove rows for entries no longer in the map
    tray.querySelectorAll('.dl-row').forEach(row => {
        if (!activeDownloads.has(row.dataset.dlPath)) row.remove();
    });

    for (const [path, dl] of activeDownloads) {
        const pct   = dl.totalSize ? Math.round(dl.bytesReceived / dl.totalSize * 100) : 0;
        const recv  = formatBytes(dl.bytesReceived);
        const total = dl.totalSize ? formatBytes(dl.totalSize) : '?';
        const name  = dl.filename || path.split('/').pop();

        // Escape path for use as a CSS attribute selector value
        const safePathAttr = path.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

        let row = tray.querySelector(`.dl-row[data-dl-path="${CSS.escape(path)}"]`);
        if (!row) {
            row = document.createElement('div');
            row.className = 'dl-row';
            row.dataset.dlPath = path;
            row.style.cssText = 'padding:10px 14px;border-bottom:1px solid #1e293b';
            row.innerHTML = `
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="dl-name" title="${escapeHtml(name)}"
                        style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px"></span>
                    <span class="dl-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="dl-bar"
                        style="background:#3b82f6;height:6px;border-radius:4px;width:0%;transition:width .3s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="dl-status" style="color:#64748b"></span>
                    <div class="dl-actions"></div>
                </div>`;
            tray.appendChild(row);
            // Auto-scroll so newest entry is visible
            requestAnimationFrame(() => { tray.scrollTop = tray.scrollHeight; });

            // Build stable button references stored on the row element
            const actionsDiv = row.querySelector('.dl-actions');

            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = t('cancel');
            cancelBtn.style.cssText = 'background:#ef4444;color:#fff;border:none;border-radius:5px;' +
                'padding:2px 8px;cursor:pointer;font-size:11px';
            cancelBtn.addEventListener('click', () => cancelDownload(path));

            const resumeBtn = document.createElement('button');
            resumeBtn.textContent = t('dl_resume');
            resumeBtn.style.cssText = 'background:#3b82f6;color:#fff;border:none;border-radius:5px;' +
                'padding:2px 8px;cursor:pointer;font-size:11px';
            resumeBtn.addEventListener('click', () => resumeDownload(encodeURIComponent(path)));

            const abortBtn = document.createElement('button');
            abortBtn.textContent = t('cancel');
            abortBtn.style.cssText = 'background:#64748b;color:#fff;border:none;border-radius:5px;' +
                'padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px';
            abortBtn.addEventListener('click', () => cancelDownload(path));

            const dismissBtn = document.createElement('button');
            dismissBtn.textContent = t('dl_dismiss');
            dismissBtn.style.cssText = 'background:#64748b;color:#fff;border:none;border-radius:5px;' +
                'padding:2px 8px;cursor:pointer;font-size:11px';
            dismissBtn.addEventListener('click', () => {
                activeDownloads.delete(path);
                renderDownloadTray();
            });

            row._btns = { cancelBtn, resumeBtn, abortBtn, dismissBtn, actionsDiv };
        }

        // Update dynamic fields
        const statusIcon = { downloading:'⬇', paused:'⏸', error:'⚠', done:'✅', cancelled:'🚫' };
        row.querySelector('.dl-name').textContent = (statusIcon[dl.status] || '') + ' ' + name;
        row.querySelector('.dl-bytes').textContent = `${recv} / ${total}`;
        const _dlBar = row.querySelector('.dl-bar');
        _dlBar.style.width      = pct + '%';
        _dlBar.style.background = dl._retrying ? '#f59e0b' : '#3b82f6';
        _dlBar.style.animation  = dl._retrying ? 'fd-retry-pulse 1s ease-in-out infinite' : '';

        // Status line
        let statusText = dl.status;
        if (dl.status === 'downloading') {
            const parts = [];
            if (dl.speed != null) parts.push(formatSpeed(dl.speed));
            if (dl.eta   != null) parts.push('ETA ' + formatEta(dl.eta));
            if (parts.length) {
                statusText = parts.join(' · ');
            } else if (dl._retrying && dl.error) {
                statusText = '🔄 ' + dl.error; // live retry countdown
            } else if (dl._mode === 'native') {
                // Both ZIP and regular files in native mode — browser owns the download
                statusText = 'Downloading via browser\u2026';
            } else if (dl._isZip && !dl._dlUrl) {
                // Polling: show scan progress if available
                const sp = dl._scanProgress;
                const hint = sp && sp.total
                    ? ` (${sp.prog}/${sp.total} files)`
                    : '';
                statusText = (dl._needsHashing
                    ? 'Hashing files on demand\u2026'
                    : 'Building archive\u2026') + hint;
            } else {
                statusText = '';
            }
        } else if (dl.status === 'error') {
            statusText = '\u26a0 ' + (dl.error || 'failed');
        } else if (dl.status === 'cancelled') {
            statusText = dl.error || 'Cancelled';
        } else if (dl.status === 'paused') {
            statusText = 'Paused';
        }
        row.querySelector('.dl-status').textContent = statusText;

        // Swap visible buttons without re-creating them
        const { actionsDiv, cancelBtn, resumeBtn, abortBtn, dismissBtn } = row._btns;
        actionsDiv.innerHTML = '';
        if (dl.status === 'downloading') {
            actionsDiv.appendChild(cancelBtn);
        } else if (dl.status === 'paused' || dl.status === 'error') {
            actionsDiv.appendChild(resumeBtn);
            actionsDiv.appendChild(abortBtn);
        } else if (dl.status === 'cancelled') {
            // Cancelled = browser dropped it; Resume will restart from scratch
            actionsDiv.appendChild(resumeBtn);
            actionsDiv.appendChild(dismissBtn);
        } else if (dl.status === 'done') {
            actionsDiv.appendChild(dismissBtn);
        }
    }
}

        // ======================================================================
        // --- MEDIA PREVIEW ---
        // ======================================================================
const EXT_IMAGE   = new Set(['jpg','jpeg','png','gif','webp','bmp','svg','ico','avif','tiff','tif']);
const EXT_IMAGE_HEIC = new Set(['heic','heif']);  // decoded client-side via heic2any
const EXT_VIDEO   = new Set(['mp4','webm','ogg','ogv','mov','m4v','mkv','avi']);
const EXT_AUDIO   = new Set(['mp3','wav','flac','aac','ogg','oga','m4a','opus','weba']);
const EXT_TEXT    = new Set(['txt','js','ts','jsx','tsx','py','sh','bash','json','xml','yaml','yml','toml','ini','cfg','conf','html','htm','css','scss','less','csv','log','env','rs','go','c','cpp','h','java','rb','php','swift','kt','sql','r','lua']);
const EXT_MARKDOWN = new Set(['md','markdown','mdown','mkd']);
const EXT_ARCHIVE  = new Set(['zip','tar','gz','tgz','bz2','tbz2','xz','txz','7z','rar','zst','lz4','lzma','cab','iso','dmg','pkg','deb','rpm']);
const EXT_PDF      = new Set(['pdf']);

function fileCategory(path) {
    const ext = (path.split('.').pop() || '').toLowerCase();
    if (EXT_IMAGE.has(ext))      return 'image';
    if (EXT_IMAGE_HEIC.has(ext)) return 'heic';
    if (EXT_VIDEO.has(ext))      return 'video';
    if (EXT_AUDIO.has(ext))      return 'audio';
    if (EXT_MARKDOWN.has(ext))   return 'markdown';
    if (EXT_PDF.has(ext))        return 'pdf';
    if (EXT_TEXT.has(ext))       return 'text';
    if (EXT_ARCHIVE.has(ext))    return 'archive';
    return 'binary';
}

// Load heic2any lazily (only when a HEIC file is previewed)
let _heic2anyLoaded = false;
function _loadHeic2any() {
    if (_heic2anyLoaded) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = '/fluxdrop_pp/assets/heic2any.min.js';
        s.onload  = () => { _heic2anyLoaded = true; resolve(); };
        s.onerror = () => reject(new Error('Failed to load heic2any'));
        document.head.appendChild(s);
    });
}

// Load JSZip lazily (only when a ZIP file is previewed)
let _jszipLoaded = false;
function _loadJSZip() {
    if (_jszipLoaded) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = '/fluxdrop_pp/assets/jszip.min.js';
        s.onload  = () => { _jszipLoaded = true; resolve(); };
        s.onerror = () => reject(new Error('Failed to load JSZip'));
        document.head.appendChild(s);
    });
}

// Load js-untar lazily (for .tar / .tar.gz / .tgz / .bz2 files)
let _untarLoaded = false;
function _loadUntar() {
    if (_untarLoaded) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = '/fluxdrop_pp/assets/untar.min.js';
        s.onload  = () => { _untarLoaded = true; resolve(); };
        s.onerror = () => reject(new Error('Failed to load js-untar'));
        document.head.appendChild(s);
    });
}

// Load marked.js lazily (only when a Markdown file is previewed)
let _markedLoaded = false;
function _loadMarked() {
    if (_markedLoaded) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = '/fluxdrop_pp/assets/marked.min.js';
        s.onload  = () => { _markedLoaded = true; resolve(); };
        s.onerror = () => reject(new Error('Failed to load marked.js'));
        document.head.appendChild(s);
    });
}

// Core Markdown parse+sanitize step, shared by both consumers:
//   - _renderMarkdown() below (file preview — dark theme, its own container)
//   - showPolicyModal() / _showPolicyAgreementModal() (policy docs — light
//     theme, rendered straight into #pm-body / #pam-body)
// Kept free of any bodyEl/theme coupling so callers can wrap the returned
// HTML string however their modal is themed.
// - Uses marked for parsing (GFM: tables, fenced code, strikethrough, task lists)
// - Sanitises every HTML tag that marked emits using a strict allowlist so
//   user-uploaded .md files cannot inject scripts even without a CSP.
function _mdParseAndSanitize(rawText) {
    // Pre-process: join soft-wrapped lines (single bare \n between two
    // non-empty, non-block lines) into a single space so that editors
    // that hard-wrap prose at column 80 don't produce staircase <br>s.
    //
    // A line is considered a "block starter" if it begins a Markdown
    // structural element: heading (#), fence (``` or ~~~), blockquote (>),
    // thematic break (--- / *** / ___), HTML tag, or a list item (-, *, +,
    // digit+dot).  Blank lines are preserved as paragraph separators.
    // Lines that begin a Markdown block element — never soft-join with adjacent lines.
    // '|' is included so GFM table rows are never merged, which would collapse
    // the pipe-delimited columns and break table parsing entirely.
    const BLOCK_START = /^(\s{0,3})(#{1,6}\s|```|~~~|>|[-*_]{3,}[ \t]*$|<\/?[a-zA-Z]|[-*+]\s|\d+[.)]\s|\|)/;

    // Subset of BLOCK_START that supports CommonMark "lazy continuation" —
    // list items and blockquotes can have follow-up lines with no marker of
    // their own that still belong to the same item/quote. Headings, hr,
    // fences, tables and raw HTML do NOT: those are always single-line
    // starters, so a following line always begins a new block.
    //
    // Without this distinction, a line like "- ***Some text" that opens a
    // list item was correctly refused a join with its own next line (since
    // it matches BLOCK_START), but the loop would then join THAT next line
    // onto the line after it instead — leaving the list item's first line
    // dangling and turning its continuation into a stray, un-indented
    // paragraph outside the list (visible as broken bold/italic spanning
    // list items in the file preview).
    const LAZY_CONTINUABLE_START = /^(\s{0,3})(>|[-*+]\s|\d+[.)]\s)/;

    const lines  = rawText.split('\n');
    const joined = [];
    let _inFence = false; // true while inside a fenced code block (``` or ~~~)
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const next = lines[i + 1];
        // Toggle fence state on opening/closing ``` or ~~~ markers.
        // Must be checked BEFORE deciding whether to join, because the
        // fence line itself should still act as a block boundary.
        if (/^\s{0,3}(`{3,}|~{3,})/.test(line)) _inFence = !_inFence;
        joined.push(line);
        // If this line and the next are both non-empty, non-block lines,
        // and they are separated by exactly one newline (soft wrap),
        // replace the newline with a space so that editors that hard-wrap
        // prose at column 80 don't produce staircase <br>s.
        //
        // NEVER join lines inside a fenced code block — line breaks are
        // significant in source code and collapsing them corrupts the output.
        if (
            !_inFence &&
            line.trim() !== '' &&
            next !== undefined && next.trim() !== '' &&
            (!BLOCK_START.test(line) || LAZY_CONTINUABLE_START.test(line)) &&
            !BLOCK_START.test(next) &&
            // Preserve two-space hard break (CommonMark spec)
            !line.endsWith('  ') &&
            !line.endsWith('\\')
        ) {
            // Merge: set the next slot to the joined string and blank this
            // slot so the join('\n') produces no extra newline here.
            lines[i + 1] = line + ' ' + next;
            joined[joined.length - 1] = ''; // this slot becomes blank
        }
    }
    const processedText = joined.join('\n');

    marked.use({ gfm: true, breaks: false });  // spec-correct: bare \n = space
    const rawHtml = marked.parse(processedText);

    // Allowlist sanitiser — strips any tag/attr not on the list.
    const ALLOWED_TAGS = new Set([
        'p','br','hr','h1','h2','h3','h4','h5','h6',
        'strong','em','del','code','pre','blockquote',
        'ul','ol','li','table','thead','tbody','tr','th','td',
        'a','img','input',
    ]);
    const ALLOWED_ATTRS = {
        'a':     new Set(['href','title']),
        'img':   new Set(['src','alt','title','width','height']),
        'input': new Set(['type','checked','disabled']),
        'th':    new Set(['align']),
        'td':    new Set(['align']),
        'code':  new Set(['class']),
        'pre':   new Set(['class']),
    };
    const SAFE_HREF = /^(https?:|mailto:|#|\/)/i;

    const tmp = document.createElement('div');
    tmp.innerHTML = rawHtml;

    function sanitise(node) {
        if (node.nodeType === Node.TEXT_NODE) return;
        if (node.nodeType !== Node.ELEMENT_NODE) { node.remove(); return; }
        const tag = node.tagName.toLowerCase();
        if (!ALLOWED_TAGS.has(tag)) { node.replaceWith(...node.childNodes); return; }
        const allowed = ALLOWED_ATTRS[tag] || new Set();
        for (const attr of [...node.attributes]) {
            if (!allowed.has(attr.name)) { node.removeAttribute(attr.name); continue; }
            if ((attr.name === 'href' || attr.name === 'src') && !SAFE_HREF.test(attr.value)) {
                node.removeAttribute(attr.name);
            }
        }
        if (tag === 'a') { node.setAttribute('target','_blank'); node.setAttribute('rel','noopener noreferrer'); }
        if (tag === 'input') node.setAttribute('disabled', '');
        node.childNodes.forEach(sanitise);
    }
    tmp.childNodes.forEach(sanitise);

    return tmp.innerHTML;
}

// Render Markdown text safely into bodyEl (file preview — dark theme).
function _renderMarkdown(bodyEl, rawText) {
    bodyEl.classList.add('fd-md-body');
    bodyEl.innerHTML = '';
    const container = document.createElement('div');
    container.className = 'md-preview';
    // Rendered document body — a user's own file (or a legal doc, which has its
    // own per-language versions). The i18n layer must never machine-swap phrases
    // in here just because they happen to match a UI string. See _translateSubtree.
    container.setAttribute('data-fd-notranslate', '');
    container.style.cssText = 'color:#e2e8f0;font-size:15px;line-height:1.75;padding:1.25rem 1.5rem;overflow-y:auto;max-height:70vh';
    container.innerHTML = _mdParseAndSanitize(rawText);

    if (!document.getElementById('md-preview-style')) {
        const st = document.createElement('style');
        st.id = 'md-preview-style';
        st.textContent = `
            .md-preview h1,.md-preview h2,.md-preview h3,
            .md-preview h4,.md-preview h5,.md-preview h6 {
                color:#93c5fd;font-weight:700;margin:1.25em 0 .5em;
                border-bottom:1px solid rgba(148,163,184,.2);padding-bottom:.25em }
            .md-preview h1{font-size:1.6em} .md-preview h2{font-size:1.35em}
            .md-preview h3{font-size:1.15em}
            .md-preview p{margin:.6em 0}
            .md-preview a{color:#60a5fa;text-decoration:underline}
            .md-preview a:hover{color:#93c5fd}
            .md-preview strong{color:#f1f5f9;font-weight:700}
            .md-preview em{color:#cbd5e1;font-style:italic}
            .md-preview del{color:#64748b}
            .md-preview code{background:#1e293b;color:#7dd3fc;padding:1px 5px;
                border-radius:4px;font-family:ui-monospace,monospace;font-size:13px}
            .md-preview pre{background:#0f172a;border:1px solid #1e293b;border-radius:8px;
                padding:1rem;overflow-x:auto;margin:.75em 0}
            .md-preview pre code{background:none;padding:0;color:#e2e8f0;font-size:13px}
            .md-preview blockquote{border-left:3px solid #3b82f6;margin:.75em 0;
                padding:.4em .75em .4em 1rem;background:rgba(59,130,246,.08);border-radius:0 6px 6px 0}
            .md-preview blockquote p{margin:0;color:#94a3b8}
            .md-preview hr{border:none;border-top:1px solid #334155;margin:1.25em 0}
            .md-preview ul,.md-preview ol{padding-left:1.5em;margin:.5em 0}
            .md-preview li{margin:.2em 0}
            .md-preview li input[type=checkbox]{margin-right:.4em;accent-color:#3b82f6}
            .md-preview table{border-collapse:collapse;width:100%;margin:.75em 0;font-size:14px}
            .md-preview th,.md-preview td{border:1px solid #334155;padding:6px 12px;text-align:left}
            .md-preview th{background:#1e293b;color:#93c5fd;font-weight:600}
            .md-preview tr:nth-child(even) td{background:rgba(255,255,255,.03)}
            .md-preview img{max-width:100%;border-radius:6px;margin:.5em 0}
        `;
        document.head.appendChild(st);
    }
    bodyEl.appendChild(container);
}

// Holds the AbortController for any in-flight preview fetch so we can
// cancel it when the modal is closed before the response arrives.
let _previewAbortCtrl = null;

// Stream a Response into a Blob while showing a progress bar inside bodyEl.
// Falls back to resp.blob() if Content-Length is absent.
async function _fetchBlobWithProgress(resp, signal, bodyEl) {
    const contentLength = resp.headers.get('Content-Length');
    const total = contentLength ? parseInt(contentLength) : 0;

    if (!total || !resp.body) return resp.blob();

    const barId = 'fd-preview-progress-' + Date.now();
    bodyEl.innerHTML = `
        <div style="width:100%;max-width:700px;margin:0 auto">
            <div style="width:100%;aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite;margin-bottom:12px"></div>
            <div style="background:#334155;border-radius:4px;height:5px;overflow:hidden">
                <div id="${barId}" style="height:100%;border-radius:4px;background:#3b82f6;width:0%;transition:width .15s"></div>
            </div>
            <div id="${barId}-label" style="text-align:center;font-size:12px;color:#64748b;margin-top:6px">0%</div>
        </div>`;

    const reader = resp.body.getReader();
    const chunks = [];
    let received = 0;

    while (true) {
        const { done, value } = await reader.read();
        if (signal && signal.aborted) throw new DOMException('Aborted', 'AbortError');
        if (done) break;
        chunks.push(value);
        received += value.byteLength;
        const pct = Math.min(100, Math.round(received / total * 100));
        const bar = document.getElementById(barId);
        const lbl = document.getElementById(barId + '-label');
        if (bar) bar.style.width = pct + '%';
        if (lbl) lbl.textContent = pct + '%  (' + formatBytes(received) + ' / ' + formatBytes(total) + ')';
    }

    const merged = new Uint8Array(received);
    let offset = 0;
    for (const c of chunks) { merged.set(c, offset); offset += c.byteLength; }
    return new Blob([merged], { type: resp.headers.get('Content-Type') || 'application/octet-stream' });
}

// Preview a trashed file by streaming it directly from the trash endpoint.
// This bypasses the normal download-token flow because trashed files live
// outside the user's regular file tree.
async function _previewTrashFile(trashId, filename) {
    // Cancel any previous in-flight preview fetch.
    if (_previewAbortCtrl) { _previewAbortCtrl.abort(); }
    _previewAbortCtrl = new AbortController();
    const _previewSignal = _previewAbortCtrl.signal;

    const modal  = document.getElementById('preview-modal');
    const titleEl = document.getElementById('preview-title');
    const bodyEl  = document.getElementById('preview-body');
    const dlBtn   = document.getElementById('preview-download-btn');

    titleEl.textContent = filename;
    bodyEl.innerHTML = '<p style="color:#64748b;padding:2rem;text-align:center">Loading…</p>';
    dlBtn.style.display = 'none';
    modal.classList.remove('hidden');

    const streamUrl = `${API_BASE_URL}/api/v1/trash/${trashId}/file`;

    try {
        const cat = fileCategory(filename);

        // For image / pdf / text / markdown — fetch as blob then render.
        if (['image','heic','pdf','text','markdown','audio','video'].includes(cat)) {
            const resp = await fetchWithFallback(streamUrl, {
                signal: _previewSignal,
                headers: authToken ? { Authorization: `Bearer ${authToken}` } : {}
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            // Show shimmer while blob downloads
            bodyEl.innerHTML = `<div style="width:100%;max-width:700px;margin:0 auto;
                aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`;
            const blob    = await resp.blob();
            if (_previewSignal.aborted) { URL.revokeObjectURL(URL.createObjectURL(blob)); return; }
            const blobUrl = URL.createObjectURL(blob);

            const revokeOnClose = () => { URL.revokeObjectURL(blobUrl); };

            if (cat === 'image' || cat === 'heic') {
                bodyEl.innerHTML = `<img src="${blobUrl}" alt="${escapeHtml(filename)}"
                    style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;
            } else if (cat === 'video') {
                bodyEl.innerHTML = `<video controls autoplay style="max-width:100%;max-height:70vh;
                    border-radius:8px;display:block;margin:0 auto;background:#000">
                    <source src="${blobUrl}">Your browser doesn't support this video format.</video>`;
            } else if (cat === 'audio') {
                bodyEl.innerHTML = `<div style="padding:2rem 1rem;text-align:center">
                    <div style="font-size:4rem;margin-bottom:1rem">🎵</div>
                    <div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${escapeHtml(filename)}</div>
                    <audio controls autoplay style="width:100%"><source src="${blobUrl}"></audio></div>`;
            } else if (cat === 'pdf') {
                bodyEl.innerHTML = `<iframe src="${blobUrl}"
                    style="width:100%;height:65vh;border:none;border-radius:8px;background:#fff"
                    title="${escapeHtml(filename)}"></iframe>`;
            } else {
                // text / markdown — read as text
                const text = await blob.text();
                if (cat === 'markdown') {
                    await _loadMarked();
                    _renderMarkdown(bodyEl, text);
                } else {
                    const ext = (filename.split('.').pop() || '').toLowerCase();
                    bodyEl.innerHTML = `<pre class="lang-${ext}">${escapeHtml(text.slice(0, 50000))}${text.length > 50000 ? '\n\n… (truncated)' : ''}</pre>`;
                }
            }

            // Revoke blob URL when preview is closed.
            const _origClose = window.closePreview;
            window.closePreview = function() { revokeOnClose(); window.closePreview = _origClose; _origClose(); };
            dlBtn.style.display = 'none'; // can't easily download from trash; use Restore first
        } else {
            bodyEl.innerHTML = `<div style="padding:3rem 1rem;text-align:center">
                <div style="font-size:3.5rem;margin-bottom:1rem">📄</div>
                <div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(filename)}</div>
                <p style="color:#64748b;font-size:14px">No preview available. Restore the file to download it.</p>
            </div>`;
        }
    } catch (err) {
        if (err.name === 'AbortError') return;
        bodyEl.innerHTML = `<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(err))}</p>`;
    }
}

window.closePreview = function() {
    const modal = document.getElementById('preview-modal');
    if (modal.classList.contains('hidden') || modal.dataset.fdClosing) return;
    // Cancel any in-progress background fetch (text, markdown, HEIC, etc.)
    if (_previewAbortCtrl) { _previewAbortCtrl.abort(); _previewAbortCtrl = null; }

    modal.dataset.fdClosing = '1';
    modal.classList.add('fd-overlay-closing');
    const content = modal.querySelector('.preview-modal-content');
    if (content) content.classList.add('fd-panel-closing');

    let done = false;
    const finish = () => {
        if (done) return;
        done = true;
        modal.classList.remove('fd-overlay-closing');
        if (content) content.classList.remove('fd-panel-closing');
        delete modal.dataset.fdClosing;
        modal.classList.add('hidden');

        const body = document.getElementById('preview-body');
        // Properly tear down media elements before clearing innerHTML.
        // Setting el.src = '' resolves to the current page URL, causing Firefox
        // to attempt to load the HTML page as a media resource and log
        // 'HTTP Content-Type of text/html is not supported' warnings.
        // The correct teardown is: pause → remove <source> children →
        // removeAttribute('src') → call load() to reset internal state.
        body.querySelectorAll('video,audio').forEach(el => {
            el.pause();
            Array.from(el.querySelectorAll('source')).forEach(s => s.remove());
            el.removeAttribute('src');
            el.load();   // resets the media element's network state to NETWORK_EMPTY
        });
        body.innerHTML = '';
        document.getElementById('preview-download-btn').style.display = 'none';
    };
    modal.addEventListener('animationend', finish, { once: true });
    setTimeout(finish, 200); // safety net if animationend doesn't fire
};

// Render a read-only archive file tree inside the preview body element.
// entries: array of { name, size, isDir }  (normalised by each format handler)
function _renderArchiveTree(bodyEl, entries, archiveName) {
    if (!entries.length) {
        bodyEl.innerHTML = `<div style="padding:2rem;text-align:center;color:#94a3b8">${t('archive_empty')}</div>`;
        return;
    }

    // Build a tree structure from flat paths.
    // children uses Object.create(null) rather than {} — archive entry names
    // are attacker/uploader controlled, and a folder literally named
    // "__proto__" would otherwise hit Object.prototype's accessor instead of
    // creating a real property, silently dropping that folder (and anything
    // nested under it) from the rendered tree instead of listing it.
    function buildTree(entries) {
        const root = { children: Object.create(null), files: [] };
        for (const e of entries) {
            const parts = e.name.replace(/\\/g, '/').replace(/\/$/, '').split('/');
            if (e.isDir || parts.length > 1) {
                // directory node — walk/create path
                let node = root;
                const dirParts = e.isDir ? parts : parts.slice(0, -1);
                for (const part of dirParts) {
                    if (!node.children[part]) node.children[part] = { children: Object.create(null), files: [] };
                    node = node.children[part];
                }
                if (!e.isDir) node.files.push({ name: parts[parts.length - 1], size: e.size });
            } else {
                root.files.push({ name: e.name, size: e.size });
            }
        }
        return root;
    }

    function renderNode(node, depth) {
        let html = '';
        const pad = depth * 16;
        // Directories first
        for (const [name, child] of Object.entries(node.children).sort(([a],[b]) => a.localeCompare(b))) {
            html += `<div style="display:flex;align-items:center;gap:6px;padding:3px 8px 3px ${8+pad}px;
                         border-radius:5px;cursor:default" class="arc-dir-row"
                         onmouseenter="this.style.background='rgba(255,255,255,.05)'"
                         onmouseleave="this.style.background=''">
                <span style="font-size:13px;flex-shrink:0">📁</span>
                <span style="font-size:13px;color:#93c5fd;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(name)}</span>
            </div>
            ${renderNode(child, depth + 1)}`;
        }
        // Files
        for (const f of node.files.sort((a,b) => a.name.localeCompare(b.name))) {
            const sz = f.size != null ? `<span style="font-size:11px;color:#64748b;flex-shrink:0;margin-left:auto;padding-left:8px">${formatBytes(f.size)}</span>` : '';
            html += `<div style="display:flex;align-items:center;gap:6px;padding:3px 8px 3px ${8+pad}px;
                         border-radius:5px;cursor:default"
                         onmouseenter="this.style.background='rgba(255,255,255,.05)'"
                         onmouseleave="this.style.background=''">
                <span style="font-size:13px;flex-shrink:0">📄</span>
                <span style="font-size:13px;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(f.name)}</span>
                ${sz}
            </div>`;
        }
        return html;
    }

    const tree = buildTree(entries);
    const totalFiles = entries.filter(e => !e.isDir).length;
    const totalDirs  = entries.filter(e => e.isDir).length;

    bodyEl.innerHTML = `
        <div style="padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.08);
                    display:flex;align-items:center;justify-content:space-between">
            <span style="font-size:12px;color:#94a3b8">
                ${totalFiles} file${totalFiles!==1?'s':''} · ${totalDirs} folder${totalDirs!==1?'s':''}
            </span>
            <span style="font-size:11px;color:#475569">read-only preview</span>
        </div>
        <div style="overflow:auto;max-height:60vh;padding:6px 4px;font-family:ui-monospace,monospace">
            ${renderNode(tree, 0)}
        </div>`;
}

window.previewFile = async function(path) {
    // Cancel any previous in-flight preview fetch before starting a new one.
    if (_previewAbortCtrl) { _previewAbortCtrl.abort(); }
    _previewAbortCtrl = new AbortController();
    const _previewSignal = _previewAbortCtrl.signal;

    const filename = path.split('/').pop();
    const cat = fileCategory(path);
    const modal = document.getElementById('preview-modal');
    const titleEl = document.getElementById('preview-title');
    const bodyEl = document.getElementById('preview-body');
    const dlBtn = document.getElementById('preview-download-btn');

    titleEl.textContent = filename;
    bodyEl.innerHTML = '<p style="color:#64748b;padding:2rem;text-align:center">Connecting…</p>';
    dlBtn.style.display = 'none';
    modal.classList.remove('hidden');

    try {
        const tokenData = await mintDownloadToken(path);
        const urlPath = `/api/v1/download${encodePath(path)}`;
        const dlUrl = `${API_BASE_URL}${urlPath}?dl_token=${encodeURIComponent(tokenData.download_token)}`;

        if (cat === 'image') {
            // Show shimmer placeholder while fetching
            bodyEl.innerHTML = `<div style="width:100%;max-width:700px;margin:0 auto;
                aspect-ratio:16/10;border-radius:8px;
                background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);
                background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></div>`;
            // Fetch as blob so the AbortController can cancel mid-download.
            bodyEl.innerHTML = '<p style="color:#64748b;padding:2rem;text-align:center">Fetching an image…</p>';
            const imgResp = await fetchWithFallback(dlUrl, {
                signal: _previewSignal,
                ...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {})
            });
            if (!imgResp.ok) throw new Error(`HTTP ${imgResp.status}`);
            const imgBlob = await _fetchBlobWithProgress(imgResp, _previewSignal, bodyEl);
            const imgUrl  = URL.createObjectURL(imgBlob);
            // If modal was closed while we were fetching, discard the blob silently.
            if (_previewSignal.aborted) { URL.revokeObjectURL(imgUrl); return; }
            bodyEl.innerHTML = `<img src="${imgUrl}" alt="${escapeHtml(filename)}"
                style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;
            // Revoke the object URL when the preview is closed.
            const _origClose = window.closePreview;
            window.closePreview = function() { URL.revokeObjectURL(imgUrl); window.closePreview = _origClose; _origClose(); };
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'heic') {
            bodyEl.innerHTML = '<p style="color:#94a3b8;padding:2rem;text-align:center">Decoding HEIC…</p>';
            await _loadHeic2any();
            const resp = await fetchWithFallback(dlUrl, { signal: _previewSignal, ...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {}) });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const blob = await resp.blob();
            // heic2any converts to JPEG blob (or PNG if toType specified)
            const jpegBlob = await heic2any({ blob, toType: 'image/jpeg', quality: 0.85 });
            const objUrl = URL.createObjectURL(jpegBlob);
            bodyEl.innerHTML = `<img src="${objUrl}" alt="${escapeHtml(filename)}"
                style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;
            // Revoke when preview is closed
            const origClose = window.closePreview;
            window.closePreview = function() { URL.revokeObjectURL(objUrl); window.closePreview = origClose; origClose(); };
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'video') {
            bodyEl.innerHTML = `<video controls autoplay style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto;background:#000"><source src="${dlUrl}">Your browser doesn't support this video format.</video>`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'audio') {
            bodyEl.innerHTML = `<div style="padding:2rem 1rem;text-align:center"><div style="font-size:4rem;margin-bottom:1rem">🎵</div><div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${escapeHtml(filename)}</div><audio controls autoplay style="width:100%"><source src="${dlUrl}">Your browser doesn't support audio playback.</audio></div>`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'markdown') {
            bodyEl.innerHTML = '<p style="color:#94a3b8;padding:2rem;text-align:center">Rendering…</p>';
            await _loadMarked();
            const resp = await fetchWithFallback(dlUrl, { signal: _previewSignal, ...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {}) });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();
            _renderMarkdown(bodyEl, text);
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'text') {
            const resp = await fetchWithFallback(dlUrl, { signal: _previewSignal, ...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {}) });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();
            const ext = (path.split('.').pop() || '').toLowerCase();
            bodyEl.innerHTML = `<pre class="lang-${ext}">${escapeHtml(text.slice(0, 50000))}${text.length > 50000 ? '\n\n… (truncated)' : ''}</pre>`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'pdf') {
            bodyEl.innerHTML = '<p style="color:#64748b;padding:2rem;text-align:center">Fetching a PDF…</p>';
            const pdfResp = await fetchWithFallback(dlUrl, {
                signal: _previewSignal,
                ...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {})
            });
            if (!pdfResp.ok) throw new Error(`HTTP ${pdfResp.status}`);
            // Force the MIME type to application/pdf regardless of what the
            // server sent — without this the blob defaults to octet-stream
            // and both Firefox and Chrome refuse to render it in an iframe.
            const pdfBlobRaw = await pdfResp.blob();
            if (_previewSignal.aborted) { return; }   // nothing to revoke yet
            const pdfBlob    = new Blob([pdfBlobRaw], { type: 'application/pdf' });
            const pdfBlobUrl = URL.createObjectURL(pdfBlob);
            // blob: URLs are same-origin to the page — X-Frame-Options does not apply.
            bodyEl.innerHTML = `<iframe
                src="${pdfBlobUrl}"
                style="width:100%;height:65vh;border:none;border-radius:8px;background:#fff"
                title="${escapeHtml(filename)}">
                <p style="color:#94a3b8;padding:2rem;text-align:center">
                    Your browser cannot display PDFs inline.
                </p>
            </iframe>`;
            // Revoke the blob URL when the preview is closed.
            const _origClosePdf = window.closePreview;
            window.closePreview = function() {
                URL.revokeObjectURL(pdfBlobUrl);
                window.closePreview = _origClosePdf;
                _origClosePdf();
            };
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };

        } else if (cat === 'archive') {
            const ext = (path.split('.').pop() || '').toLowerCase();
            bodyEl.innerHTML = '<p style="color:#94a3b8;padding:2rem;text-align:center">Reading archive…</p>';

            const isZip = ext === 'zip';
            const isTar = ['tar', 'gz', 'tgz'].includes(ext);
            const noPreview = ['bz2','tbz2','xz','txz','7z','rar','zst','lz4','lzma','cab','iso','dmg','pkg','deb','rpm'].includes(ext);

            const FORMAT_NAMES = {
                bz2:'bzip2', tbz2:'bzip2 tar', xz:'XZ', txz:'XZ tar',
                '7z':'7-Zip', rar:'RAR', zst:'Zstandard', lz4:'LZ4',
                lzma:'LZMA', cab:'Windows Cabinet', iso:'Disc Image',
                dmg:'macOS Disk Image', pkg:'Package', deb:'Debian Package',
                rpm:'RPM Package',
            };
            if (noPreview) {
                const fmtName = FORMAT_NAMES[ext] || ('.' + ext.toUpperCase());
                bodyEl.innerHTML = `<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">🗜</div>
                    <div style="color:#94a3b8;font-weight:600;margin-bottom:4px">${escapeHtml(filename)}</div>
                    <div style="color:#64748b;font-size:12px;margin-bottom:12px">${fmtName} archive</div>
                    <p style="color:#64748b;font-size:14px">
                        In-browser preview is not available for this format.<br>
                        Download the file and extract it locally.
                    </p></div>`;
                dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };
            } else if (isZip || isTar) {
                // Use the server-side archive_tree endpoint — reads only the central
                // directory / tar headers, never the compressed file data.
                // This is O(entry-count) rather than O(file-size).
                try {
                    // tokenData was already minted at the top of previewFile() for
                    // every category (used there to build dlUrl) — reuse it instead
                    // of minting a second, redundant token just for this branch.
                    const dlToken = tokenData.download_token;

                    const encodedPath = path.split('/').map(encodeURIComponent).join('/');
                    const treeUrl = `${API_BASE_URL}/api/v1/archive_tree${encodedPath}?dl_token=${encodeURIComponent(dlToken)}`;
                    const treeResp = await fetchWithFallback(treeUrl, {
                        signal: _previewSignal,
                        headers: authToken ? { Authorization: `Bearer ${authToken}` } : {}
                    });
                    if (!treeResp.ok) throw new Error(`HTTP ${treeResp.status}`);
                    const treeData = await treeResp.json();
                    // Server uses snake_case (is_dir); _renderArchiveTree expects isDir
                    const entries = treeData.entries.map(e => ({
                        name:  e.name,
                        size:  e.size,
                        isDir: e.is_dir,
                    }));
                    _renderArchiveTree(bodyEl, entries, filename);
                } catch (treeErr) {
                    bodyEl.innerHTML = `<p style="color:#ef4444;padding:2rem;text-align:center">
                        Archive preview failed: ${escapeHtml(String(treeErr))}</p>`;
                }
            } else {
                bodyEl.innerHTML = `<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3.5rem;margin-bottom:1rem">📦</div>
                    <div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(filename)}</div>
                    <p style="color:#64748b;font-size:14px">No preview available for this archive type yet.</p>
                </div>`;
                dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };
            }
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else {
            bodyEl.innerHTML = `<div style="padding:3rem 1rem;text-align:center"><div style="font-size:3.5rem;margin-bottom:1rem">📄</div><div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(filename)}</div><p style="color:#64748b;font-size:14px">No preview available for this file type yet.</p></div>`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };
        }
    } catch (err) {
        if (err.name === 'AbortError') return;  // modal closed mid-fetch, not an error
        bodyEl.innerHTML = `<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(err))}</p>`;
    }
};

window.previewText = window.previewFile;

// After the table is inserted we need to hook up click handlers for the
// various buttons.  We read the path from the `data-path` attribute, so
// we no longer need to worry about quoting/escaping in the HTML.
// ── Selection state ──────────────────────────────────────────────────────
let _selectedPaths  = new Set();
let _lastClickedPath = null; // used for Shift+click range selection (by path, not index — robust to row reordering between clicks)
// When true (toggled via the fd-sel-bar "keep selection" checkbox), navigating
// into a different folder does NOT clear the current multi-selection — rows
// matching a selected path re-show their checkmark when you return to that
// folder, and ancestor folders show a dash to indicate they contain a
// selected descendant. Off by default so normal browsing behaves as before.
window._fdKeepSelectionOnNav = false;

// ── Selection bar ─────────────────────────────────────────────────────────
// Ghost HTML for the selection bar when nothing is selected.
// Must match the visible bar's markup so reserved height is pixel-identical.
// Used in both renderFileBrowserView (initial render) and _updateSelBar (clear).
// NOTE: this must stay a function, not a top-level const — script.js loads
// before fd_locale_bundle.js/fd_addons.js (see index.html script order), so
// window.t() doesn't exist yet while this file is being parsed. A top-level
// `const ... = \`${t(...)}\`` throws ReferenceError: t is not defined at
// load time. Calling it lazily, after everything's loaded, is safe.
function _selBarGhost() {
    return `
    <span style="opacity:0;pointer-events:none;flex-shrink:0">${t('sel_bar_count', { n: 0 })}</span>
    <button class="btn" style="opacity:0;pointer-events:none;padding:3px 10px;font-size:12px" disabled>⬇ ${t('download')}</button>
    <button class="btn" style="opacity:0;pointer-events:none;padding:3px 10px;font-size:12px;background:#ef4444" disabled>🗑 ${t('trash')}</button>
    <button class="btn" style="opacity:0;pointer-events:none;padding:3px 10px;font-size:12px;background:#6b7280;margin-left:auto" disabled>✕ ${t('sel_bar_clear')}</button>`;
}

// ── Shared bulk-trash flow ───────────────────────────────────────────────────
// Used by the sel-bar "Trash" button, the context-menu "trash-multi" action,
// and the Del-key hotkey — all three want the same confirm → clear selection
// → move each path to Trash → show one batch notice → reload flow. Works
// fine for a single path too (batch notice text handles singular/plural).
async function _trashSelectedPaths(paths) {
    if (!paths.length) return;
    const n = paths.length;
    const ok = await showConfirmModal({
        title: t('sel_bar_delete_title', { n }),
        message: t('sel_bar_delete_msg', { n, days: _lastKnownRetentionDays }),
    });
    if (!ok) return;
    _clearSelection(); _updateSelBar();
    let lastDays = _lastKnownRetentionDays;
    let failed   = 0;
    for (const p of paths) {
        const r = await deleteItem(p, { skipConfirm: true, silent: true });
        if (r === false) failed++;
        else if (r) lastDays = r;
    }
    const moved = paths.length - failed;
    if (moved > 0) {
        // One-time verbose "how Trash works" modal, then always a lightweight
        // toast so every delete gets visible feedback (the modal self-silences
        // after the first time).
        _showTrashBatchNotice(moved, lastDays);
        showToast(t('trash_moved_toast', { n: moved }));
    }
    if (failed > 0) showToast(t('trash_delete_failed') + ` (${failed})`, { type: 'error' });
    loadDirectory(currentPath);
}

function _updateSelBar() {
    const n = _selectedPaths.size;
    const bar = document.getElementById('fd-sel-bar');
    if (!bar) return;

    if (n === 0) {
        bar.classList.remove('fd-sel-bar-visible');
        bar.innerHTML = _selBarGhost();   // restore ghost — keeps height stable
        bar.onclick = null;
        return;
    }

    bar.classList.add('fd-sel-bar-visible');
    // "Keep selection while browsing" is a mouse-ergonomic feature — show the
    // toggle whenever a fine pointer OR hover is available, matching the
    // belt-and-suspenders check used for the upload UI (see
    // _initUploadWrapVisibility). Gating on (pointer: fine) alone made the
    // chip miss the first selection on touch-capable laptops, where that
    // query only flips to true once a mouse has actually been used.
    const showKeepToggle = window.matchMedia('(pointer: fine)').matches
                        || window.matchMedia('(hover: hover)').matches;
    bar.innerHTML = `
        <span style="color:var(--fd-accent,#3b82f6);font-weight:600;flex-shrink:0">${t('sel_bar_count', { n })}</span>
        ${showKeepToggle ? `
        <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--fd-muted,#64748b);
                       cursor:pointer;flex-shrink:0;user-select:none" title="${t('sel_bar_keep_tooltip')}">
            <input type="checkbox" id="fd-sel-keep-chk" ${window._fdKeepSelectionOnNav ? 'checked' : ''}
                   style="width:13px;height:13px">
            📌 ${t('sel_bar_keep_label')}
        </label>` : ''}
        <button data-fdsel="download" class="btn" style="padding:3px 10px;font-size:12px">⬇ ${t('download')}</button>
        <button data-fdsel="trash"    class="btn" style="padding:3px 10px;font-size:12px;background:#ef4444">🗑 ${t('trash')}</button>
        <button data-fdsel="clear"    class="btn" style="padding:3px 10px;font-size:12px;background:#6b7280;margin-left:auto">✕ ${t('sel_bar_clear')}</button>
    `;

    if (showKeepToggle) {
        bar.querySelector('#fd-sel-keep-chk').addEventListener('change', function () {
            window._fdKeepSelectionOnNav = this.checked;
        });
    }

    bar.onclick = e => {
        const btn = e.target.closest('[data-fdsel]');
        if (!btn) return;
        const action = btn.dataset.fdsel;
        if (action === 'clear') { _clearSelection(); _updateSelBar(); return; }
        if (action === 'trash') {
            _trashSelectedPaths([..._selectedPaths]);
            return;
        }
        if (action === 'download') {
            const rows = _getFileRows().filter(r => _selectedPaths.has(r.dataset.path));
            rows.forEach(r => {
                if (r.dataset.isDir === '1') downloadFolderZip(r.dataset.path);
                else downloadFile(r.dataset.path);
            });
            return;
        }
    };
}

// ── Selection helper ─────────────────────────────────────────────────────────
// Called from both the row-body click and from name/open buttons when a
// modifier key is held, so Shift/Ctrl never accidentally opens a file.
function _doRowSelect(row, idx, e) {
    _removeContextMenu();
    const infoPanel = document.getElementById('fd-info-panel');
    if (infoPanel) window.fdCloseFloatingPanel(infoPanel);
    const rows = _getFileRows();
    const anchorIdx = _lastClickedPath ? rows.findIndex(r => r.dataset.path === _lastClickedPath) : -1;
    if (e.shiftKey && anchorIdx >= 0) {
        const lo = Math.min(anchorIdx, idx);
        const hi = Math.max(anchorIdx, idx);
        _selectedPaths.clear();
        rows.forEach((r, i) => {
            const sel = i >= lo && i <= hi;
            _updateRowSelVisual(r, sel);
            if (sel) _selectedPaths.add(r.dataset.path);
        });
        // Deliberately NOT updating _lastClickedPath here — shift-click
        // extends from the original anchor, not a moving one, matching
        // standard file-manager convention.
    } else if (e.ctrlKey || e.metaKey) {
        _toggleSelect(row);
        _lastClickedPath = row.dataset.path;
    } else {
        _clearSelection();
        _toggleSelect(row, true);
        _lastClickedPath = row.dataset.path;
    }
    _updateSelBar();
}

function attachRowListeners() {
    const fileList = document.getElementById('file-list');
    if (!fileList) return;

    // "⋮" context menu button
    fileList.querySelectorAll('.fd-more-btn').forEach(btn => {
        btn.addEventListener('click', e => {
            e.stopPropagation();
            const row = btn.closest('.fd-file-row');
            const r = btn.getBoundingClientRect();
            _showContextMenu(r.left, r.bottom + 4, row);
        });
    });

    // Row-level interactions
    fileList.querySelectorAll('.fd-file-row').forEach((row, idx) => {
        // Single / range / toggle click on row BODY (not buttons)
        row.addEventListener('click', e => {
            if (e.target.closest('button')) return;   // let button handlers fire
            _doRowSelect(row, idx, e);
        });

        // ── Name/open buttons: Shift or Ctrl → select only, never open ───────
        // Without this, holding Shift and clicking a filename would still
        // navigate/preview instead of extending the selection.
        row.querySelectorAll('.preview-btn, .open-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                if (e.shiftKey || e.ctrlKey || e.metaKey) {
                    _doRowSelect(row, idx, e);
                    return;
                }
                if (btn.classList.contains('open-btn')) enterDir(btn.dataset.path);
                else                                    previewFile(btn.dataset.path);
            });
        });

        // Double-click — open / preview
        row.addEventListener('dblclick', e => {
            if (e.target.closest('button')) return;
            _clearSelection(); _updateSelBar();
            if (row.dataset.isDir === '1') enterDir(row.dataset.path);
            else previewFile(row.dataset.path);
        });

        // Right-click — context menu
        row.addEventListener('contextmenu', e => {
            e.preventDefault();
            if (!_selectedPaths.has(row.dataset.path)) {
                _clearSelection();
                _toggleSelect(row, true);
                _lastClickedPath = row.dataset.path;
                _updateSelBar();
            }
            _showContextMenu(e.clientX, e.clientY, row);
        });
    });

    // Clear selection on any click outside the file list entirely — empty
    // <body> margins, #app-root's own background outside #file-list, not
    // just the empty space inside #file-list itself (the old scope). Bound
    // once on document.body rather than re-added on every directory render
    // like the rest of this function, since body persists for the whole
    // session and re-binding here would leak one listener per navigation.
    if (!document.body._fdSelClearBound) {
        document.body._fdSelClearBound = true;
        document.body.addEventListener('click', e => {
            if (e.target.closest('.fd-file-row, #fd-sel-bar, #fd-ctx-menu, .modal-overlay, .fd-profile-overlay')) return;
            if (_selectedPaths.size > 0) { _clearSelection(); _updateSelBar(); }
        });
    }

    // Lazy folder sizes — only for cells the list response couldn't already
    // fill in (cache was cold for that folder); warm ones need no request.
    fileList.querySelectorAll('.folder-size-cell:not([data-warm])').forEach((cell, idx) => {
        setTimeout(() => loadFolderSize(cell), idx * 80);
    });
}

function _getFileRows() {
    return Array.from(document.querySelectorAll('#file-list .fd-file-row'));
}

// Cancels any pending deselect/indeterminate-clear cleanup scheduled on a
// dot by _updateRowSelVisual or _setRowIndeterminate below. Both schedule a
// finish() callback (via animationend + a timeout safety net) to run ~180ms
// later; without cancelling the previous one before scheduling a new state
// change, a stale callback from an earlier toggle could fire AFTER a fast
// subsequent re-select and wrongly hide the dot again — the actual
// selection (_selectedPaths) stays correct the whole time, but the visual
// desyncs from it when toggles happen faster than the fade animation.
function _cancelPendingDotCleanup(dot) {
    if (dot._fdSelTimeout) { clearTimeout(dot._fdSelTimeout); dot._fdSelTimeout = null; }
    if (dot._fdSelFinish) { dot.removeEventListener('animationend', dot._fdSelFinish); dot._fdSelFinish = null; }
}

function _updateRowSelVisual(row, selected) {
    const dot = row.querySelector('.fd-sel-dot');
    if (!dot) return;
    _cancelPendingDotCleanup(dot);
    if (selected) {
        dot.style.display = 'inline-flex';
        dot.style.background = 'var(--fd-accent,#3b82f6)';
        dot.textContent = '✓';
        dot.style.color = '#fff';
        dot.classList.remove('fd-sel-dot-out');
        // Force reflow so re-adding the class restarts the animation even
        // if the dot was mid fade-out from a fast double-toggle.
        void dot.offsetWidth;
        dot.classList.add('fd-sel-dot-in');
        row.style.background = 'var(--fd-accent-bg,#eff6ff)';
    } else {
        if (dot.style.display === 'none') return; // already hidden, nothing to animate
        dot.classList.remove('fd-sel-dot-in');
        dot.classList.add('fd-sel-dot-out');
        row.style.background = '';
        const finish = () => {
            dot.style.display = 'none';
            dot.style.background = 'transparent';
            dot.textContent = '';
            dot.classList.remove('fd-sel-dot-out');
            dot._fdSelFinish = null;
            dot._fdSelTimeout = null;
        };
        dot._fdSelFinish = finish;
        dot.addEventListener('animationend', finish, { once: true });
        dot._fdSelTimeout = setTimeout(finish, 180); // safety net if animationend doesn't fire
    }
}

function _toggleSelect(row, force) {
    const path = row.dataset.path;
    const nowSelected = (force !== undefined) ? force : !_selectedPaths.has(path);
    if (nowSelected) _selectedPaths.add(path); else _selectedPaths.delete(path);
    _updateRowSelVisual(row, nowSelected);
}

// Shows a dash ("–") on a folder row's selection dot to indicate it contains
// a selected item somewhere inside it (without the folder itself being
// selected) — same dot slot as the checkmark, slightly muted color so it
// reads as "partially selected" rather than "selected".
function _setRowIndeterminate(row, on) {
    const dot = row.querySelector('.fd-sel-dot');
    if (!dot) return;
    _cancelPendingDotCleanup(dot);
    if (on) {
        dot.style.display = 'inline-flex';
        dot.style.background = 'var(--fd-accent-dim,#93c5fd)';
        dot.textContent = '–';
        dot.style.color = '#fff';
        dot.classList.remove('fd-sel-dot-out');
        void dot.offsetWidth; // restart animation if mid fade-out
        dot.classList.add('fd-sel-dot-in');
    } else {
        if (dot.textContent !== '–') return; // not currently a dash — nothing to clear
        dot.classList.remove('fd-sel-dot-in');
        dot.classList.add('fd-sel-dot-out');
        const finish = () => {
            dot.style.display = 'none';
            dot.style.background = 'transparent';
            dot.textContent = '';
            dot.classList.remove('fd-sel-dot-out');
            dot._fdSelFinish = null;
            dot._fdSelTimeout = null;
        };
        dot._fdSelFinish = finish;
        dot.addEventListener('animationend', finish, { once: true });
        dot._fdSelTimeout = setTimeout(finish, 180); // safety net if animationend doesn't fire
    }
}

// True if some currently-selected path lives inside dirPath (dirPath is a
// strict ancestor of a selected item) — drives the dash indicator above.
function _hasSelectedDescendant(dirPath) {
    const prefix = dirPath.endsWith('/') ? dirPath : dirPath + '/';
    for (const p of _selectedPaths) {
        if (p !== dirPath && p.startsWith(prefix)) return true;
    }
    return false;
}

// Re-applies checkmark/dash visuals to whatever rows are currently rendered,
// based on the persisted _selectedPaths set. A fresh loadDirectory() render
// always starts with plain, unselected row markup — this is what makes a
// kept-across-navigation selection (see window._fdKeepSelectionOnNav) show
// up again when the user returns to a folder.
function _applySelectionVisuals() {
    _getFileRows().forEach(row => {
        const p = row.dataset.path;
        if (_selectedPaths.has(p)) {
            _updateRowSelVisual(row, true);
        } else if (row.dataset.isDir === '1' && _hasSelectedDescendant(p)) {
            _setRowIndeterminate(row, true);
        }
        // else: leave as freshly-rendered default (unselected, dot hidden)
    });
}

function _clearSelection() {
    _getFileRows().forEach(r => _updateRowSelVisual(r, false));
    _selectedPaths.clear();
    _lastClickedPath = null;
}

// Drop a path — and, if it was a folder, everything nested under it — from the
// persisted selection. Used after a move/rename: the old path no longer exists
// so its checkmark can never re-render, but the entry would otherwise linger
// forever (wrong sel-bar count, stale ancestor dash, phantom pre-selected row
// if the same name is recreated). Mirrors the single-path scrub deleteItem()
// does after trashing. Caller is responsible for the follow-up _updateSelBar().
function _dropSelectedUnder(path) {
    const prefix = path.endsWith('/') ? path : path + '/';
    for (const p of [..._selectedPaths]) {
        if (p === path || p.startsWith(prefix)) _selectedPaths.delete(p);
    }
    if (_lastClickedPath === path || _lastClickedPath?.startsWith(prefix)) _lastClickedPath = null;
}

// ── Context menu ─────────────────────────────────────────────────────────
function _removeContextMenu() {
    document.getElementById('fd-ctx-menu')?.remove();
}

// Animated dismiss, for every user-initiated close (click outside/inside the
// menu, an item action, or scroll). _removeContextMenu() itself must stay
// instant only where a brand-new menu is about to take the same #fd-ctx-menu
// id right away: _showContextMenu()'s own guard, and _doRowSelect() (a hot
// path — row selection fires far more often than the menu is actually open,
// so it can't afford a fade there). Everywhere the menu is genuinely being
// dismissed, use this instead so it doesn't just vanish.
function _dismissContextMenu() {
    const menu = document.getElementById('fd-ctx-menu');
    if (menu) window.fdCloseFloatingPanel(menu);
}

function _showContextMenu(x, y, row) {
    _removeContextMenu();
    const path  = row.dataset.path;
    const isDir = row.dataset.isDir === '1';

    // ── Multi-select mode ──────────────────────────────────────────────────
    // When more than one item is selected and the right-clicked item is part
    // of the selection, show a reduced menu that acts on all selected items.
    const selCount = _selectedPaths.size;
    const isMulti  = selCount > 1 && _selectedPaths.has(path);

    const menu = document.createElement('div');
    menu.id = 'fd-ctx-menu';
    menu.style.cssText =
        `position:fixed;left:${x}px;top:${y}px;` +
        `background:var(--fd-surface,#fff);border:1px solid var(--fd-border,#e2e8f0);` +
        `border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,0.15);` +
        `z-index:50000;min-width:190px;padding:4px 0;font-size:13px;overflow:hidden`;

    const ITEM = (icon, label, action, danger) =>
        `<button class="fd-ctx-item" data-action="${action}"
            style="display:block;width:100%;padding:7px 14px;text-align:left;
                   background:none;border:none;cursor:pointer;
                   color:${danger ? 'var(--fd-danger,#dc2626)' : 'var(--fd-text,#1e293b)'};
                   white-space:nowrap;font-size:13px"
        >${icon} ${label}</button>`;
    const SEP = `<div style="border-top:1px solid var(--fd-border,#e2e8f0);margin:4px 0"></div>`;

    if (isMulti) {
        // Work out folder/file counts for better label wording
        const selRows = _getFileRows().filter(r => _selectedPaths.has(r.dataset.path));
        const nDirs   = selRows.filter(r => r.dataset.isDir === '1').length;
        const nFiles  = selRows.length - nDirs;

        let dlLabel;
        if (nDirs === 0)       dlLabel = t('ctx_download_files', { n: nFiles });
        else if (nFiles === 0) dlLabel = t('ctx_download_folders_zip', { n: nDirs });
        else                   dlLabel = t('ctx_download_mixed', { nf: nFiles, nd: nDirs });

        menu.innerHTML = [
            ITEM('⬇', dlLabel,                          'download-multi'),
            SEP,
            ITEM('🗑', t('ctx_trash_multi', { n: selCount }), 'trash-multi', true),
        ].join('');
    } else {
        menu.innerHTML = [
            isDir ? ITEM('📂', t('ctx_open'),         'open')    : ITEM('👁', t('ctx_preview'),  'preview'),
            isDir ? ITEM('⬇',  t('ctx_download_zip'), 'zip')     : ITEM('⬇', t('ctx_download'), 'download'),
            ITEM('🔗', t('ctx_share'),                            'share'),
            ITEM('✂',  t('ctx_move_rename'),                     'move'),
            ITEM('ℹ',  t('ctx_info'),                             'info'),
            SEP,
            ITEM('🗑',  t('ctx_trash'),                           'trash', true),
        ].join('');
    }

    document.body.appendChild(menu);
    menu.classList.add('fd-ctx-menu-in');

    // Close on click anywhere outside the menu, or on scroll.
    // setTimeout 0 defers registration past the current click event that opened
    // the menu, so the same click that shows it doesn't immediately close it.
    setTimeout(() => {
        document.addEventListener('click',  _dismissContextMenu, { once: true, capture: true });
        document.addEventListener('scroll', _dismissContextMenu, { once: true, passive: true });
    }, 0);

    // Hover highlight + actions
    menu.querySelectorAll('.fd-ctx-item').forEach(btn => {
        btn.addEventListener('mouseenter', () => btn.style.background = 'var(--fd-surface3,#f1f5f9)');
        btn.addEventListener('mouseleave', () => btn.style.background = 'none');
        btn.addEventListener('click', () => {
            _dismissContextMenu();
            const p  = row.dataset.path;
            const id = row.dataset.isDir === '1';
            switch (btn.dataset.action) {
                // ── Single-item actions ─────────────────────────────────────
                case 'open':     enterDir(p); break;
                case 'preview':  previewFile(p); break;
                case 'download': downloadFile(p); break;
                case 'zip':      downloadFolderZip(p); break;
                case 'share':    openShareDialog(p, id); break;
                case 'move':     openMoveDialog(p); break;
                case 'info':     _showFileInfo(row); break;
                case 'trash':    deleteItem(p); break;

                // ── Multi-select actions ────────────────────────────────────
                case 'download-multi': {
                    _getFileRows()
                        .filter(r => _selectedPaths.has(r.dataset.path))
                        .forEach(r => {
                            if (r.dataset.isDir === '1') downloadFolderZip(r.dataset.path);
                            else downloadFile(r.dataset.path);
                        });
                    break;
                }
                case 'trash-multi': {
                    _trashSelectedPaths([..._selectedPaths]);
                    break;
                }
            }
        });
    });

    // Keep within viewport
    requestAnimationFrame(() => {
        const r = menu.getBoundingClientRect();
        if (r.right  > window.innerWidth)  menu.style.left = Math.max(4, window.innerWidth  - r.width  - 8) + 'px';
        if (r.bottom > window.innerHeight) menu.style.top  = Math.max(4, y - r.height) + 'px';
    });
}

// ── File info panel ──────────────────────────────────────────────────────
// Torn down and re-armed each time _showFileInfo runs; a no-op when the panel
// isn't in "inspector" (pinned) mode.
let _fdInfoInspectorCleanup = () => {};

function _showFileInfo(row) {
    _fdInfoInspectorCleanup();
    document.getElementById('fd-info-panel')?.remove();

    const name    = row.dataset.name    || '—';
    const path    = row.dataset.path    || '—';
    const isDir   = row.dataset.isDir   === '1';
    const mtime   = row.dataset.mtime   || '';
    const uploader= row.dataset.uploader|| '';
    const rawSize = parseInt(row.dataset.size, 10);
    const sizeStr = isDir
        ? (row.querySelector('.folder-size-cell')?.textContent?.trim() || '…')
        : (isNaN(rawSize) ? '—' : formatBytes(rawSize));

    const ext = !isDir && name.includes('.') ? name.split('.').pop().toUpperCase() : null;
    const typeStr = isDir ? 'Folder' : (ext ? `${ext} file` : 'File');

    const panel = document.createElement('div');
    panel.id = 'fd-info-panel';
    panel.style.cssText =
        'position:fixed;right:12px;top:70px;width:280px;z-index:20000;' +
        'background:var(--fd-surface,#fff);border:1px solid var(--fd-border,#e2e8f0);' +
        'border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.14);' +
        'padding:0;overflow:hidden;font-size:13px;animation:fd-info-in .18s ease';

    if (!document.getElementById('fd-info-kf')) {
        const s = document.createElement('style'); s.id = 'fd-info-kf';
        s.textContent = '@keyframes fd-info-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}';
        document.head.appendChild(s);
    }

    const row2 = (label, value, isHTML) =>
        `<div style="display:flex;justify-content:space-between;padding:5px 14px;
                     border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <span style="color:var(--fd-muted,#64748b);flex-shrink:0;margin-right:8px;white-space:nowrap">${label}</span>
            <span style="color:var(--fd-text,#1e293b);text-align:right;word-break:break-all;font-family:${label==='CRC-32'?'monospace':'inherit'}">${isHTML ? value : escapeHtml(value)}</span>
         </div>`;

    panel.innerHTML =
        `<div style="background:var(--fd-surface3,#f1f5f9);padding:10px 14px;
                     display:flex;justify-content:space-between;align-items:center;
                     border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <span style="font-weight:600;color:var(--fd-text,#1e293b);font-size:14px">
                ${isDir ? '📁' : '📄'} Info
            </span>
            <button id="fd-info-close" style="background:none;border:none;cursor:pointer;
                font-size:18px;color:var(--fd-muted,#64748b);padding:0 2px;line-height:1">✕</button>
        </div>` +
        row2('Name',     name) +
        row2('Path',     path) +
        row2('Type',     typeStr) +
        row2('Size',     sizeStr) +
        row2('Modified', mtime ? formatMtime(mtime) : '—') +
        (uploader ? row2('Uploaded by', uploader) : '') +
        (!isDir ? `<div id="fd-info-cs-wrap">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0);gap:8px">
                <span style="color:var(--fd-muted,#64748b);flex-shrink:0;white-space:nowrap">CRC-32</span>
                <span id="fd-cs-val-crc32" style="display:flex;align-items:center;gap:4px;min-width:0"><span style="color:#94a3b8;font-size:12px">Loading\u2026</span></span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0);gap:8px">
                <span style="color:var(--fd-muted,#64748b);flex-shrink:0;white-space:nowrap">SHA-256</span>
                <span id="fd-cs-val-sha256" style="display:flex;align-items:center;gap:4px;min-width:0"><span style="color:#94a3b8;font-size:12px">Loading\u2026</span></span>
            </div>
        </div>` : '') +
        (!isDir ? `<div style="padding:8px 14px;border-bottom:1px solid var(--fd-border,#e2e8f0)">
            <button id="fd-info-dl" class="btn"
                style="width:100%;padding:5px;font-size:12px;text-align:center">
                ⬇ Download
            </button></div>` : '');

    document.body.appendChild(panel);

    let pinned = false;
    try { pinned = localStorage.getItem('fd_pin_info_panel') === '1'; } catch (_) {}

    document.getElementById('fd-info-close').addEventListener('click', () => {
        _fdInfoInspectorCleanup();
        window.fdCloseFloatingPanel(panel);
    });

    // Download button
    const dlBtn = document.getElementById('fd-info-dl');
    if (dlBtn) dlBtn.addEventListener('click', () => { _fdInfoInspectorCleanup(); panel.remove(); downloadFile(path); });

    if (!isDir) _initChecksumSection(path, panel);

    if (pinned) {
        // Inspector mode (Settings → "Click items to inspect"): the panel stays
        // open on outside clicks, and clicking another row retargets the panel
        // to that item instead of opening/previewing it. ✕ closes it. Right-
        // click still opens the normal actions menu, and ⋮ is left alone.
        const inspect = e => {
            if (panel.contains(e.target)) return;
            if (e.target.closest && e.target.closest('.fd-more-btn')) return;
            const r = e.target.closest && e.target.closest('.fd-file-row');
            if (!r) return;                       // empty space — leave the panel as-is
            e.preventDefault();
            e.stopPropagation();
            _showFileInfo(r);                     // rebuilds the panel + re-arms this listener
        };
        setTimeout(() => document.addEventListener('click', inspect, true), 10);
        _fdInfoInspectorCleanup = () => {
            document.removeEventListener('click', inspect, true);
            _fdInfoInspectorCleanup = () => {};
        };
    } else {
        const closer = e => { if (!panel.contains(e.target)) { window.fdCloseFloatingPanel(panel); document.removeEventListener('click', closer, true); } };
        setTimeout(() => document.addEventListener('click', closer, true), 10);
    }
}

// ── File info — checksum section (CRC-32 + SHA-256) ──────────────────────────
// Fetches cached values from /api/v1/fileinfo, shows Calc buttons when missing,
// polls while a computation job is active, and shows a copy button when done.
function _initChecksumSection(path, panel) {
    let _pollT = null;

    // Show an amber "Calculating…" spinner in the given algo row.
    function _csSetCalc(algo) {
        const el = panel.querySelector(`#fd-cs-val-${algo}`);
        if (el) el.innerHTML =
            '<span style="color:#d97706;font-size:12px">\u29d7 Calculating\u2026</span>';
    }

    // Show a computed hash value with a copy-to-clipboard button.
    function _csSetValue(algo, value) {
        const el = panel.querySelector(`#fd-cs-val-${algo}`);
        if (!el) return;
        // SHA-256 is 64 hex chars — truncate for display, keep full value in title.
        const display = algo === 'sha256' ? (value.slice(0, 16) + '\u2026') : value;
        el.innerHTML =
            `<span style="font-family:monospace;font-size:11px;color:var(--fd-text,#1e293b);` +
            `word-break:break-all;text-align:right" title="${escapeHtmlAttr(value)}">${escapeHtml(display)}</span>` +
            `<button id="fd-cs-copy-${algo}" title="Copy ${algo.toUpperCase()}" ` +
            `style="border:none;background:none;cursor:pointer;color:#94a3b8;font-size:13px;` +
            `padding:0 0 0 3px;flex-shrink:0;line-height:1">\u29c9</button>`;
        panel.querySelector(`#fd-cs-copy-${algo}`)?.addEventListener('click', e => {
            e.stopPropagation();
            navigator.clipboard?.writeText(value);
            const btn = panel.querySelector(`#fd-cs-copy-${algo}`);
            if (btn) {
                btn.textContent = '\u2713';
                setTimeout(() => { if (btn) btn.textContent = '\u29c9'; }, 1500);
            }
        });
    }

    // Show a "—" placeholder (or error badge) with a Calc / Retry button.
    // targetAlgos: the algos list that will be sent to the server on click.
    function _csSetMissing(algo, targetAlgos, errMsg) {
        const el = panel.querySelector(`#fd-cs-val-${algo}`);
        if (!el) return;
        const tip  = errMsg ? ` title="${escapeHtmlAttr(errMsg)}"` : '';
        const icon = errMsg ? '\u26a0\ufe0f error' : '\u2014';
        el.innerHTML =
            `<span style="color:#94a3b8;font-size:12px"${tip}>${icon}</span>` +
            `<button id="fd-cs-calc-${algo}" ` +
            `style="border:none;background:#f1f5f9;color:#3b82f6;cursor:pointer;` +
            `padding:2px 7px;border-radius:6px;font-size:11px;font-weight:600;` +
            `margin-left:4px;flex-shrink:0">${errMsg ? 'Retry' : 'Calc'}</button>`;
        panel.querySelector(`#fd-cs-calc-${algo}`)?.addEventListener('click', async e => {
            e.stopPropagation();
            // Immediately show "Calculating…" for every algo that will be computed.
            for (const a of targetAlgos) _csSetCalc(a);
            try {
                await apiCall('/api/v1/checksums/compute', 'POST',
                              { path, algos: targetAlgos }, true);
            } catch (err) {
                _csSetMissing(algo, targetAlgos, err.message || 'Request failed');
                return;
            }
            _schedPoll();
        });
    }

    function _schedPoll() {
        if (!panel.isConnected) return;
        clearTimeout(_pollT);
        _pollT = setTimeout(fetchAndRender, 1800);
    }

    async function fetchAndRender() {
        if (!panel.isConnected) { clearTimeout(_pollT); return; }
        let data;
        try {
            data = await apiCall(`/api/v1/fileinfo${encodePath(path)}`, 'GET', null, true);
        } catch {
            const dash = '<span style="color:#94a3b8;font-size:12px">\u2014</span>';
            ['crc32', 'sha256'].forEach(a => {
                const el = panel.querySelector(`#fd-cs-val-${a}`);
                if (el) el.innerHTML = dash;
            });
            return;
        }
        if (!panel.isConnected) return;

        const job      = data.job;
        const isActive = job && (job.status === 'pending' || job.status === 'running');
        const isError  = job && job.status === 'error';
        const errMsg   = isError ? (job.error || 'Computation failed') : null;
        const jobAlgos = job ? (job.algos || '') : '';

        // When both hashes are missing, clicking either Calc button computes both
        // in a single server-side file read.  When only one is missing, only
        // that algo is computed.
        const calcAlgos = [];
        if (!data.crc32)  calcAlgos.push('crc32');
        if (!data.sha256) calcAlgos.push('sha256');

        // CRC-32 row
        if (data.crc32) {
            _csSetValue('crc32', data.crc32.toLowerCase());
        } else if (isActive && jobAlgos.includes('crc32')) {
            _csSetCalc('crc32');
        } else {
            _csSetMissing('crc32',
                calcAlgos.length ? calcAlgos : ['crc32'],
                isError && jobAlgos.includes('crc32') ? errMsg : null);
        }

        // SHA-256 row
        if (data.sha256) {
            _csSetValue('sha256', data.sha256.toLowerCase());
        } else if (isActive && jobAlgos.includes('sha256')) {
            _csSetCalc('sha256');
        } else {
            _csSetMissing('sha256',
                calcAlgos.length ? calcAlgos : ['sha256'],
                isError && jobAlgos.includes('sha256') ? errMsg : null);
        }

        if (isActive && panel.isConnected) _schedPoll();
    }

    fetchAndRender();
}

// ── [attachRowListeners defined above in _updateSelBar block] ─────────────

async function loadFolderSize(cell) {
    const path = cell.dataset.path;
    if (!path || !authToken) return;
    try {
        const ep = `/api/v1/foldersize${encodePath(path)}`;
        const data = await apiCall(ep, 'GET', null, true);
        if (cell.isConnected) {  // row may have been replaced by a re-render
            cell.textContent = formatBytes(data.size);
            cell.title = `${data.file_count} file${data.file_count !== 1 ? 's' : ''}`;
            cell.style.color = '';
        }
    } catch {
        if (cell.isConnected) { cell.textContent = '—'; cell.style.color = '#94a3b8'; }
    }
}

window.deleteItem = async function(path, optsOrLegacy = {}) {
    // Accept either a plain options object {skipConfirm, silent} or a legacy
    // boolean `true` (old call sites that passed `true` as skipConfirm).
    const opts = typeof optsOrLegacy === 'boolean'
        ? { skipConfirm: optsOrLegacy }
        : (optsOrLegacy || {});
    const skipConfirm = !!opts.skipConfirm;
    const silent      = !!opts.silent;

    const disp = stripInternalPrefix(path);
    if (!skipConfirm) {
        const ok = await showConfirmModal({
            title: `Move "${disp}" to Trash?`,
            message: `You'll be able to retrieve it from the Trash bin for the next `
                     + `${_lastKnownRetentionDays} day${_lastKnownRetentionDays !== 1 ? 's' : ''}.`,
        });
        if (!ok) return false;
    }
    try {
        const res = await apiCall('/api/v1/trash', 'POST', { path });
        const days = res.retention_days || 30;
        _lastKnownRetentionDays = days;
        // Deleted paths must never linger in _selectedPaths: batch callers
        // (trash-multi, sel-bar trash) already clear the whole set up front,
        // so this is a no-op for them, but the single-item context-menu
        // "Move to Trash" action calls deleteItem() directly with nothing
        // else scrubbing the selection — without this, a deleted item's path
        // stays "selected" forever (wrong sel-bar count, stale ancestor dash
        // indicators, and a phantom pre-selected row if the same path is
        // ever recreated).
        _selectedPaths.delete(path);
        if (!silent) {
            _updateSelBar();
            showToast(`${disp} moved to Trash (${days} day${days !== 1 ? 's' : ''})`);
        }
        loadDirectory(currentPath);
        return days;   // return retention days so batch callers can use the last value
    } catch (err) {
        showMessage('Failed', err.message);
        return false;
    }
}

// ── Batch-trash notice ────────────────────────────────────────────────────────
// Shows ONE informational message the very first time the user moves multiple
// items to the Trash via multi-select.  Subsequent batch deletes are silent.
// Storage key is versioned so a copy-change can re-show it if needed.
const _TRASH_BATCH_NOTICE_KEY = 'fd-trash-batch-notice-v1';

function _showTrashBatchNotice(count, retentionDays) {
    const days = retentionDays || 30;
    const already = localStorage.getItem(_TRASH_BATCH_NOTICE_KEY);
    if (already) return;   // already seen — stay silent
    localStorage.setItem(_TRASH_BATCH_NOTICE_KEY, '1');
    showMessage(
        `${count} item${count !== 1 ? 's' : ''} moved to Trash`,
        `They will be kept for ${days} day${days !== 1 ? 's' : ''} before permanent deletion.\n\n`
        + 'Open Trash (🗑 in the sidebar) at any time to restore or permanently delete them.\n\n'
        + '💡 This notice appears only once. For more details on Trash behaviour, '
        + 'visit the Wiki inside your profile settings.'
    );
}

// ======================================================================
// --- TRASH BIN VIEW ---
// ======================================================================

// Inject spin keyframe once
;(function() {
    if (document.getElementById('_fd-spin-style')) return;
    const s = document.createElement('style');
    s.id = '_fd-spin-style';
    s.textContent = '@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}';
    document.head.appendChild(s);
})();

async function openTrashView() {
    // Remove any existing trash overlay
    document.getElementById('trash-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'trash-overlay';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal-content" style="max-width:680px;width:95vw;padding:0;overflow:hidden;border-radius:14px">
            <div style="background:linear-gradient(135deg,#dc2626,#b91c1c);padding:16px 20px;
                        display:flex;align-items:center;justify-content:space-between">
                <div>
                    <div style="color:white;font-weight:700;font-size:16px">🗑 Trash</div>
                    <div id="trash-subtitle" style="color:rgba(255,255,255,.75);font-size:12px;margin-top:2px"></div>
                </div>
                <div onclick="window.fdCloseOverlay(document.getElementById('trash-overlay'))"
                    style="background:rgba(255,255,255,.15);border:none;color:white;
                           border-radius:6px;padding:4px 10px;cursor:pointer;font-size:14px
                           ;display:inline-block">${t('close') || '✕'}</div>
            </div>
            <div id="trash-notice" style="display:none;padding:8px 20px;background:#fef3c7;
                border-bottom:1px solid #fde68a;font-size:12px;color:#92400e"></div>
            <div style="padding:12px 20px;border-bottom:1px solid #e2e8f0;display:flex;
                        justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                <span style="font-size:12px;color:#64748b">
                    ${t('trash_retention_notice') !== 'trash_retention_notice'
                        ? t('trash_retention_notice')
                        : 'Files are automatically deleted after their retention period. Trash does not count toward your storage quota.'}
                </span>
                <button id="trash-empty-btn"
                    style="background:#ef4444;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;
                           white-space:nowrap">
                    ${t('trash_empty_btn') !== 'trash_empty_btn' ? t('trash_empty_btn') : 'Empty Trash'}
                </button>
            </div>
            <div id="trash-body" style="max-height:55vh;overflow-y:auto;padding:8px 0">
                <div style="padding:24px;text-align:center;color:#94a3b8">Loading…</div>
            </div>
        </div>`;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });

    await _refreshTrashView();

    document.getElementById('trash-empty-btn').addEventListener('click', async () => {
        const ok = await showConfirmModal({
            title: 'Empty Trash?',
            message: 'Everything in the Trash will be permanently deleted. This cannot be undone.',
        });
        if (!ok) return;
        try {
            await apiCall('/api/v1/trash', 'DELETE');
            await _refreshTrashView();
        } catch (err) {
            alert('Failed to empty trash: ' + err.message);
        }
    });
}

async function _refreshTrashView() {
    const body     = document.getElementById('trash-body');
    const subtitle = document.getElementById('trash-subtitle');
    const notice   = document.getElementById('trash-notice');
    if (!body) return;

    body.innerHTML = '<div style="padding:24px;text-align:center;color:#94a3b8">Loading…</div>';

    let data;
    try {
        data = await apiCall('/api/v1/trash', 'GET');
    } catch (err) {
        body.innerHTML = `<div style="padding:24px;text-align:center;color:#ef4444">Failed: ${escapeHtml(err.message)}</div>`;
        return;
    }

    const items = data.items || [];
    if (data.retention_days) _lastKnownRetentionDays = data.retention_days;
    subtitle.textContent = items.length === 1
        ? (t('trash_1_item') !== 'trash_1_item' ? t('trash_1_item') : '1 item')
        : (t('trash_n_items') !== 'trash_n_items'
            ? t('trash_n_items', { n: items.length })
            : `${items.length} items`);

    // The backend only sends retention_days now (see server_cdn.py
    // _handle_trash_list) — the "reduced retention" notice is built here so
    // it goes through i18n instead of being a hardcoded English sentence.
    if (data.retention_days === 7 && notice) {
        notice.textContent = '⚠ ' + t('trash_retention_reduced_notice', { days: data.retention_days });
        notice.style.display = 'block';
    } else if (notice) {
        notice.style.display = 'none';
    }

    if (!items.length) {
        body.innerHTML = '<div style="padding:40px;text-align:center;color:#94a3b8;font-size:15px">🗑 Trash is empty</div>';
        return;
    }

    function fmtDate(ts) {
        if (!ts) return '—';
        return new Date(ts * 1000).toLocaleString();
    }
    function fmtBytes(b) {
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
        if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
        return (b/1073741824).toFixed(2) + ' GB';
    }
    function daysLeft(expiresAt) {
        const d = Math.ceil((expiresAt - Date.now()/1000) / 86400);
        if (d <= 0) {
            const lbl = t('trash_days_expiring') !== 'trash_days_expiring' ? t('trash_days_expiring') : 'Expiring soon';
            return `<span style="color:#ef4444">${lbl}</span>`;
        }
        if (d === 1) {
            const lbl = t('trash_days_1') !== 'trash_days_1' ? t('trash_days_1') : '1 day left';
            return `<span style="color:#f59e0b">${lbl}</span>`;
        }
        if (d <= 3) {
            const lbl = t('trash_days_n') !== 'trash_days_n' ? t('trash_days_n', { n: d }) : `${d} days left`;
            return `<span style="color:#f59e0b">${lbl}</span>`;
        }
        const lbl = t('trash_days_n') !== 'trash_days_n' ? t('trash_days_n', { n: d }) : `${d} days left`;
        return `<span style="color:#64748b">${lbl}</span>`;
    }

    body.innerHTML = items.map(item => `
        <div class="trash-row" data-id="${item.id}"
             style="display:flex;align-items:center;gap:10px;padding:10px 20px;
                    border-bottom:1px solid #f1f5f9;transition:background .12s"
             onmouseenter="this.style.background='#f8fafc'"
             onmouseleave="this.style.background=''">
            <span style="font-size:18px;flex-shrink:0">${item.is_dir ? '📁' : '📄'}</span>
            <div style="flex:1;min-width:0">
                <div style="font-weight:500;font-size:13px;overflow:hidden;text-overflow:ellipsis;
                            white-space:nowrap" title="${escapeHtmlAttr(item.original_path)}">
                    ${escapeHtml(item.name)}
                </div>
                <div style="font-size:11px;color:#94a3b8;margin-top:2px">
                    ${escapeHtml(item.original_path)} &nbsp;·&nbsp;
                    ${fmtBytes(item.size_bytes)} &nbsp;·&nbsp;
                    ${t('trash_deleted_label')} ${fmtDate(item.deleted_at)}
                </div>
            </div>
            <div style="flex-shrink:0;font-size:11px;text-align:right;min-width:70px">
                ${daysLeft(item.expires_at)}
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0">
                ${!item.is_dir
                    ? `<button class="trash-preview-btn" data-id="${item.id}" data-name="${escapeHtmlAttr(item.name)}"
                           style="background:#6366f1;color:white;border:none;border-radius:6px;
                                  padding:4px 10px;cursor:pointer;font-size:12px">
                           ${t('trash_preview')}
                       </button>`
                    : `<button class="trash-browse-btn" data-trash-path="${escapeHtmlAttr(item.trash_path)}" data-id="${item.id}"
                           style="background:#6366f1;color:white;border:none;border-radius:6px;
                                  padding:4px 10px;cursor:pointer;font-size:12px">
                           ${t('trash_browse')}
                       </button>`}
                <button class="trash-restore-btn" data-id="${item.id}"
                    style="background:#22c55e;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px;font-weight:600">
                    ${t('trash_restore')}
                </button>
                <button class="trash-del-btn" data-id="${item.id}" data-name="${escapeHtmlAttr(item.name)}"
                    style="background:#ef4444;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px">
                    ${t('trash_delete')}
                </button>
            </div>
        </div>`).join('');

    // Attach listeners
    body.querySelectorAll('.trash-restore-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = +btn.dataset.id;
            try {
                const res = await apiCall(`/api/v1/trash/${id}/restore`, 'POST');
                loadDirectory(currentPath);
                await _refreshTrashView();
            } catch (err) {
                alert('Restore failed: ' + err.message);
            }
        });
    });

    body.querySelectorAll('.trash-del-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = +btn.dataset.id;
            const name = btn.dataset.name || '';
            const ok = await showConfirmModal({
                title: t('trash_perm_delete_title', { name }),
                message: t('trash_perm_delete_body'),
            });
            if (!ok) return;
            try {
                await apiCall(`/api/v1/trash/${id}`, 'DELETE');
                await _refreshTrashView();
            } catch (err) {
                showToast(t('trash_delete_failed') + ': ' + err.message, { type: 'error' });
            }
        });
    });

   // Preview button — stream the trashed file directly via the trash endpoint.
    body.querySelectorAll('.trash-preview-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            _previewTrashFile(+btn.dataset.id, btn.dataset.name);
        });
    });

    // NOTE: no .trash-browse-btn handler here on purpose. The real,
    // working implementation lives in fd_addons.js ("6. TRASH FOLDER
    // BROWSE" — document-level, capturing-phase listener that calls
    // GET /api/v1/trash/<id>/list). This file used to have a second,
    // dead handler bound to the same buttons, which raced against the
    // real one and caused the button to get stuck on "Close" — removed.
}


window.promptRename = function(path) { openMoveDialog(path); }

// ======================================================================
// --- MOVE / RENAME / COPY DIALOG ---
// ======================================================================
async function openMoveDialog(srcPath) {
    const srcName  = srcPath.split('/').pop() || srcPath;
    const srcDir   = srcPath.includes('/') ? srcPath.slice(0, srcPath.lastIndexOf('/')) || '/' : '/';

    // Inject styles once
    if (!document.getElementById('fd-move-style')) {
        const st = document.createElement('style');
        st.id = 'fd-move-style';
        st.textContent = `
            .mv-tree-row{display:flex;align-items:center;gap:0;cursor:pointer;border-radius:6px;
                padding:3px 6px;font-size:13px;user-select:none;white-space:nowrap}
            .mv-tree-row:hover{background:#f1f5f9}
            .mv-tree-row.mv-selected{background:#dbeafe;font-weight:600}
            .mv-tree-row.mv-selected:hover{background:#bfdbfe}
            .mv-expand-btn{background:none;border:none;cursor:pointer;padding:0 2px;
                font-size:11px;width:18px;text-align:center;color:#64748b;flex-shrink:0}
            .mv-expand-btn:hover{color:#1e293b}
            .mv-tree-label{overflow:hidden;text-overflow:ellipsis}
            #mv-name-input{width:100%;padding:7px 10px;border:1px solid #e2e8f0;border-radius:8px;
                font-size:14px;font-family:Inter,sans-serif;outline:none;box-sizing:border-box}
            #mv-name-input:focus{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.15)}
            .mv-tab{padding:6px 14px;border:none;border-radius:6px;font-size:13px;font-weight:600;
                cursor:pointer;background:none;color:#64748b;transition:background .15s,color .15s}
            .mv-tab.mv-active{background:#3b82f6;color:#fff}
            .mv-tab:not(.mv-active):hover{background:#f1f5f9;color:#1e293b}
        `;
        document.head.appendChild(st);
    }

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'mv-dialog-overlay';
    overlay.innerHTML = `
        <div class="modal-content" style="max-width:560px;width:95vw;padding:0;overflow:hidden;border-radius:14px">
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:16px 20px;display:flex;align-items:center;justify-content:space-between">
                <div>
                    <div style="color:white;font-weight:700;font-size:16px">📁 Move / Rename / Copy</div>
                    <div style="color:rgba(255,255,255,.75);font-size:12px;margin-top:2px;max-width:380px;
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtmlAttr(srcPath)}">${escapeHtml(srcPath)}</div>
                </div>
                <button id="mv-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:30px;height:30px;color:white;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center">✕</button>
            </div>

            <!-- Tabs -->
            <div style="display:flex;gap:6px;padding:14px 20px 0">
                <button class="mv-tab mv-active" data-tab="move">✂️ Move</button>
                <button class="mv-tab" data-tab="rename">✏️ Rename</button>
                <button class="mv-tab" data-tab="copy">📋 Copy</button>
            </div>

            <!-- Move/Copy tab body -->
            <div id="mv-tab-move" style="padding:14px 20px 20px">
                <div style="font-size:13px;color:#64748b;margin-bottom:8px">
                    Select destination folder — then confirm below.
                </div>
                <!-- New folder shortcut -->
                <div style="display:flex;gap:6px;margin-bottom:8px">
                    <input id="mv-new-folder-input" placeholder="New subfolder name…" style="flex:1;padding:5px 9px;border:1px solid #e2e8f0;border-radius:7px;font-size:13px;font-family:Inter,sans-serif;outline:none">
                    <button id="mv-new-folder-btn" style="background:#0ea5e9;color:white;border:none;border-radius:7px;padding:5px 12px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap">+ Folder</button>
                </div>
                <!-- Tree -->
                <div id="mv-tree" style="border:1px solid #e2e8f0;border-radius:8px;background:#f8fafc;
                    height:240px;overflow-y:auto;padding:6px 4px"></div>
                <!-- Selected path display -->
                <div style="margin-top:8px;font-size:12px;color:#64748b">
                    Destination: <span id="mv-dest-label" style="font-weight:600;color:#1e293b">/</span>
                </div>
            </div>

            <!-- Rename tab body -->
            <div id="mv-tab-rename" style="display:none;padding:14px 20px 20px">
                <label style="display:block;font-size:13px;color:#64748b;margin-bottom:6px">New name (filename only, no slashes):</label>
                <input id="mv-name-input" type="text" value="${escapeHtmlAttr(srcName)}" spellcheck="false" autocomplete="off">
                <div style="font-size:12px;color:#94a3b8;margin-top:6px">The file stays in its current folder. To also move it, use the Move tab.</div>
            </div>

            <!-- Footer -->
            <div style="padding:12px 20px 18px;display:flex;gap:8px;justify-content:flex-end;border-top:1px solid #f1f5f9">
                <button id="mv-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">Cancel</button>
                <button id="mv-confirm-btn" class="btn" style="background:#3b82f6;min-width:110px">Move here</button>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    // ── State ──────────────────────────────────────────────────────────────
    let activeTab   = 'move';
    let destFolder  = srcDir;  // currently selected destination for move/copy
    // tree: path → { children: Map, loaded: bool, expanded: bool }
    const treeData  = new Map();

    // ── Helpers ────────────────────────────────────────────────────────────
    const $ = id => overlay.querySelector('#' + id);

    // Smoothly animate the dialog panel's height when its content changes size
    // (e.g. switching between the tall Move tree and the short Rename form).
    const _mvPanel = overlay.querySelector('.modal-content');
    function _mvAnimateHeight(mutate) {
        if (!_mvPanel) { mutate(); return; }
        const startH = _mvPanel.getBoundingClientRect().height;
        mutate();
        const endH = _mvPanel.getBoundingClientRect().height;
        if (Math.abs(startH - endH) < 2) return;
        const prevOverflow = _mvPanel.style.overflow; // panel ships with overflow:hidden — preserve it
        _mvPanel.style.overflow = 'hidden';
        _mvPanel.style.height = startH + 'px';
        void _mvPanel.offsetHeight; // force reflow so the start height sticks
        _mvPanel.style.transition = 'height .22s cubic-bezier(.4,0,.2,1)';
        _mvPanel.style.height = endH + 'px';
        const cleanup = e => {
            if (e && e.type === 'transitionend' && e.propertyName !== 'height') return;
            _mvPanel.style.transition = '';
            _mvPanel.style.height = '';
            _mvPanel.style.overflow = prevOverflow;
            _mvPanel.removeEventListener('transitionend', cleanup);
        };
        _mvPanel.addEventListener('transitionend', cleanup);
        setTimeout(cleanup, 300); // safety net if transitionend doesn't fire
    }

    function setTab(tab) {
        activeTab = tab;
        overlay.querySelectorAll('.mv-tab').forEach(b => {
            b.classList.toggle('mv-active', b.dataset.tab === tab);
        });
        _mvAnimateHeight(() => {
            $('mv-tab-move').style.display   = (tab === 'move' || tab === 'copy') ? '' : 'none';
            $('mv-tab-rename').style.display = (tab === 'rename') ? '' : 'none';
        });
        const confirmBtn = $('mv-confirm-btn');
        if (tab === 'move')   { confirmBtn.textContent = t('mv_move_here');  confirmBtn.style.background = '#3b82f6'; }
        if (tab === 'copy')   { confirmBtn.textContent = t('mv_copy_here');  confirmBtn.style.background = '#0ea5e9'; }
        if (tab === 'rename') { confirmBtn.textContent = t('mv_rename_btn'); confirmBtn.style.background = '#8b5cf6'; }
    }

    function updateDestLabel() {
        $('mv-dest-label').textContent = destFolder || '/';
    }

    // ── Tree rendering ─────────────────────────────────────────────────────
    function getNode(path) {
        if (!treeData.has(path)) treeData.set(path, { children: [], loaded: false, expanded: false, loading: false });
        return treeData.get(path);
    }

    async function loadChildren(path) {
        const node = getNode(path);
        if (node.loaded || node.loading) return;
        node.loading = true;
        try {
            const ep = path === '/' ? '/api/v1/list/' : `/api/v1/list${encodePath(path)}`;
            const data = await apiCall(ep, 'GET', null, true);
            node.children = (data.entries || [])
                .filter(e => e.is_dir)
                .map(e => e.path)
                .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
            node.loaded = true;
        } catch {
            node.children = [];
            node.loaded = true;
        }
        node.loading = false;
    }

    function buildTreeHTML(paths, depth) {
        return paths.map(p => {
            const node     = getNode(p);
            const label    = p.split('/').pop() || p;
            const isSelected = p === destFolder;
            const hasKids  = node.loaded ? node.children.length > 0 : true; // assume expandable until loaded
            const expandIcon = node.loading ? '⟳'
                : !hasKids && node.loaded ? '·'
                : node.expanded ? '▾' : '▸';
            return `<div class="mv-tree-row${isSelected ? ' mv-selected' : ''}"
                        data-path="${escapeHtmlAttr(p)}"
                        style="padding-left:${8 + depth * 16}px">
                    <button class="mv-expand-btn" data-expand="${escapeHtmlAttr(p)}">${expandIcon}</button>
                    <span class="mv-tree-label" title="${escapeHtmlAttr(p)}">📁 ${escapeHtml(label)}</span>
                </div>
                ${node.expanded && node.children.length > 0 ? buildTreeHTML(node.children, depth + 1) : ''}`;
        }).join('');
    }

    async function renderTree() {
        const treeEl = $('mv-tree');
        if (!treeEl) return;
        const root = getNode('/');
        if (!root.loaded) {
            treeEl.innerHTML = '<div style="padding:12px;color:#64748b;font-size:13px">Loading…</div>';
            await loadChildren('/');
            root.expanded = true;
        }
        // Also auto-expand the path to srcDir so the user can see where they are
        treeEl.innerHTML = `
            <div class="mv-tree-row${destFolder === '/' ? ' mv-selected' : ''}" data-path="/"
                style="padding-left:8px;font-weight:600">
                <button class="mv-expand-btn" data-expand="/">▾</button>
                <span class="mv-tree-label">🏠 / (root)</span>
            </div>
            ${buildTreeHTML(root.children, 1)}`;
        attachTreeListeners();
    }

    function attachTreeListeners() {
        const treeEl = $('mv-tree');
        if (!treeEl) return;
        // Row select
        treeEl.querySelectorAll('.mv-tree-row').forEach(row => {
            row.addEventListener('click', e => {
                if (e.target.classList.contains('mv-expand-btn')) return;
                destFolder = row.dataset.path;
                updateDestLabel();
                renderTree();
            });
        });
        // Expand toggle
        treeEl.querySelectorAll('.mv-expand-btn').forEach(btn => {
            btn.addEventListener('click', async e => {
                e.stopPropagation();
                const p    = btn.dataset.expand;
                const node = getNode(p);
                if (!node.loaded) {
                    await loadChildren(p);
                    node.expanded = true;
                } else {
                    node.expanded = !node.expanded;
                }
                renderTree();
            });
        });
    }

    // ── New folder creation inside tree ───────────────────────────────────
    $('mv-new-folder-btn').addEventListener('click', async () => {
        const nameInput = $('mv-new-folder-input');
        const name = nameInput.value.trim();
        if (!name) return;
        const newPath = (destFolder.endsWith('/') ? destFolder : destFolder + '/') + name;
        try {
            await apiCall('/api/v1/mkdir', 'POST', { path: newPath }, true);
            nameInput.value = '';
            // Invalidate parent so it reloads
            const node = getNode(destFolder);
            node.loaded = false;
            node.expanded = true;
            await loadChildren(destFolder);
            // Select the new folder
            destFolder = newPath;
            updateDestLabel();
            renderTree();
        } catch (err) {
            showMessage('Create folder failed', err.message);
        }
    });
    $('mv-new-folder-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') $('mv-new-folder-btn').click();
    });

    // ── Tab switching ──────────────────────────────────────────────────────
    overlay.querySelectorAll('.mv-tab').forEach(btn => {
        btn.addEventListener('click', () => setTab(btn.dataset.tab));
    });

    // ── Confirm ────────────────────────────────────────────────────────────
    $('mv-confirm-btn').addEventListener('click', async () => {
        const confirmBtn = $('mv-confirm-btn');
        if (!overlay.isConnected) return;

        if (activeTab === 'rename') {
            const newName = $('mv-name-input').value.trim();
            if (!newName || newName.includes('/')) {
                showMessage(t('mv_invalid_name_title'), t('mv_invalid_name_body')); return;
            }
            const newPath = srcDir === '/' ? '/' + newName : srcDir + '/' + newName;
            confirmBtn.disabled = true; confirmBtn.textContent = t('mv_renaming');
            const _rnDismiss = showSpinnerOverlay(t('mv_renaming'), { minMs: 1000 });
            try {
                await withMinDelay(apiCall('/api/v1/rename', 'POST', { old: srcPath, new: newPath }), 1000);
                _rnDismiss(); overlay.remove();
                _dropSelectedUnder(srcPath); _updateSelBar();
                loadDirectory(currentPath);
            } catch (err) {
                _rnDismiss(); confirmBtn.disabled = false; confirmBtn.textContent = t('mv_rename_btn');
                if (err.message !== 'SESSION_EXPIRED') showMessage(t('mv_rename_failed_title'), err.message);
            }
            return;
        }

        // Move or Copy
        if (!destFolder) { showMessage(t('mv_no_destination_title'), t('mv_no_destination_body')); return; }
        const newPath = (destFolder.endsWith('/') ? destFolder : destFolder + '/') + srcName;
        if (activeTab === 'move') {
            if (newPath === srcPath) { showMessage(t('mv_same_location_title'), t('mv_same_location_body')); return; }
            confirmBtn.disabled = true; confirmBtn.textContent = t('mv_moving');
            const _mvDismiss = showSpinnerOverlay(t('mv_moving'), { minMs: 1000 });
            try {
                await withMinDelay(apiCall('/api/v1/rename', 'POST', { old: srcPath, new: newPath }), 1000);
                _mvDismiss(); overlay.remove();
                _dropSelectedUnder(srcPath); _updateSelBar();
                loadDirectory(currentPath);
            } catch (err) {
                _mvDismiss(); confirmBtn.disabled = false; confirmBtn.textContent = t('mv_move_here');
                if (err.message !== 'SESSION_EXPIRED') showMessage(t('mv_move_failed_title'), err.message);
            }
        } else {
            // Copy — runs as an async background job server-side now (large
            // copies were blowing past the reverse proxy's socket timeout
            // even though the copy itself kept succeeding). The POST only
            // does fast validation and returns a job id immediately, so the
            // modal closes right away and a sticky progress toast tracks the
            // actual transfer via polling instead of staying open/blocked.
            if (newPath === srcPath) { showMessage(t('mv_same_location_title'), t('mv_same_location_body')); return; }
            confirmBtn.disabled = true; confirmBtn.textContent = t('mv_copying');
            try {
                const res = await apiCall('/api/v1/copy', 'POST', { src: srcPath, dest: newPath });
                overlay.remove();
                const fname = srcPath.split('/').filter(Boolean).pop() || srcPath;
                _startCopyJobTracking(res.job_id, fname);
            } catch (err) {
                confirmBtn.disabled = false; confirmBtn.textContent = t('mv_copy_here');
                if (err.message !== 'SESSION_EXPIRED') showMessage(t('mv_copy_failed_title'), err.message);
            }
        }
    });

    // ── Close / cancel ─────────────────────────────────────────────────────
    const _mvClose = () => { window.fdCloseOverlay(overlay); _detachModalKeys(); };
    $('mv-cancel-btn').addEventListener('click', _mvClose);
    $('mv-close').addEventListener('click', _mvClose);

    // P12: Enter confirms the active tab action; Escape closes the dialog.
    // Re-attach whenever the tab changes so the correct action fires.
    function _attachMvKeys() {
        _attachModalKeys(
            () => { if (overlay.isConnected) $('mv-confirm-btn').click(); },
            _mvClose
        );
    }
    overlay.querySelectorAll('.mv-tab').forEach(btn => {
        btn.addEventListener('click', () => _attachMvKeys());
    });
    _attachMvKeys();   // attach immediately on open

    // Also let Enter submit the rename input directly (feels natural)
    $('mv-name-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); $('mv-confirm-btn').click(); }
    });
    overlay.addEventListener('click', e => { if (e.target === overlay) _mvClose(); });

    // ── Initial render ─────────────────────────────────────────────────────
    updateDestLabel();
    // Pre-expand the path to the source file's parent for convenience
    async function preExpand(targetDir) {
        // Walk segments and load each
        const segments = targetDir.split('/').filter(Boolean);
        let cur = '/';
        getNode('/').expanded = true;
        await loadChildren('/');
        for (const seg of segments) {
            cur = cur === '/' ? '/' + seg : cur + '/' + seg;
            const node = getNode(cur);
            node.expanded = true;
            await loadChildren(cur);
        }
    }
    preExpand(srcDir).then(() => renderTree());
}

async function promptCreateFolder() {
    const name = await showPromptModal({
        title: t('create_folder_title'),
        label: t('folder_name_label'),
        defaultValue: 'NewFolder',
        confirmLabel: t('create'),
    });
    if (!name) return;
    try {
        let targetPath = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
        await apiCall('/api/v1/mkdir', 'POST', { path: targetPath }, true);
        showToast(t('folder_created_toast', { name }));
        loadDirectory(currentPath);
    } catch (err) {
        try {
            const fd = new FormData();
            fd.append('fileToUpload', new Blob(['']), '.placeholder');
            let endpointPath = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
            const endpoint = '/api/v1/upload/' + encodePath(endpointPath);
            await uploadFormData(endpoint, fd);
            showToast(t('folder_created_toast', { name }));
            loadDirectory(currentPath);
        } catch (err2) {
            showMessage(t('create_folder_failed'), err.message || String(err2));
        }
    }
}

        // ======================================================================
        // --- CHUNKED UPLOAD ENGINE ---
        // ======================================================================
// Anon device tokens for share uploads are stored in localStorage so the
// same device can resume an interrupted upload. Cross-device resume is
// not supported for anonymous callers — they'd need the token.
const ANON_TOKEN_KEY_PREFIX = 'fluxdrop_anon_upload_';

function saveAnonDeviceToken(uploadToken, anonDeviceToken) {
    try { localStorage.setItem(ANON_TOKEN_KEY_PREFIX + uploadToken, anonDeviceToken); } catch {}
}
function loadAnonDeviceToken(uploadToken) {
    try { return localStorage.getItem(ANON_TOKEN_KEY_PREFIX + uploadToken) || null; } catch { return null; }
}
function removeAnonDeviceToken(uploadToken) {
    try { localStorage.removeItem(ANON_TOKEN_KEY_PREFIX + uploadToken); } catch {}
}

// ── Interrupted upload persistence ─────────────────────────────────
// Stores { uploadToken, filename, destRel, totalChunks, chunkSize,
//          nextChunkIdx, ownerType, shareToken, anonDeviceToken, total }
// keyed by 'fluxdrop_interrupted_<uploadToken>'
const INTERRUPTED_KEY_PREFIX = 'fluxdrop_interrupted_';

function saveInterruptedUpload(uploadToken, meta) {
    try { localStorage.setItem(INTERRUPTED_KEY_PREFIX + uploadToken, JSON.stringify(meta)); } catch {}
}
function loadInterruptedUpload(uploadToken) {
    try { const v = localStorage.getItem(INTERRUPTED_KEY_PREFIX + uploadToken); return v ? JSON.parse(v) : null; } catch { return null; }
}
function removeInterruptedUpload(uploadToken) {
    try { localStorage.removeItem(INTERRUPTED_KEY_PREFIX + uploadToken); } catch {}
}
function getAllInterruptedUploads() {
    const out = [];
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            if (k && k.startsWith(INTERRUPTED_KEY_PREFIX)) {
                try { out.push(JSON.parse(localStorage.getItem(k))); } catch {}
            }
        }
    } catch {}
    return out;
}

/**
 * Upload a File using the resumable chunked upload API.
 * Supports pause/resume/cancel and survives page reloads (user uploads only).
 *
 * @param {File}   file
 * @param {string} destRel      - Path relative to owner root
 * @param {object} [opts]
 * @param {string} [opts.ownerType]       - 'user' (default) | 'share' | 'catbox'
 * @param {string} [opts.shareToken]      - required when ownerType === 'share'
 * @param {boolean} [opts.protected]      - mark upload as protected (user uploads only)
 * @param {string}  [opts.resumeToken]    - existing upload_token to resume
 * @param {number}  [opts.resumeFromChunk]- first chunk index to send when resuming
 * @param {number}  [opts.resumeChunkSize]- chunk size stored from original session
 * @param {string}  [opts.resumeAnonToken]- anon_device_token for share resumes
 * @returns {Promise<{url, sha256, size}>}
 */
// Maps a measured upload speed (bytes/sec) to a sane initial concurrency.
// Used both to divide the per-chunk-duration target by the bandwidth each
// concurrent stream will actually get (see the chunk-size calculation in
// uploadChunked) and to seed the real worker concurrency later — keeping
// the two numbers consistent. A genuinely narrow connection needs to stay
// at concurrency 1: splitting an already-thin pipe across several streams
// doesn't add throughput, it just makes each individual chunk take longer
// to finish than the timeout budget it was sized for.
function _concurrencyForSpeed(bytesPerSec) {
    if (!bytesPerSec || bytesPerSec <= 0) return 3; // no probe data — previous default
    const KBps = bytesPerSec / 1024;
    if (KBps < 100)   return 1;  // very slow — single stream, don't fragment the pipe
    if (KBps < 500)   return 2;
    if (KBps < 2000)  return 3;
    if (KBps < 5000)  return 4;
    return 6; // CONCURRENCY_MAX
}

async function uploadChunked(file, destRel, opts = {}) {
    const ownerType  = opts.ownerType  || 'user';
    const shareToken = opts.shareToken  || '';

    // ── Build auth headers ──────────────────────────────────────────
    function authHeaders(anonDeviceToken) {
        const h = {};
        if (authToken) h['Authorization'] = `Bearer ${authToken}`;
        if (anonDeviceToken) h['X-Anon-Device-Token'] = anonDeviceToken;
        return h;
    }

    let uploadToken, anonDeviceToken, chunkSize, totalChunks, startIdx, measuredSpeed = null;

    if (opts.resumeToken) {
        // ── Resuming an existing session ────────────────────────────
        uploadToken     = opts.resumeToken;
        anonDeviceToken = opts.resumeAnonToken || loadAnonDeviceToken(uploadToken) || null;
        chunkSize       = opts.resumeChunkSize || 1 * 1024 * 1024;
        totalChunks     = file.size === 0 ? 0 : (Math.ceil(file.size / chunkSize) || 1);
        startIdx        = opts.resumeFromChunk || 0;
    } else {
        // ── Config + speed probe — run in parallel so no sequential wait ──
        // Speed probe: POST 512 KB of zeros, measure round-trip to seed ETA.
        // Config fetch: get server chunk size.
        // Both fire simultaneously so total wait ≈ max(config_rtt, probe_rtt).
        const PROBE_SIZE = 512 * 1024; // 512 KB

        const [cfgResult, probeResult] = await Promise.allSettled([
            fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/config`, {
                headers: authHeaders(null),
            }).then(r => r.ok ? r.json() : null).catch(() => null),

            (async () => {
                const probeData = new Uint8Array(PROBE_SIZE); // zeros, no disk read
                const t0 = performance.now();
                const res = await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/speed_probe`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/octet-stream',
                                'Content-Length': String(PROBE_SIZE),
                                ...authHeaders(null) },
                    body: probeData,
                });
                const elapsed = (performance.now() - t0) / 1000;
                if (res.ok && elapsed > 0) return PROBE_SIZE / elapsed; // bytes/sec
                return null;
            })(),
        ]);

        const cfg       = cfgResult.status === 'fulfilled' ? cfgResult.value : null;
        const probeSpeed = probeResult.status === 'fulfilled' ? probeResult.value : null;

        let serverChunkSize = (cfg && cfg.chunk_size) ? cfg.chunk_size : 1 * 1024 * 1024;

        // Adaptive chunk size: aim for a chunk that takes roughly 20s to
        // transfer — comfortably inside uploadChunk's 90s per-chunk timeout
        // even with margin for jitter — at the bandwidth each concurrent
        // stream will actually get, not the full measured speed as if a
        // single stream had it all to itself. Chunks upload multi-streamed
        // (see the concurrency pool below), so on a slow connection with
        // several streams running at once, each one only gets a fraction of
        // the measured aggregate — sizing purely off the raw measured speed
        // undersells how long an individual chunk will really take and can
        // still time out even though the math "looked" safe.
        // Falls back to the server's default when the probe itself failed
        // (probeSpeed === null) rather than guessing. The server clamps
        // this independently too (see handle_upload_session_init's
        // _MIN_CHUNK_SIZE / UPLOAD_CHUNK_SIZE*2 bounds) — this client-side
        // clamp just avoids sending something wildly out of range in the
        // first place.
        const TARGET_CHUNK_SECONDS = 20;
        const MIN_CHUNK_SIZE = 32 * 1024;                      // 32 KB floor
        const maxChunkSize   = (cfg && cfg.max_chunk_size) ? cfg.max_chunk_size : serverChunkSize;
        const expectedConcurrency = _concurrencyForSpeed(probeSpeed);
        const perStreamSpeed = probeSpeed ? probeSpeed / expectedConcurrency : null;
        let preferredChunkSize = null;
        if (perStreamSpeed) {
            preferredChunkSize = Math.round(
                Math.max(MIN_CHUNK_SIZE, Math.min(perStreamSpeed * TARGET_CHUNK_SECONDS, maxChunkSize))
            );
        }
        const effectiveChunkSize = preferredChunkSize || serverChunkSize;

        // ── Init session (no blocking whole-file SHA — server verifies after assembly) ──
        const tentativeTotalChunks = file.size === 0 ? 0 : (Math.ceil(file.size / effectiveChunkSize) || 1);
        const initBody = {
            filename:             file.name,
            dest_path:            destRel,
            total_size:           file.size,
            total_chunks:         tentativeTotalChunks,
            preferred_chunk_size: preferredChunkSize,
            sha256:               null,
            owner_type:           ownerType,
            share_token:          shareToken,
        };
        const initRes = await fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/init`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...authHeaders(null) },
            body: JSON.stringify(initBody),
        });
        if (!initRes.ok) {
            const err = await initRes.json().catch(() => ({}));
            throw new Error(err.error || `Init failed: HTTP ${initRes.status}`);
        }
        const initData = await initRes.json();
        uploadToken     = initData.upload_token;
        chunkSize       = initData.chunk_size || serverChunkSize;
        totalChunks     = file.size === 0 ? 0 : (Math.ceil(file.size / chunkSize) || 1);
        startIdx        = 0;
        anonDeviceToken = initData.anon_device_token || null;
        if (anonDeviceToken) saveAnonDeviceToken(uploadToken, anonDeviceToken);
        measuredSpeed   = probeSpeed; // carry real measured speed into ul for ETA seed
    }

    // ── Register in active uploads map ──────────────────────────────
    // On resume, reuseId lets us update the existing tray row in-place
    // instead of creating a duplicate entry with a new id.
    const id = (opts.reuseId != null) ? opts.reuseId : ++uploadIdCounter;
    const ul = activeUploads.get(id) || {
        filename: file.name,
        loaded: startIdx * chunkSize,
        total: file.size,
        status: 'uploading',
        speed: null, eta: null, error: null,
        measuredSpeed,
        paused: false,
        cancelled: false,
        abortController: null,
        uploadToken,
        anonDeviceToken,
        chunkSize,
        totalChunks,
        nextChunk: startIdx,
        destRel,
        ownerType,
        shareToken,
        file,
    };
    // Refresh mutable fields on resume
    ul.status    = 'uploading';
    ul.paused    = false;
    ul.cancelled = false;
    ul.uploadToken    = uploadToken;
    ul.anonDeviceToken = anonDeviceToken;
    ul.chunkSize  = chunkSize;
    ul.totalChunks = totalChunks;
    ul.nextChunk  = startIdx;
    if (measuredSpeed) ul.measuredSpeed = measuredSpeed;
    activeUploads.set(id, ul);

    // Persist to localStorage so page reloads can offer recovery (user uploads only)
    if (ownerType === 'user') {
        saveInterruptedUpload(uploadToken, {
            uploadToken, filename: file.name, destRel, totalChunks,
            chunkSize, nextChunkIdx: startIdx, ownerType, shareToken,
            anonDeviceToken: null, total: file.size,
        });
    }

    // Seed speed from probe so first-chunk ETA is meaningful immediately
    if (ul.measuredSpeed && ul.measuredSpeed > 0) ul.speed = ul.measuredSpeed;
    renderUploadTray();

    // ── Parallel chunk upload loop ──────────────────────────────────
    // Concurrency is adaptive: starts from the speed probe result, then
    // self-tunes every 3 s by watching the EWA speed trend.
    // Min 1, max 6. (8 was too aggressive for i3 370m + HDD.)
    const CONCURRENCY_MIN = 1;
    const CONCURRENCY_MAX = 6;

    // Seed from the measured probe speed via the same _concurrencyForSpeed
    // tiering used for the chunk-size calculation above, so the two stay
    // consistent. Previously this was seeded from chunkSize alone ("target
    // ~50MB in-flight / chunkSize") — for a small chunk size correctly
    // chosen for a slow connection, that formula computed the MAXIMUM
    // concurrency, fragmenting an already-thin pipe across up to 6 streams
    // and making each individual chunk take far longer than the timeout
    // budget it was sized for, even though the raw chunk-size math looked
    // safe for a single stream.
    let concurrency = _concurrencyForSpeed(ul.measuredSpeed);

    let _activeWorkerCount = 0;
    let _workerLaunchFn    = null;
    let _tunerLastSpeed    = ul.speed || 0;
    let _tunerTimer        = null;

    function _startConcurrencyTuner() {
        if (_tunerTimer) return;
        _tunerTimer = setInterval(() => {
            if (ul.cancelled || uploadError) { clearInterval(_tunerTimer); _tunerTimer = null; return; }
            if (ul.paused) return; // don't tune while paused
            const cur = ul.speed || 0;
            if (_tunerLastSpeed > 0 && cur > 0) {
                const ratio = cur / _tunerLastSpeed;
                if (ratio < 0.85 && concurrency > CONCURRENCY_MIN) {
                    // Speed dropped >15 % — back off one worker
                    concurrency = Math.max(CONCURRENCY_MIN, concurrency - 1);
                } else if (ratio >= 0.95 && concurrency < CONCURRENCY_MAX
                           && _activeWorkerCount < concurrency + 1
                           && nextIdx < totalChunks) {
                    // Speed stable/rising — try adding one more worker
                    concurrency++;
                    if (_workerLaunchFn) _workerLaunchFn();
                }
            }
            _tunerLastSpeed = cur;
        }, 3000);
    }

    // Per-chunk XHR registry so cancel aborts ALL in-flight XHRs, not just the last one
    const activeXhrs = new Map(); // idx -> xhr

    // ── Shared EWA rate sampler ─────────────────────────────────────
    // All concurrent XHR progress events feed raw bytes into one sampler
    // that emits a smoothed speed (exponential weighted average) every 800ms.
    // This eliminates per-chunk speed jitter from concurrent uploads.
    let samplerLoaded   = startIdx * chunkSize; // bytes confirmed sent at start
    let samplerLastTime = Date.now();
    let samplerLastSnap = samplerLoaded;
    const EWA_ALPHA     = 0.25; // smoothing factor: lower = smoother but slower to react
    const SAMPLE_MS     = 800;  // minimum ms between speed recalculations

    function samplerOnBytes(delta) {
        // Thread-safe: JavaScript is single-threaded; no mutex needed.
        // Clamped on both ends: ceiling so a burst of progress events can't
        // report more than the file's actual size, floor so a rollback (see
        // uploadChunk's failure paths below) can't push it negative.
        samplerLoaded = Math.max(0, Math.min(file.size, samplerLoaded + delta));
        ul.loaded     = samplerLoaded;

        const now = Date.now();
        const dt  = now - samplerLastTime;
        if (dt >= SAMPLE_MS) {
            const rawSpeed = (samplerLoaded - samplerLastSnap) / (dt / 1000);
            if (rawSpeed > 0) {
                // EWA: blend new measurement with previous
                ul.speed = ul.speed != null
                    ? EWA_ALPHA * rawSpeed + (1 - EWA_ALPHA) * ul.speed
                    : rawSpeed;
                ul.eta = (file.size - samplerLoaded) / ul.speed;
            }
            samplerLastSnap = samplerLoaded;
            samplerLastTime = now;
        }
        renderUploadTray();
    }

    // Per-chunk SHA-256 using SubtleCrypto (async, zero-copy, works in both
    // Firefox and Chromium).  Returns hex string.
    async function chunkSha256(blob) {
        const buf    = await blob.arrayBuffer();
        const digest = await crypto.subtle.digest('SHA-256', buf);
        return Array.from(new Uint8Array(digest))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function uploadChunk(idx) {
        const start = idx * chunkSize;
        const blob  = file.slice(start, start + chunkSize);

        // Compute SHA-256 before sending so the server can reject corrupt data
        // immediately. SubtleCrypto reads the blob in a worker thread; for 1 MB
        // chunks this takes <5 ms on modern hardware and runs in parallel with
        // the previous chunk's XHR, so it adds no measurable latency.
        let chunkHash = null;
        try { chunkHash = await chunkSha256(blob); } catch (_) { /* non-fatal */ }

        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            activeXhrs.set(idx, xhr);

            // Expose a cancel handle that aborts ALL concurrent XHRs
            ul.abortController = {
                abort: () => { activeXhrs.forEach(x => x.abort()); }
            };

            let chunkSentPrev = 0; // bytes already fed to sampler from this XHR attempt

            // Roll back whatever THIS attempt has credited to the shared
            // progress sampler so far. Called on every non-success
            // termination path — a retried chunk needs to start crediting
            // progress from the same baseline as before this attempt began,
            // not stack failed-attempt bytes on top of each other across
            // retries.
            function rollBackCredit() {
                if (chunkSentPrev > 0) {
                    samplerOnBytes(-chunkSentPrev);
                    chunkSentPrev = 0;
                }
            }

            xhr.upload.onprogress = (e) => {
                if (!e.lengthComputable) return;
                const delta  = e.loaded - chunkSentPrev;
                chunkSentPrev = e.loaded;
                if (delta > 0) samplerOnBytes(delta);
            };

            xhr.onload = () => {
                activeXhrs.delete(idx);
                if (xhr.status >= 200 && xhr.status < 300) {
                    // Credit any tail bytes that landed after the last
                    // progress event but before onload fired — only
                    // meaningful (and only correct) on an actual success;
                    // this used to run unconditionally, crediting the whole
                    // chunk as "sent" even when the server rejected it.
                    const remaining = blob.size - chunkSentPrev;
                    if (remaining > 0) samplerOnBytes(remaining);
                    renderUploadTray();
                    resolve();
                } else {
                    rollBackCredit();
                    renderUploadTray();
                    let msg = `Chunk ${idx} failed: HTTP ${xhr.status}`;
                    try { const j = JSON.parse(xhr.responseText); if (j.error) msg = j.error; } catch {}
                    reject(new Error(msg));
                }
            };

            xhr.onerror = () => {
                activeXhrs.delete(idx);
                rollBackCredit();
                renderUploadTray();
                reject(new Error(`Chunk ${idx} network error`));
            };
            xhr.onabort = () => {
                activeXhrs.delete(idx);
                rollBackCredit();
                renderUploadTray();
                const e = new Error('Upload cancelled');
                e.name  = 'AbortError';
                reject(e);
            };

            xhr.open('POST', `${API_BASE_URL}/api/v1/upload_session/${uploadToken}/chunk/${idx}`);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            if (chunkHash) xhr.setRequestHeader('X-Chunk-SHA256', chunkHash);
            const ah = authHeaders(anonDeviceToken);
            for (const [k, v] of Object.entries(ah)) xhr.setRequestHeader(k, v);
            xhr.timeout = 90_000;  // 90 s; chunk should never take longer
            xhr.ontimeout = () => {
                activeXhrs.delete(idx);
                rollBackCredit();
                renderUploadTray();
                reject(new Error(`Chunk ${idx} timed out`));
            };
            xhr.send(blob);
        });
    }

    // Run chunks with a concurrency pool
    let nextIdx = startIdx;
    let uploadError = null;

    async function worker() {
        while (true) {
            // Pause: spin-wait until resumed or cancelled
            while (ul.paused && !ul.cancelled) {
                await new Promise(r => setTimeout(r, 200));
            }
            if (ul.cancelled || uploadError) return;

            const idx = nextIdx++;
            if (idx >= totalChunks) return;

            ul.nextChunk = idx;
            // Keep localStorage in sync so recovery knows the right restart point
            if (ownerType === 'user') {
                saveInterruptedUpload(uploadToken, {
                    uploadToken, filename: file.name, destRel, totalChunks,
                    chunkSize, nextChunkIdx: idx, ownerType, shareToken,
                    anonDeviceToken: null, total: file.size,
                });
            }

            try {
                await uploadChunk(idx);
            } catch (err) {
                if (err.name === 'AbortError') {
                    if (ul.paused && !ul.cancelled) {
                        if (idx < nextIdx) nextIdx = idx;
                        return;
                    }
                    ul.cancelled = true;
                    return;
                }
                if (ul.cancelled) return;
                // ── Retry loop: up to 3 retries with back-off, resuming from the
                // exact failed chunk index.  No page reload needed.
                const MAX_CHUNK_RETRIES = 3;
                let retryErr = err;
                for (let attempt = 1; attempt <= MAX_CHUNK_RETRIES; attempt++) {
                    if (ul.cancelled) return;
                    const backoff = 1500 * attempt; // 1.5s, 3s, 4.5s
                    ul.status    = 'uploading';
                    ul._retrying = true;
                    // Per-second countdown
                    for (let s = Math.round(backoff / 1000); s > 0; s--) {
                        if (ul.cancelled) return;
                        ul.error = `Chunk ${idx} failed. Retry ${attempt}/${MAX_CHUNK_RETRIES} in ${s}s…`;
                        renderUploadTray();
                        await new Promise(r => setTimeout(r, 1000));
                    }
                    ul._retrying = false;
                    if (ul.cancelled) return;
                    try {
                        await uploadChunk(idx);
                        retryErr     = null;
                        ul.error     = null;
                        ul._retrying = false;
                        break;
                    } catch (e2) {
                        retryErr = e2;
                        if (e2.name === 'AbortError') { ul.cancelled = true; return; }
                    }
                }
                if (retryErr) {
                    uploadError = retryErr;
                    ul.error   = retryErr.message;
                    // Persist the exact failed chunk so the interrupted-upload
                    // manager can offer resuming from here — not from chunk 0.
                    if (ownerType === 'user') {
                        saveInterruptedUpload(uploadToken, {
                            uploadToken, filename: file.name, destRel, totalChunks,
                            chunkSize, nextChunkIdx: idx, ownerType, shareToken,
                            anonDeviceToken: null, total: file.size,
                        });
                    }
                    return;
                }
            }
        }
    }

    // Launch adaptive worker pool and wait for all chunks to finish.
    _startConcurrencyTuner();
    await new Promise((resolvePool) => {
        let _poolDone = false;
        function _checkDone() {
            if (!_poolDone && _activeWorkerCount === 0) {
                _poolDone = true;
                clearInterval(_tunerTimer);
                _tunerTimer = null;
                resolvePool();
            }
        }
        _workerLaunchFn = function _spawnWorker() {
            if (ul.cancelled || uploadError || nextIdx >= totalChunks) { _checkDone(); return; }
            _activeWorkerCount++;
            worker().finally(() => { _activeWorkerCount--; _checkDone(); });
        };
        const initial = Math.min(concurrency, Math.max(0, totalChunks - startIdx));
        for (let i = 0; i < initial; i++) _workerLaunchFn();
        if (initial === 0) resolvePool(); // zero-chunk (empty) file
    });

    if (ul.paused && !ul.cancelled) {
        // Workers exited due to pause — don't complete, just leave state as paused.
        // nextIdx was backed up to the lowest aborted chunk index by the workers.
        ul.nextChunk = nextIdx;
        const e = new Error('Upload paused');
        e.name = 'PauseSignal';
        throw e;
    }
    if (ul.cancelled) {
        // Tell the server to clean up the tmp chunks — actually waited on
        // (bounded by a short timeout, since this is best-effort and
        // shouldn't hang the UI if the server is slow/unreachable) so
        // "Cancelled" only shows once the server has genuinely been told to
        // stop, not the instant the local abort() call returns.
        ul.status = 'cancelling';
        renderUploadTray();
        try {
            await Promise.race([
                fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${uploadToken}/cancel`, {
                    method: 'DELETE',
                    headers: authHeaders(anonDeviceToken),
                }),
                new Promise(r => setTimeout(r, 5000)),
            ]);
        } catch (_) { /* best-effort — proceed regardless */ }

        ul.status = 'cancelled';
        removeInterruptedUpload(uploadToken);
        if (anonDeviceToken) removeAnonDeviceToken(uploadToken);
        renderUploadTray();
        throw new Error('Upload cancelled');
    }
    if (uploadError) {
        ul.status = 'error';
        ul.error  = uploadError.message;
        renderUploadTray();
        if (anonDeviceToken) removeAnonDeviceToken(uploadToken);
        throw uploadError;
    }

    // ── Complete ────────────────────────────────────────────────────
    ul.status        = 'verifying';
    ul.speed         = null;
    ul.eta           = null;
    ul.verifyPct     = 0;
    ul.verifyEta     = null;
    ul.verifyBytes   = 0;
    ul.verifyTotal   = file.size;
    renderUploadTray();

    // Poll /assembly_progress while the server hashes the assembled file.
    // We compute client-side ETA using an EWA on the bytes_hashed deltas.
    let pollTimer = null;
    let verifySpeed = null;
    let verifyLastBytes = 0;
    let verifyLastTime  = Date.now();
    const EWA_V = 0.3;

    function startVerifyPoller() {
        if (pollTimer) return;
        pollTimer = setInterval(async () => {
            try {
                const r = await fetchWithFallback(
                    `${API_BASE_URL}/api/v1/upload_session/${uploadToken}/assembly_progress`,
                    { headers: authHeaders(anonDeviceToken) }
                );
                if (!r.ok) return;
                const p = await r.json();
                if (p.error) { clearInterval(pollTimer); return; }
                ul.verifyPct   = p.pct || 0;
                ul.verifyBytes = p.bytes_hashed || 0;
                ul.verifyTotal = p.total_bytes  || file.size;

                // EWA speed + ETA
                const now = Date.now();
                const dt  = (now - verifyLastTime) / 1000;
                if (dt >= 0.5 && ul.verifyBytes > verifyLastBytes) {
                    const raw = (ul.verifyBytes - verifyLastBytes) / dt;
                    verifySpeed   = verifySpeed != null
                        ? EWA_V * raw + (1 - EWA_V) * verifySpeed
                        : raw;
                    ul.verifyEta  = verifySpeed > 0
                        ? (ul.verifyTotal - ul.verifyBytes) / verifySpeed
                        : null;
                    verifyLastBytes = ul.verifyBytes;
                    verifyLastTime  = now;
                }
                renderUploadTray();
                if (p.done) { clearInterval(pollTimer); pollTimer = null; }
            } catch (_) { /* non-fatal — /complete will return the real result */ }
        }, 500);
    }
    startVerifyPoller();

    const completeRes = await fetchWithFallback(
        `${API_BASE_URL}/api/v1/upload_session/${uploadToken}/complete`,
        { method: 'POST', headers: authHeaders(anonDeviceToken) }
    );
    clearInterval(pollTimer);
    if (!completeRes.ok) {
        const err = await completeRes.json().catch(() => ({}));
        ul.status = 'error';
        ul.error  = err.error || `Complete failed: HTTP ${completeRes.status}`;
        renderUploadTray();
        if (anonDeviceToken) removeAnonDeviceToken(uploadToken);
        throw new Error(ul.error);
    }

    ul.loaded = file.size;
    ul.status = 'done';
    const delay = getTrayDismissDelay();
    if (delay > 0 && !ul._dismissScheduled) {
        ul._dismissScheduled = true;
        setTimeout(() => { activeUploads.delete(id); renderUploadTray(); }, delay);
    }
    ul.speed  = null;
    ul.eta    = null;
    renderUploadTray();
    removeInterruptedUpload(uploadToken);
    if (anonDeviceToken) removeAnonDeviceToken(uploadToken);

    return await completeRes.json();
}

function windowLock() {
    // Cancel the event as per the standard.
    event.preventDefault();
    // Included for legacy support and specific browser requirements (e.g., Chrome)
    event.returnValue = '';
}

async function handleUploadForm(e) {
    e.preventDefault();
    window.addEventListener('beforeunload', windowLock);

    const fileInput = document.getElementById('upload-file');
    if (!fileInput.files.length) { showMessage('Upload', 'No file selected'); return; }
    const files = Array.from(fileInput.files);
    const isProtected = document.getElementById('upload-protected').checked;
    const ownerType = currentPath.startsWith('/cdn') ? 'catbox' : 'user';

    // Show spinner between button press and first tray update
    const _ubtn = document.getElementById('btn-upload-submit');
    const _uspinner = document.getElementById('upload-spinner');
    function _showUploadSpinner() {
        if (_ubtn) { _ubtn.disabled = true; _ubtn.style.opacity = '0.6'; }
        if (_uspinner) _uspinner.style.display = 'inline';
    }
    function _hideUploadSpinner() {
        if (_ubtn) { _ubtn.disabled = false; _ubtn.style.opacity = ''; }
        if (_uspinner) _uspinner.style.display = 'none';
    }
    _showUploadSpinner();

    // Build queue items for all selected files.
    // When using webkitdirectory, f.webkitRelativePath gives the full relative path
    // including the folder name (e.g. "MyFolder/sub/file.txt"). We use that to
    // preserve the original directory structure under currentPath.
    const basePath = currentPath.endsWith('/') ? currentPath : currentPath + '/';
    const items = files.map(f => {
        const rel = f.webkitRelativePath || f.name;
        return { file: f, destRel: basePath + rel, ownerType, isProtected };
    });

    if (items.length === 1) {
        // Single file: start immediately
        try {
            const _p = uploadChunked(items[0].file, items[0].destRel, { ownerType });
            // Hide spinner as soon as the tray row is created (first renderUploadTray call)
            setTimeout(_hideUploadSpinner, 600);
            await _p;
            _hideUploadSpinner();
            _notifyUploadDone(1);   // P10
            showMessage('Upload successful', `${items[0].file.name} uploaded successfully.`);
            window.removeEventListener('beforeunload', windowLock);
            loadDirectory(currentPath);
        } catch (err) {
            _hideUploadSpinner();
            if (err.name === 'PauseSignal' || err.message === 'Upload cancelled') return;
            showMessage('Upload failed', err.message || String(err));
        }
    } else {
        // Multiple files: first file starts immediately, rest go to queue
        const [first, ...rest] = items;
        window._uploadQueue = [...(window._uploadQueue || []), ...rest];
        const refreshQ = () => {
            const btn = document.getElementById('btn-show-queue');
            const countEl = document.getElementById('queue-count');
            if (btn && countEl) {
                const q = window._uploadQueue;
                if (q.length > 0) { btn.classList.remove('hidden'); countEl.textContent = q.length; }
                else btn.classList.add('hidden');
            }
        };
        refreshQ();

        // Hide spinner as soon as queuing is done
        setTimeout(_hideUploadSpinner, 400);
        _lastUploadBatchCount += items.length;   // P10: count this batch
        // Start first immediately, then drain queue sequentially
        let _qOk = 0, _qFail = 0;
        function _finishQueue() {
            _notifyUploadDone(_qOk, _qFail);            // P10
            _lastUploadBatchCount = 0;                  // P10: reset for next batch
            window.removeEventListener('beforeunload', windowLock);
        }
        async function drainQueue(startItem) {
            let item = startItem;
            while (item) {
                try {
                    await uploadChunked(item.file, item.destRel, { ownerType: item.ownerType });
                    _qOk++;
                    loadDirectory(currentPath);
                } catch (err) {
                    if (err.name === 'PauseSignal') {
                        // Queue waits here until the paused item is resumed or
                        // cancelled (tray handlers call _pausedQueueDrain).
                        _pausedQueueDrain = () => {
                            _pausedQueueDrain = null;
                            let next = null;
                            if (window._uploadQueue && window._uploadQueue.length > 0) { next = window._uploadQueue.shift(); refreshQ(); }
                            if (next) drainQueue(next); else _finishQueue();
                        };
                        return;
                    }
                    if (err.message !== 'Upload cancelled') {
                        _qFail++;
                        showMessage('Upload failed', `${item.file.name}: ${err.message || String(err)}`);
                        window.removeEventListener('beforeunload', windowLock);
                    }
                }
                // Next from queue
                if (window._uploadQueue && window._uploadQueue.length > 0) {
                    item = window._uploadQueue.shift();
                    refreshQ();
                } else {
                    item = null;
                    _finishQueue();
                }
            }
        }
        drainQueue(first);
        showMessage('Queued', `${files.length} files queued. Uploading now…`);
    }

    // Reset the file input
    fileInput.value = '';
}

        // ======================================================================
        // --- UPLOAD MANAGER (progress-tracked) ---
        // ======================================================================
// Active uploads map: id -> { filename, loaded, total, status, error }
const activeUploads = new Map();
let uploadIdCounter = 0;

function formatSpeed(bps) {
    if (bps < 1024) return bps.toFixed(0) + ' B/s';
    if (bps < 1048576) return (bps / 1024).toFixed(1) + ' KB/s';
    if (bps < 1073741824) return (bps / 1048576).toFixed(1) + ' MB/s';
    return (bps / 1073741824).toFixed(2) + ' GB/s';
}

function formatEta(seconds) {
    if (!isFinite(seconds) || seconds < 0) return '…';
    if (seconds < 60) return Math.ceil(seconds) + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + Math.ceil(seconds % 60) + 's';
    return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
}

function renderUploadTray() {
    let tray = document.getElementById('ul-tray');
    if (!tray) {
        tray = document.createElement('div');
        tray.id = 'ul-tray';
        tray.style.cssText = `
            position:fixed; bottom:0; left:1rem; width:340px; max-height:60vh;
            overflow-y:auto; background:#1e293b; border-radius:12px 12px 0 0;
            box-shadow:0 -4px 24px rgba(0,0,0,0.4); z-index:9000;
            font-family:Inter,sans-serif; font-size:13px; color:#e2e8f0;
        `;
        document.body.appendChild(tray);
        tray.classList.add('fd-tray-in');
        tray.addEventListener('animationend', () => tray.classList.remove('fd-tray-in'), { once: true });
    }

    if (activeUploads.size === 0) {
        // Auto-hide (all uploads finished/cleared) gets the same slide-out
        // as the manual ✕ button, instead of an instant innerHTML wipe.
        if (tray.innerHTML.trim() !== '') {
            window.fdCollapseTray(tray).then(() => {
                // A new upload may have started while this was animating —
                // only actually clear if the tray is still meant to be empty.
                if (activeUploads.size === 0) tray.innerHTML = '';
            });
        }
        return;
    }
    // A new upload can start mid auto-hide-animation (see above) — cancel
    // any pending collapse so the tray doesn't fade out from under the rows
    // we're about to (re)populate below.
    tray.classList.remove('fd-tray-closing');

    // Header
    let header = tray.querySelector('.ul-tray-header');
    if (!header) {
        header = document.createElement('div');
        header.className = 'ul-tray-header';
        header.style.cssText = 'padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;';
        header.innerHTML = `<span class="ul-count"></span><span style="cursor:pointer;opacity:.6" id="ul-tray-close">✕</span>`;
        tray.prepend(header);
        header.querySelector('#ul-tray-close').addEventListener('click', async () => {
            await window.fdCollapseTray(tray);
            tray.innerHTML = '';
        });
    }
    header.querySelector('.ul-count').textContent = `📤 Uploads (${activeUploads.size})`;

    // Remove dismissed rows
    tray.querySelectorAll('.ul-row').forEach(row => {
        if (!activeUploads.has(+row.dataset.ulId)) row.remove();
    });

    for (const [id, ul] of activeUploads) {
        const pct = ul.total ? Math.round(ul.loaded / ul.total * 100) : 0;
        const sent = formatBytes(ul.loaded);
        const total = ul.total ? formatBytes(ul.total) : '?';

        let row = tray.querySelector(`.ul-row[data-ul-id="${+id}"]`);
        if (!row) {
            row = document.createElement('div');
            row.className = 'ul-row';
            row.dataset.ulId = id;
            row.style.cssText = 'padding:10px 14px;border-bottom:1px solid #1e293b';
            row.innerHTML = `
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="ul-name" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px"></span>
                    <span class="ul-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="ul-bar" style="background:#22c55e;height:6px;border-radius:4px;width:0%;transition:width .2s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="ul-status" style="color:#64748b"></span>
                    <div class="ul-actions"></div>
                </div>`;
            tray.appendChild(row);
            requestAnimationFrame(() => { tray.scrollTop = tray.scrollHeight; });  // auto-scroll to newest entry

            const actionsDiv = row.querySelector('.ul-actions');

            const dismissBtn = document.createElement('button');
            dismissBtn.textContent = t('dl_dismiss');
            dismissBtn.style.cssText = 'background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px';
            dismissBtn.addEventListener('click', () => { activeUploads.delete(id); renderUploadTray(); });

            const pauseBtn = document.createElement('button');
            pauseBtn.textContent = '⏸ Pause';
            pauseBtn.style.cssText = 'background:#f59e0b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px';
            pauseBtn.addEventListener('click', () => {
                ul.paused = true;
                ul.status = 'paused';
                // Abort in-flight XHRs immediately so we stop now, not after the current chunk finishes
                if (ul.abortController) ul.abortController.abort();
                renderUploadTray();
            });

            const resumeBtn = document.createElement('button');
            resumeBtn.textContent = '▶ Resume';
            resumeBtn.style.cssText = 'background:#22c55e;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px';
            resumeBtn.addEventListener('click', () => {
                ul.paused    = false;
                ul.cancelled = false;
                ul.status    = 'uploading';
                renderUploadTray();
                uploadChunked(ul.file, ul.destRel, {
                    ownerType:        ul.ownerType,
                    shareToken:       ul.shareToken,
                    resumeToken:      ul.uploadToken,
                    resumeFromChunk:  ul.nextChunk,
                    resumeChunkSize:  ul.chunkSize,
                    resumeAnonToken:  ul.anonDeviceToken,
                    reuseId:          id,
                }).then(() => {
                    loadDirectory(currentPath);
                    // This item finished — if a multi-file queue was parked
                    // waiting on it, let the rest of the queue drain now.
                    if (_pausedQueueDrain) _pausedQueueDrain();
                }).catch(err => {
                    if (err.name === 'PauseSignal') return;   // paused again — queue stays parked
                    if (err.message === 'Upload cancelled') { if (_pausedQueueDrain) _pausedQueueDrain(); return; }
                    showMessage('Upload failed', err.message);
                    if (_pausedQueueDrain) _pausedQueueDrain();
                });
            });

            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = '✕ Cancel';
            cancelBtn.style.cssText = 'background:#ef4444;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px';
            cancelBtn.addEventListener('click', () => {
                const wasPaused = ul.paused;
                ul.status = 'cancelling';
                renderUploadTray();
                ul.cancelled = true;
                ul.paused = false;
                if (ul.abortController) ul.abortController.abort();
                // If this item was paused, its uploadChunked() promise already
                // settled (PauseSignal) — nothing will fire _pausedQueueDrain
                // for us, so release any parked queue here.
                if (wasPaused && _pausedQueueDrain) _pausedQueueDrain();
            });

            // Pre-attach all buttons; visibility is toggled via display — never detached
            actionsDiv.appendChild(pauseBtn);
            actionsDiv.appendChild(resumeBtn);
            actionsDiv.appendChild(cancelBtn);
            actionsDiv.appendChild(dismissBtn);

            row._dismissBtn = dismissBtn;
            row._pauseBtn   = pauseBtn;
            row._resumeBtn  = resumeBtn;
            row._cancelBtn  = cancelBtn;
            row._actionsDiv = actionsDiv;
        }

        const statusMap = { uploading: '⬆', verifying: '🔍', done: '✅', error: '⚠', paused: '⏸', cancelling: '⏳', cancelled: '🚫' };
        row.querySelector('.ul-name').textContent = (statusMap[ul.status] || '') + ' ' + ul.filename;
        row.querySelector('.ul-bytes').textContent = `${sent} / ${total}`;
        const bar = row.querySelector('.ul-bar');
        // During verification use verifyPct for the bar so it visually advances
        const displayPct = (ul.status === 'verifying' && ul.verifyPct != null && ul.verifyPct > 0)
            ? ul.verifyPct
            : pct;
        bar.style.width = displayPct + '%';
        bar.style.background = ul._retrying ? '#f59e0b' : (ul.status === 'paused' || ul.status === 'cancelling') ? '#f59e0b' : ul.status === 'error' || ul.status === 'cancelled' ? '#ef4444' : ul.status === 'verifying' ? '#a78bfa' : '#22c55e';
        bar.style.animation  = ul._retrying ? 'fd-retry-pulse 1s ease-in-out infinite' : '';

        let statusText = ul.status;
        if (ul.status === 'uploading') {
            const parts = [];
            if (ul.speed != null) parts.push(formatSpeed(ul.speed));
            if (ul.eta != null) parts.push('ETA ' + formatEta(ul.eta));
            if (parts.length) {
                statusText = parts.join(' · ');
            } else if (ul._retrying && ul.error) {
                statusText = '🔄 ' + ul.error; // live retry countdown
            }
        } else if (ul.status === 'verifying') {
            // Show real progress if the poller has data, otherwise generic label
            if (ul.verifyPct != null && ul.verifyPct > 0) {
                const vParts = [`🔍 Verifying… ${ul.verifyPct.toFixed(0)}%`];
                if (ul.verifyEta != null) vParts.push('ETA ' + formatEta(ul.verifyEta));
                if (ul.verifyBytes && ul.verifyTotal) {
                    vParts.push(`${formatBytes(ul.verifyBytes)} / ${formatBytes(ul.verifyTotal)}`);
                }
                statusText = vParts.join(' · ');
            } else {
                statusText = '🔍 Verifying integrity…';
            }
        } else if (ul.status === 'paused') {
            statusText = '⏸ Paused — click Resume to continue';
        } else if (ul.status === 'cancelling') {
            statusText = '⏳ Cancelling…';
        } else if (ul.status === 'error') {
            statusText = '⚠ ' + (ul.error || 'failed');
        } else if (ul.status === 'cancelled') {
            statusText = '🚫 Cancelled';
        }
        row.querySelector('.ul-status').textContent = statusText;

        // Toggle visibility without detaching (prevents lost-click during rapid renders)
        const isUploading = ul.status === 'uploading' || ul.status === 'verifying';
        const isPaused    = ul.status === 'paused';
        const isFinished  = ul.status === 'done' || ul.status === 'error' || ul.status === 'cancelled';
        row._pauseBtn.style.display   = isUploading          ? '' : 'none';
        row._resumeBtn.style.display  = isPaused             ? '' : 'none';
        row._cancelBtn.style.display  = (isUploading || isPaused) ? '' : 'none';
        row._dismissBtn.style.display = isFinished           ? '' : 'none';
    }
}

function uploadFormData(endpoint, formData) {
    return new Promise((resolve, reject) => {
        const id = ++uploadIdCounter;
        const filename = (() => {
            for (const [, v] of formData.entries()) {
                if (v instanceof File) return v.name;
            }
            return 'file';
        })();

        const ul = { filename, loaded: 0, total: 0, status: 'uploading', speed: null, eta: null, error: null };
        activeUploads.set(id, ul);
        renderUploadTray();

        const xhr = new XMLHttpRequest();
        let startTime = Date.now();
        let lastLoaded = 0;
        let lastTime = startTime;

        xhr.upload.addEventListener('progress', e => {
            ul.loaded = e.loaded;
            ul.total = e.total || 0;

            const now = Date.now();
            const dt = (now - lastTime) / 1000;
            if (dt >= 0.5) {
                const bytesInWindow = e.loaded - lastLoaded;
                ul.speed = bytesInWindow / dt;
                ul.eta = ul.speed > 0 && ul.total ? (ul.total - e.loaded) / ul.speed : null;
                lastLoaded = e.loaded;
                lastTime = now;
            }
            renderUploadTray();
        });

        xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                ul.loaded = ul.total;
                ul.status = 'done';
                const delay = getTrayDismissDelay();
                if (delay > 0 && !ul._dismissScheduled) {
                    ul._dismissScheduled = true;
                    setTimeout(() => { activeUploads.delete(id); renderUploadTray(); }, delay);
                }
                ul.speed = null;
                ul.eta = null;
                renderUploadTray();
                try { resolve(JSON.parse(xhr.responseText)); } catch { resolve(xhr.responseText); }
            } else {
                ul.status = 'error';
                ul.error = `HTTP ${xhr.status}`;
                renderUploadTray();
                reject(new Error(`Upload failed: ${xhr.status}`));
            }
        });

        xhr.addEventListener('error', () => {
            // Try HTTP fallback
            const xhrFallback = new XMLHttpRequest();
            xhrFallback.upload.addEventListener('progress', e => {
                ul.loaded = e.loaded;
                ul.total = e.total || 0;
                renderUploadTray();
            });
            xhrFallback.addEventListener('load', () => {
                if (xhrFallback.status >= 200 && xhrFallback.status < 300) {
                    ul.loaded = ul.total;
                    ul.status = 'done';
                    const delay = getTrayDismissDelay();
                    if (delay > 0 && !ul._dismissScheduled) {
                        ul._dismissScheduled = true;
                        setTimeout(() => { activeUploads.delete(id); renderUploadTray(); }, delay);
                    }
                    ul.speed = null;
                    ul.eta = null;
                    renderUploadTray();
                    try { resolve(JSON.parse(xhrFallback.responseText)); } catch { resolve(xhrFallback.responseText); }
                } else {
                    ul.status = 'error';
                    ul.error = `HTTP ${xhrFallback.status}`;
                    renderUploadTray();
                    reject(new Error(`Upload failed: ${xhrFallback.status}`));
                }
            });
            xhrFallback.addEventListener('error', () => {
                ul.status = 'error';
                ul.error = 'Network error';
                renderUploadTray();
                reject(new Error('Upload failed: network error'));
            });
            if (authToken) xhrFallback.setRequestHeader('Authorization', `Bearer ${authToken}`);
            xhrFallback.open('POST', `${API_HTTP}${endpoint}`);
            if (authToken) xhrFallback.setRequestHeader('Authorization', `Bearer ${authToken}`);
            xhrFallback.send(formData);
        });

        xhr.open('POST', `${API_BASE_URL}${endpoint}`);
        if (authToken) xhr.setRequestHeader('Authorization', `Bearer ${authToken}`);
        xhr.send(formData);
    });
}


        // ======================================================================
        // --- EVENT HANDLERS & LOGIC ---
        // ======================================================================
async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const nickname = document.getElementById('reg-nickname').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    try {
        const data = await apiCall('/auth/register', 'POST', { username, nickname, email, password }, false);
        showMessage('Registration Success', data.message);
        // Switch to the login tab in the existing modal (or open fresh login)
        const _existingModal = document.getElementById('fd-auth-modal');
        if (_existingModal) {
            _existingModal.querySelector('#fd-tab-login')?.click();
        } else {
            renderApp('login');
        }
    } catch (error) {
        showMessage('Registration Failed', error.message);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const data = await apiCall('/auth/login', 'POST', { username, password }, false);
        authToken = data.token;
        currentUsername = data.username;
        isAdmin = !!data.is_admin;
        localStorage.setItem('fluxdrop_token', authToken);
        localStorage.setItem('fluxdrop_is_admin', data.is_admin ? '1' : '0');
        localStorage.setItem('fluxdrop_username', currentUsername);
        if (data.id) localStorage.setItem('fluxdrop_user_id', String(data.id));
        const _authModal = document.getElementById('fd-auth-modal');
        if (_authModal) window.fdCloseOverlay(_authModal);
        delete appRoot.dataset.fdLanding;
        const _welcomeKey = `fluxdrop_welcomed_${currentUsername}`;
        if (!localStorage.getItem(_welcomeKey)) {
            localStorage.setItem(_welcomeKey, '1');
            renderApp();          // renders file browser (policy check may show first)
            _showWelcomeScreen(); // overlays welcome on top after a tick
        } else {
            renderApp();
        }
    } catch (error) {
        showMessage('Login Failed', error.message);
    }
}


// ── Welcome screen shown once to new users after first login ─────────────
function _showWelcomeScreen() {
    // Defer until after policy modals (if any) are done
    const _tryShow = () => {
        if (document.querySelector('[id^="pam-"]')?.closest('[style*="z-index:10001"]')) {
            setTimeout(_tryShow, 400); return;
        }
        _doShowWelcome();
    };
    setTimeout(_tryShow, 300);
}

function _doShowWelcome() {
    const overlay = document.createElement('div');
    overlay.id = 'fd-welcome-overlay';
    overlay.style.cssText = [
        'position:fixed;top:0;left:0;width:100%;height:100%;z-index:10200',
        'background:rgba(15,23,42,.72);display:flex;align-items:center;justify-content:center;padding:1rem',
        'animation:fadeIn .25s ease',
    ].join(';');

    const features = [
        ['📁', 'File browser', 'Browse, create folders, rename, move, and delete files. Sorting and breadcrumb navigation included.'],
        ['⬆', 'Chunked uploads', 'Upload files up to 10 GB in resumable chunks. Pause, resume, or queue multiple uploads simultaneously.'],
        ['📁➡📄', 'Folder upload', 'Click the <strong>📁 Folder</strong> toggle next to the upload input to switch between file and folder upload mode. FluxDrop preserves the full directory structure.'],
        ['👁', 'Previews', 'Click any file name to preview it in-app — images, video, audio, text, Markdown, PDFs, and even ZIP contents.'],
        ['🔗', 'Sharing', 'Right-click (or use the Share button) on any file or folder to generate a public link. Set expiry, restrict to logged-in users, or allow anonymous uploads.'],
        ['🗑', 'Trash bin', 'Deleted files land in the Trash (🗑 button, top right). Items are kept for 30 days and can be restored at any time.'],
        ['⬇', 'Downloads', 'All downloads run in a floating tray (bottom-right). Large downloads support pause/resume via HTTP Range.'],
        ['🔒', 'Protected files', "Tick the <em>Protected</em> checkbox before uploading to mark a file as private — it won't appear in public share listings."],
        ['👤', 'Profile & settings', 'Click the 👤 button (top-right) to manage your profile, view shared links, check server status, and adjust preferences.'],
        ['📡', 'CDN browser', 'Click <strong>Browse CDN</strong> to browse the CDN storage area, separate from your personal file space.'],
    ];

    overlay.innerHTML = `
        <div style="background:#fff;border-radius:1.25rem;width:100%;max-width:740px;
                    max-height:92vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 32px 64px rgba(0,0,0,.45)">
            <!-- Header -->
            <div style="background:linear-gradient(135deg,#1e40af,#4f46e5);padding:1.75rem 2rem 1.5rem;flex-shrink:0">
                <div style="display:flex;align-items:center;gap:.9rem;margin-bottom:.5rem">
                    <img src="icon.svg" style="width:44px;height:44px" alt="">
                    <h2 style="color:white;font-size:1.55rem;font-weight:800;margin:0">Welcome to FluxDrop!</h2>
                </div>
                <p style="color:rgba(255,255,255,.82);margin:0;font-size:.95rem;line-height:1.6">
                    Here's a quick tour of everything available to you.
                </p>
            </div>
            <!-- Feature grid -->
            <div style="overflow-y:auto;flex:1;padding:1.5rem 2rem">
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem">
                    ${features.map(([icon, title, desc]) => `
                        <div style="display:flex;gap:.75rem;padding:.9rem 1rem;background:#f8fafc;
                                    border-radius:.75rem;border:1px solid #e2e8f0;align-items:flex-start">
                            <div style="font-size:1.4rem;flex-shrink:0;line-height:1;margin-top:.1rem">${icon}</div>
                            <div>
                                <div style="font-weight:700;color:#1e293b;font-size:.95rem;margin-bottom:.25rem">${title}</div>
                                <div style="color:#475569;font-size:.85rem;line-height:1.55">${desc}</div>
                            </div>
                        </div>`).join('')}
                </div>
                <div style="margin-top:1.25rem;padding:1rem 1.25rem;background:#eff6ff;border-radius:.75rem;
                            border:1px solid #bfdbfe;font-size:.88rem;color:#1e40af;line-height:1.6">
                    💡 <strong>Tip:</strong> This tour won't show again — you can always re-read the
                    <a href="#" onclick="event.preventDefault();document.getElementById('fd-welcome-overlay').remove();showPolicyModal('tos')"
                       style="color:#1d4ed8;text-decoration:underline">Terms of Service</a> and
                    <a href="#" onclick="event.preventDefault();document.getElementById('fd-welcome-overlay').remove();showPolicyModal('pp')"
                       style="color:#1d4ed8;text-decoration:underline">Privacy Policy</a> from the footer.
                </div>
            </div>
            <!-- Footer -->
            <div style="padding:1rem 2rem;border-top:1px solid #e2e8f0;display:flex;justify-content:flex-end;flex-shrink:0">
                <button id="fd-welcome-ok" class="btn" style="padding:.7rem 2rem;font-size:.95rem">
                    Get started →
                </button>
            </div>
        </div>`;

    if (!document.getElementById('fd-fadein-style')) {
        const st = document.createElement('style');
        st.id = 'fd-fadein-style';
        st.textContent = '@keyframes fadeIn{from{opacity:0}to{opacity:1}}';
        document.head.appendChild(st);
    }

    document.body.appendChild(overlay);
    overlay.querySelector('#fd-welcome-ok').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
}

async function handleLogout() {
    try {
        await apiCall('/auth/logout', 'POST');
    } catch (error) {
        console.error("Logout failed on server, but logging out client-side anyway.", error);
    } finally {
        authToken = null;
        currentUsername = null;
        isAdmin = false;
        localStorage.removeItem('fluxdrop_token');
        localStorage.removeItem('fluxdrop_is_admin');
        localStorage.removeItem('fluxdrop_username');
        renderApp();
    }
}

        // ======================================================================
        // --- PROFILE MENU ---
        // ======================================================================
// ── Avatar pan/zoom crop editor ───────────────────────────────────────────────
// Opens a modal letting the user drag to pan and scroll/pinch to zoom the image
// before committing.  The output is always a square JPEG blob (the server will
// further compress to AVIF/WebP if Pillow supports it).
//
// Usage:  _showAvatarEditor(fileObject, blob => uploadFn(blob))
//
// Constants — mirror AVATAR_MAX_DIM in server_cdn.py if you change them:
//   CANVAS    = size of the canvas element in the UI (px)
//   RADIUS    = radius of the circular crop guide (< CANVAS/2)
//   OUT_SIZE  = pixel dimensions of the square blob sent to the server
//               (server resizes again if > AVATAR_MAX_DIM)
function _showAvatarEditor(file, onConfirm) {
    const CANVAS   = 300;
    const RADIUS   = 130;   // circular guide inside the canvas
    const OUT_SIZE = 600;   // exported square — server will resize to ≤ 1024 px

    // ── Build overlay ──────────────────────────────────────────────────────
    const ov = document.createElement('div');
    ov.style.cssText =
        'position:fixed;inset:0;background:rgba(0,0,0,.78);display:flex;' +
        'align-items:center;justify-content:center;z-index:20000;font-family:Inter,sans-serif';

    ov.innerHTML = `
        <div style="background:#1e293b;border-radius:14px;overflow:hidden;
                    width:${CANVAS + 40}px;max-width:96vw;
                    box-shadow:0 24px 64px rgba(0,0,0,.65)">
            <!-- Header -->
            <div style="display:flex;justify-content:space-between;align-items:center;
                        padding:13px 16px;border-bottom:1px solid #334155">
                <span style="color:#e2e8f0;font-weight:700;font-size:14px">✂ ${t('avatar_crop_title')}</span>
                <button id="aed-x" style="background:rgba(255,255,255,.1);border:none;color:#e2e8f0;
                    border-radius:50%;width:26px;height:26px;cursor:pointer;font-size:15px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <!-- Canvas -->
            <div style="padding:16px 20px;display:flex;flex-direction:column;align-items:center;gap:10px">
                <canvas id="aed-cv" width="${CANVAS}" height="${CANVAS}"
                    style="border-radius:8px;cursor:grab;touch-action:none;
                           max-width:calc(96vw - 40px);max-height:calc(96vw - 40px)"></canvas>
                <p style="margin:0;font-size:11px;color:#475569;text-align:center">
                    ${t('avatar_crop_hint')}
                </p>
            </div>
            <!-- Footer -->
            <div style="display:flex;justify-content:space-between;align-items:center;
                        gap:8px;padding:13px 16px;border-top:1px solid #334155">
                <button id="aed-reset"
                    style="background:#334155;color:#cbd5e1;border:none;border-radius:7px;
                           padding:7px 14px;cursor:pointer;font-size:13px">${t('avatar_crop_reset')}</button>
                <div style="display:flex;gap:8px">
                    <button id="aed-cancel"
                        style="background:#334155;color:#cbd5e1;border:none;border-radius:7px;
                               padding:7px 14px;cursor:pointer;font-size:13px">${t('cancel')}</button>
                    <button id="aed-ok"
                        style="background:#3b82f6;color:#fff;border:none;border-radius:7px;
                               padding:7px 18px;cursor:pointer;font-size:13px;font-weight:600">
                        ${t('avatar_set_photo')}
                    </button>
                </div>
            </div>
        </div>`;
    document.body.appendChild(ov);

    const canvas = ov.querySelector('#aed-cv');
    const ctx    = canvas.getContext('2d');
    const img    = new Image();
    let blobUrl  = URL.createObjectURL(file);

    // Pan/zoom state
    let px = 0, py = 0, scale = 1, baseScale = 1;

    // ── Draw ────────────────────────────────────────────────────────────────
    function draw() {
        ctx.clearRect(0, 0, CANVAS, CANVAS);

        // Image
        ctx.save();
        ctx.translate(CANVAS / 2 + px, CANVAS / 2 + py);
        ctx.scale(scale, scale);
        ctx.drawImage(img, -img.naturalWidth / 2, -img.naturalHeight / 2);
        ctx.restore();

        // Semi-transparent overlay with circular cutout (evenodd fill)
        ctx.save();
        ctx.fillStyle = 'rgba(0,0,0,0.52)';
        ctx.beginPath();
        ctx.rect(0, 0, CANVAS, CANVAS);
        ctx.arc(CANVAS / 2, CANVAS / 2, RADIUS, 0, Math.PI * 2, true); // hole
        ctx.fill('evenodd');

        // Circle border
        ctx.strokeStyle = 'rgba(96,165,250,0.85)';
        ctx.lineWidth   = 2;
        ctx.beginPath();
        ctx.arc(CANVAS / 2, CANVAS / 2, RADIUS, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
    }

    // ── Clamp so the crop circle never shows empty canvas ───────────────────
    function clamp() {
        const hw = (img.naturalWidth  * scale) / 2;
        const hh = (img.naturalHeight * scale) / 2;
        const mx = Math.max(0, hw - RADIUS);
        const my = Math.max(0, hh - RADIUS);
        px = Math.max(-mx, Math.min(mx, px));
        py = Math.max(-my, Math.min(my, py));
    }

    img.onload = () => {
        // fit-to-fill: image covers the circle at start
        baseScale = Math.max(
            (2 * RADIUS) / img.naturalWidth,
            (2 * RADIUS) / img.naturalHeight
        );
        scale = baseScale;
        px = 0; py = 0;
        draw();
    };
    img.src = blobUrl;

    // ── Mouse drag ──────────────────────────────────────────────────────────
    let drag = null;
    canvas.addEventListener('mousedown', e => {
        drag = { sx: e.clientX, sy: e.clientY, ox: px, oy: py };
        canvas.style.cursor = 'grabbing';
    });
    const onMove = e => {
        if (!drag) return;
        px = drag.ox + (e.clientX - drag.sx);
        py = drag.oy + (e.clientY - drag.sy);
        clamp(); draw();
    };
    const onUp = () => { drag = null; canvas.style.cursor = 'grab'; };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup',   onUp);

    // ── Scroll to zoom ───────────────────────────────────────────────────────
    canvas.addEventListener('wheel', e => {
        e.preventDefault();
        scale = Math.max(baseScale, Math.min(scale * (e.deltaY < 0 ? 1.1 : 0.9), baseScale * 10));
        clamp(); draw();
    }, { passive: false });

    // ── Touch: drag + pinch zoom ─────────────────────────────────────────────
    const touches = {};
    let pinch0 = null, pscale0 = null;
    canvas.addEventListener('touchstart', e => {
        e.preventDefault();
        [...e.changedTouches].forEach(t => { touches[t.identifier] = { x: t.clientX, y: t.clientY }; });
        const ids = Object.keys(touches);
        if (ids.length === 2) {
            const [a, b] = ids.map(id => touches[id]);
            pinch0   = Math.hypot(b.x - a.x, b.y - a.y);
            pscale0  = scale;
        }
        if (ids.length === 1) {
            const t = e.changedTouches[0];
            drag = { sx: t.clientX, sy: t.clientY, ox: px, oy: py };
        }
    }, { passive: false });

    canvas.addEventListener('touchmove', e => {
        e.preventDefault();
        [...e.changedTouches].forEach(t => { touches[t.identifier] = { x: t.clientX, y: t.clientY }; });
        const ids = Object.keys(touches);
        if (ids.length === 2 && pinch0) {
            const [a, b] = ids.map(id => touches[id]);
            const d = Math.hypot(b.x - a.x, b.y - a.y);
            scale = Math.max(baseScale, Math.min(pscale0 * d / pinch0, baseScale * 10));
        } else if (ids.length === 1 && drag) {
            const t = e.changedTouches[0];
            px = drag.ox + (t.clientX - drag.sx);
            py = drag.oy + (t.clientY - drag.sy);
        }
        clamp(); draw();
    }, { passive: false });

    canvas.addEventListener('touchend', e => {
        [...e.changedTouches].forEach(t => { delete touches[t.identifier]; });
        if (Object.keys(touches).length < 2) { pinch0 = null; pscale0 = null; }
        if (Object.keys(touches).length === 0) drag = null;
    });

    // ── Cleanup helper ──────────────────────────────────────────────────────
    function close() {
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup',   onUp);
        URL.revokeObjectURL(blobUrl);
        ov.remove();
    }

    // ── Buttons ──────────────────────────────────────────────────────────────
    ov.querySelector('#aed-x').addEventListener('click', close);
    ov.querySelector('#aed-cancel').addEventListener('click', close);

    ov.querySelector('#aed-reset').addEventListener('click', () => {
        scale = baseScale; px = 0; py = 0; draw();
    });

    ov.querySelector('#aed-ok').addEventListener('click', () => {
        // Render the crop region to an output canvas.
        //
        // In display-canvas space the crop circle is at (CANVAS/2, CANVAS/2)
        // with radius RADIUS.  The image is drawn at (CANVAS/2 + px, CANVAS/2 + py)
        // scaled by `scale`.  To extract a square of side 2*RADIUS centred on
        // the circle, we map that region to OUT_SIZE × OUT_SIZE:
        //   factor  = OUT_SIZE / (2 * RADIUS)
        //   image-center in output = (RADIUS + px) * factor, (RADIUS + py) * factor
        const out  = document.createElement('canvas');
        out.width  = out.height = OUT_SIZE;
        const octx = out.getContext('2d');
        const f    = OUT_SIZE / (2 * RADIUS);
        octx.translate((RADIUS + px) * f, (RADIUS + py) * f);
        octx.scale(scale * f, scale * f);
        octx.drawImage(img, -img.naturalWidth / 2, -img.naturalHeight / 2);
        out.toBlob(blob => { close(); if (blob) onConfirm(blob); }, 'image/jpeg', 0.88);
    });
}

function openProfileMenu() {
    // Close if already open
    const existing = document.getElementById('profile-menu-modal');
    if (existing) { existing.remove(); return; }

    const overlay = document.createElement('div');
    overlay.id = 'profile-menu-modal';
    overlay.className = 'fd-profile-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:8000;display:flex;align-items:flex-start;justify-content:flex-end;padding:70px 1rem 0 0';
    overlay.innerHTML = `
        <div id="profile-menu-panel" data-fd-dark="surface" style="background:white;border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,0.18);min-width:260px;overflow:hidden;animation:fadeSlideDown .15s ease">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:18px 20px;display:flex;align-items:center;gap:12px" data-fd-dark="header">
                <!-- Avatar with fallback emoji -->
                <div style="width:46px;height:46px;border-radius:50%;overflow:hidden;
                            background:rgba(255,255,255,0.25);flex-shrink:0;
                            display:flex;align-items:center;justify-content:center;font-size:22px">
                    <img id="pm-avatar-img"
                         src="${_avatarUrl()}"
                         style="width:46px;height:46px;object-fit:cover;display:block"
                         onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"
                         alt="">
                    <span id="pm-avatar-fallback"
                          style="display:none;width:100%;height:100%;
                                 align-items:center;justify-content:center;font-size:22px">👤</span>
                </div>
                <div>
                    <div style="color:white;font-weight:700;font-size:15px">${currentUsername}</div>
                    <div style="color:rgba(255,255,255,0.75);font-size:12px">${t('menu_account_info_fluxdrop')}</div>
                </div>
            </div>
            <div id="pm-quota-bar" style="padding:10px 16px 6px;border-bottom:1px solid var(--fd-border,#e2e8f0)">
                <div style="font-size:11px;color:#94a3b8;margin-bottom:4px">${t('menu_account_info_storage_loading')}</div>
                <div style="background:#e2e8f0;border-radius:4px;height:5px;overflow:hidden">
                    <div id="pm-quota-fill" style="height:100%;border-radius:4px;background:#3b82f6;width:0%;transition:width .4s"></div>
                </div>
            </div>
            <div style="padding:8px 0">
                <button class="profile-menu-item" id="pm-profile">${t('menu_account_info_profile')}</button>
                <button class="profile-menu-item" id="pm-shares">${t('menu_account_info_links')}</button>
                <button class="profile-menu-item" id="pm-beacon">${t('menu_account_info_ip_beacon')}</button>
                <button class="profile-menu-item" id="pm-status">${t('menu_account_info_status')}</button>
                <div style="height:1px;background:var(--fd-border,#f1f5f9);margin:4px 0"></div>
                ${isAdmin ? `<button class="profile-menu-item" id="pm-admin">${t('menu_account_info_admin_panel')}</button>` : ''}
                <button class="profile-menu-item" id="pm-logout" style="color:#ef4444">${t('menu_account_info_logout')}</button>
            </div>
        </div>`;
    // Inject menu-item style
    const style = document.createElement('style');
    style.textContent = `
        .profile-menu-item{display:block;width:100%;text-align:left;padding:10px 20px;background:none;border:none;font-size:14px;cursor:pointer;color:#1e293b;transition:background .15s}
        .profile-menu-item:hover{background:#f8fafc}
        @keyframes fadeSlideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}`;
    overlay.appendChild(style);
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });
    document.getElementById('pm-profile').addEventListener('click', () => { overlay.remove(); openProfilePanel(); });
    // Quota bar → open space analyzer directly
    document.getElementById('pm-quota-bar').style.cursor = 'pointer';
    document.getElementById('pm-quota-bar').title = 'Click to open Space Analyzer';
    document.getElementById('pm-quota-bar').addEventListener('click', () => { window.fdCloseOverlay(overlay); openSpaceAnalyzer(); });
    document.getElementById('pm-shares').addEventListener('click', () => { overlay.remove(); openShareManager(); });
    document.getElementById('pm-beacon').addEventListener('click', () => {
        overlay.remove();
        // Open IP Beacon — session validation is handled server-side via the
        // FluxDrop cookie/header.  Do NOT pass authToken as ?token= because
        // that query param is consumed by ip_lookup.html as a beacon lookup
        // token (primary/read), which is a completely different credential.
        window.location.href = '/beacon/ui';
    });
    document.getElementById('pm-status').addEventListener('click', () => {
        overlay.remove();
        window.location.href = '/status';
    });
    document.getElementById('pm-logout').addEventListener('click', () => { overlay.remove(); handleLogout(); });
    if (isAdmin) document.getElementById('pm-admin')?.addEventListener('click', () => { overlay.remove(); openAdminPanel(); });

    // Load quota info asynchronously — don't block menu opening
    apiCall('/api/v1/me', 'GET').then(me => {
        const bar  = document.getElementById('pm-quota-bar');
        const fill = document.getElementById('pm-quota-fill');
        if (!bar || !fill) return;
        const used  = me.usage_bytes  || 0;
        const quota = me.quota_bytes  || 1;
        const pct   = Math.min(100, (used / quota) * 100);
        const color = pct >= 95 ? '#ef4444' : pct >= 75 ? '#f59e0b' : '#3b82f6';
        const fmt   = b => b >= 1073741824 ? (b/1073741824).toFixed(1)+' GB'
                         : b >= 1048576    ? (b/1048576).toFixed(1)+' MB'
                         : (b/1024).toFixed(0)+' KB';
        bar.querySelector('div').textContent = `${t('menu_account_info_storage')} ${fmt(used)} ${t('quota_of_word')} ${fmt(quota)} (${pct.toFixed(0)}%)`;
        fill.style.width   = pct.toFixed(1) + '%';
        fill.style.background = color;
    }).catch(() => {
        const bar = document.getElementById('pm-quota-bar');
        if (bar) bar.querySelector('div').textContent = t('menu_account_info_storage') + ' unavailable';
    });
}

        // ======================================================================
        // --- PROFILE PANEL ---
        // ======================================================================
async function openProfilePanel() {
    const existing = document.getElementById('profile-panel-overlay');
    if (existing) { existing.remove(); return; }

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'profile-panel-overlay';
    overlay.style.zIndex = '9000';
    overlay.innerHTML = `
        <div data-fd-dark="surface" style="background:white;border-radius:16px;width:95vw;max-width:500px;
                    overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.3);display:flex;flex-direction:column;max-height:90vh">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:18px 24px;
                        display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
                <div style="color:white;font-weight:700;font-size:18px">👤 My Profile</div>
                <button id="pp-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:32px;height:32px;color:white;font-size:18px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div style="overflow-y:auto;flex:1;padding:20px 24px;display:grid;gap:20px">
                <!-- Quota card -->
                <div id="pp-quota-card" data-fd-dark="surface2" style="background:#f8fafc;border-radius:10px;padding:14px 16px">
                    <div style="font-size:13px;color:#64748b;margin-bottom:8px">${t('loading')}</div>
                </div>

                <!-- Edit profile section -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">${t('profile_info_profile_info')}</div>

                    <!-- Profile picture -->
                    <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px">
                        <div id="pp-avatar-wrap" style="position:relative;flex-shrink:0">
                            <img id="pp-avatar-img"
                                 src="${_avatarUrl()}"
                                 style="width:64px;height:64px;border-radius:50%;object-fit:cover;
                                        border:2px solid #e2e8f0;background:#f1f5f9"
                                 onerror="this.style.display='none';document.getElementById('pp-avatar-fallback').style.display='flex'"
                                 alt="Avatar">
                            <div id="pp-avatar-fallback"
                                 style="display:none;width:64px;height:64px;border-radius:50%;
                                        background:#dbeafe;border:2px solid #e2e8f0;
                                        align-items:center;justify-content:center;font-size:28px">👤</div>
                        </div>
                        <div style="display:grid;gap:6px">
                            <label id="pp-avatar-btn" class="btn"
                                   style="padding:5px 12px;font-size:12px;cursor:pointer;display:inline-block">
                                ${t('avatar_change_photo')}
                                <input type="file" id="pp-avatar-file" accept="image/*"
                                       style="display:none">
                            </label>
                            <button id="pp-avatar-remove"
                                    style="background:none;border:none;color:#94a3b8;font-size:12px;
                                           cursor:pointer;text-align:left;padding:0;text-decoration:underline">
                                ${t('avatar_remove_photo')}
                            </button>
                            <div id="pp-avatar-msg" style="font-size:11px;color:#94a3b8">
                                ${t('avatar_hint')}
                            </div>
                        </div>
                    </div>

                    <div style="display:grid;gap:10px">
                        <label style="font-size:13px;font-weight:600;color:#374151">${t('profile_info_nickname')}
                            <input id="pp-nickname" type="text" placeholder="${t('loading')}"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">${t('email')}
                            <input id="pp-email" type="email" placeholder="${t('loading')}"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <div id="pp-profile-msg" style="display:none;font-size:13px;border-radius:6px;padding:6px 10px"></div>
                        <button id="pp-save-profile" class="btn" style="justify-self:end;padding:.5rem 1.25rem">${t('save_changes')}</button>
                    </div>
                </div>

                <hr style="border:none;border-top:1px solid var(--fd-border,#e2e8f0);margin:0">

                <!-- Change password section -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">${t('change_password')}</div>
                    <div style="display:grid;gap:10px">
                        <label style="font-size:13px;font-weight:600;color:#374151">${t('current_pw')}
                            <input id="pp-cur-pw" type="password" autocomplete="current-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">${t('new_password')}
                            <input id="pp-new-pw" type="password" autocomplete="new-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">${t('profile_info_password_confirm')}
                            <input id="pp-confirm-pw" type="password" autocomplete="new-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <div id="pp-pw-msg" style="display:none;font-size:13px;border-radius:6px;padding:6px 10px"></div>
                        <button id="pp-change-pw" class="btn" style="justify-self:end;padding:.5rem 1.25rem;background:#6366f1">${t('change_password')}</button>
                    </div>
                </div>

                <!-- Settings card -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">${t('transfer_tray')}</div>
                    <label style="font-size:13px;font-weight:600;color:#374151">
                        ${t('auto_dismiss')}
                        <select id="pp-dismiss-delay" style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                            border:1px solid #e2e8f0;border-radius:8px;font-size:14px;font-family:Inter,sans-serif">
                            <option value="0">${t('never_dismiss')}</option>
                            <option value="3000">${t('profile_info_info_modal_message_autoclose_selector_3s')}</option>
                            <option value="5000">${t('profile_info_info_modal_message_autoclose_selector_5s')}</option>
                            <option value="10000">${t('profile_info_info_modal_message_autoclose_selector_10s')}</option>
                            <option value="30000">${t('profile_info_info_modal_message_autoclose_selector_30s')}</option>
                        </select>
                    </label>
                </div>

                <!-- Account info footer -->
                <div id="pp-account-info" style="font-size:12px;color:#94a3b8;padding-bottom:4px"></div>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });
    overlay.querySelector('#pp-close').addEventListener('click', () => window.fdCloseOverlay(overlay));

    // Helper: show message in a field's msg element
    function ppMsg(elId, text, isError) {
        const el = overlay.querySelector('#' + elId);
        if (!el) return;
        el.textContent = text;
        el.style.display = text ? 'block' : 'none';
        el.style.background = isError ? '#fef2f2' : '#f0fdf4';
        el.style.color = isError ? '#ef4444' : '#16a34a';
    }

    // Load user info
    try {
        const me = await apiCall('/api/v1/me', 'GET');
        if (!overlay.isConnected) return;

        // Quota card
        const used  = me.usage_bytes  || 0;
        const quota = me.quota_bytes  || 1;
        const pct   = Math.min(100, (used / quota) * 100);
        const barColor = pct >= 95 ? '#ef4444' : pct >= 75 ? '#f59e0b' : '#22c55e';
        const fmt = b => b >= 1073741824 ? (b/1073741824).toFixed(2)+' GB'
                       : b >= 1048576    ? (b/1048576).toFixed(1)+' MB'
                       : (b/1024).toFixed(0)+' KB';
        const pinNote = me.quota_override
            ? ` · <span style="color:#6366f1;font-size:11px">${t('quota_pinned')}</span>`
            : ` · <span style="color:#94a3b8;font-size:11px">${t('quota_dynamic')}</span>`;
        overlay.querySelector('#pp-quota-card').innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px">
                <span style="font-size:13px;font-weight:600;color:#374151">${t('storage_quota')}</span>
                <span style="font-size:13px;color:#475569">${fmt(used)} <span style="color:#94a3b8">${t('quota_of_word')}</span> ${fmt(quota)}</span>
            </div>
            <div style="background:#e2e8f0;border-radius:6px;height:8px;overflow:hidden;margin-bottom:6px">
                <div style="height:100%;border-radius:6px;background:${barColor};width:${pct.toFixed(1)}%;transition:width .4s"></div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-size:12px;color:#64748b">${t('profile_info_quota_space', {pct: pct.toFixed(1), free: fmt(quota - used), pin: pinNote})}</span>
                ${pct >= 95 ? `<span style="font-size:12px;color:#ef4444;font-weight:600">${t('profile_info_quota_space_warning')}</span>` : ''}
            </div>
            <div style="font-size:11px;color:#94a3b8;margin-top:6px;text-align:right">${t('profile_info_quota_space_analyzer_hinter')}</div>`;
        // Make quota card open space analyzer on click
        const _qCard = overlay.querySelector('#pp-quota-card');
        _qCard.style.cursor = 'pointer';
        _qCard.title = 'Open Space Analyzer';
        _qCard.addEventListener('click', () => { window.fdCloseOverlay(overlay); openSpaceAnalyzer(); });

        // Fill in editable fields
        overlay.querySelector('#pp-nickname').value = me.nickname || '';
        overlay.querySelector('#pp-email').value    = me.email    || '';

        // Cache user_id (needed by header avatar URL)
        if (me.id) localStorage.setItem('fluxdrop_user_id', String(me.id));

        // Account info footer
        overlay.querySelector('#pp-account-info').innerHTML =
            `ID ${me.id} ${t('profile_info_username')} <strong>${escapeHtml(me.username)}</strong> ${t('profile_info_join_time')} ${(me.created_at||'').slice(0,10)}` +
            (me.is_admin ? ` · <span style="color:#92400e;background:#fef3c7;padding:1px 6px;border-radius:999px;font-weight:600">${t('profile_info_admin_badge')}</span>` : '');

    } catch (err) {
        if (!overlay.isConnected) return;
        overlay.querySelector('#pp-quota-card').innerHTML =
            `<div style="color:#ef4444;font-size:13px">Failed to load profile: ${escapeHtml(err.message)}</div>`;
    }

    // Save profile info
    overlay.querySelector('#pp-save-profile').addEventListener('click', async () => {
        const btn      = overlay.querySelector('#pp-save-profile');
        const nickname = overlay.querySelector('#pp-nickname').value.trim();
        const email    = overlay.querySelector('#pp-email').value.trim();
        if (!nickname && !email) { ppMsg('pp-profile-msg', 'Nothing to save.', true); return; }
        ppMsg('pp-profile-msg', '', false);
        btn.disabled = true; btn.textContent = 'Saving…';
        try {
            await apiCall('/api/v1/me', 'PATCH', { nickname, email });
            ppMsg('pp-profile-msg', 'Saved!', false);
        } catch (err) {
            if (!overlay.isConnected) return;
            ppMsg('pp-profile-msg', err.message, true);
        } finally {
            if (overlay.isConnected) { btn.disabled = false; btn.textContent = 'Save changes'; }
        }
    });

    // ── Avatar upload ─────────────────────────────────────────────────────────
    function _ppRefreshAvatar() {
        // Bump the shared avatar version so this element AND every future
        // normal render (header, profile menu, next time this panel opens)
        // fetch the new image instead of a stale cached copy — then goes back
        // to being cacheable again until the avatar changes again.
        _bumpAvatarVersion();
        const uid = localStorage.getItem('fluxdrop_user_id') || '0';
        const url = _avatarUrl(uid);
        const ppImg = overlay.querySelector('#pp-avatar-img');
        const ppFallback = overlay.querySelector('#pp-avatar-fallback');
        const hdrImg = document.getElementById('header-avatar');
        const hdrFallback = document.getElementById('header-avatar-fallback');
        if (ppImg) {
            ppImg.style.display = 'block';
            ppFallback && (ppFallback.style.display = 'none');
            ppImg.onerror = () => {
                ppImg.style.display = 'none';
                ppFallback && (ppFallback.style.display = 'flex');
            };
            ppImg.src = url;
        }
        if (hdrImg) {
            hdrImg.style.display = 'block';
            hdrFallback && (hdrFallback.style.display = 'none');
            hdrImg.onerror = () => {
                hdrImg.style.display = 'none';
                hdrFallback && (hdrFallback.style.display = 'flex');
            };
            hdrImg.src = url;
        }
    }

    const _ppAvatarFile = overlay.querySelector('#pp-avatar-file');
    const _ppAvatarMsg  = overlay.querySelector('#pp-avatar-msg');

    // Upload helper — called after the editor produces a cropped blob
    async function _ppDoUpload(blob) {
        _ppAvatarMsg.textContent = 'Uploading…';
        _ppAvatarMsg.style.color = '#64748b';
        const fd = new FormData();
        fd.append('avatar', blob, 'avatar.jpg');
        try {
            const resp = await fetchWithFallback(`${API_BASE_URL}/api/v1/me/avatar`, {
                method: 'POST',
                headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
                body: fd,
            });
            const result = await resp.json();
            if (!resp.ok) throw new Error(result.error || `HTTP ${resp.status}`);
            _ppAvatarMsg.textContent = `✓ Saved (${result.mime}, ${Math.round(result.size_bytes / 1024)} kB)`;
            _ppAvatarMsg.style.color = '#16a34a';
            _ppRefreshAvatar();
        } catch (e) {
            _ppAvatarMsg.textContent = '⚠ ' + e.message;
            _ppAvatarMsg.style.color = '#ef4444';
        }
    }

    if (_ppAvatarFile) {
        _ppAvatarFile.addEventListener('change', function () {
            const file = this.files && this.files[0];
            if (!file) return;
            if (!file.type.startsWith('image/')) {
                _ppAvatarMsg.textContent = '⚠ Please select an image file.';
                _ppAvatarMsg.style.color = '#ef4444';
                return;
            }
            this.value = '';
            // Open the pan/zoom crop editor; upload the result when confirmed
            _showAvatarEditor(file, blob => _ppDoUpload(blob));
        });
    }

    const _ppAvatarRemove = overlay.querySelector('#pp-avatar-remove');
    if (_ppAvatarRemove) {
        _ppAvatarRemove.addEventListener('click', async () => {
            _ppAvatarMsg.textContent = 'Removing…';
            _ppAvatarMsg.style.color = '#64748b';
            try {
                const resp = await fetchWithFallback(`${API_BASE_URL}/api/v1/me/avatar`, {
                    method: 'DELETE',
                    headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
                });
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                _ppAvatarMsg.textContent = 'Photo removed.';
                _ppAvatarMsg.style.color = '#64748b';
                _ppRefreshAvatar();
            } catch (e) {
                _ppAvatarMsg.textContent = '⚠ ' + e.message;
                _ppAvatarMsg.style.color = '#ef4444';
            }
        });
    }

    // Change password
    overlay.querySelector('#pp-change-pw').addEventListener('click', async () => {
        const btn       = overlay.querySelector('#pp-change-pw');
        const curPw     = overlay.querySelector('#pp-cur-pw').value;
        const newPw     = overlay.querySelector('#pp-new-pw').value;
        const confirmPw = overlay.querySelector('#pp-confirm-pw').value;
        if (!curPw || !newPw || !confirmPw) {
            ppMsg('pp-pw-msg', 'All three fields are required.', true); return;
        }
        if (newPw !== confirmPw) {
            ppMsg('pp-pw-msg', 'New passwords do not match.', true); return;
        }
        if (newPw.length < 8) {
            ppMsg('pp-pw-msg', 'New password must be at least 8 characters.', true); return;
        }
        ppMsg('pp-pw-msg', '', false);
        btn.disabled = true; btn.textContent = 'Changing…';
        try {
            const res = await apiCall('/api/v1/me/password', 'PATCH', {
                current_password: curPw, new_password: newPw,
            });
            ppMsg('pp-pw-msg', res.message || 'Password changed!', false);
            overlay.querySelector('#pp-cur-pw').value     = '';
            overlay.querySelector('#pp-new-pw').value     = '';
            overlay.querySelector('#pp-confirm-pw').value = '';
        } catch (err) {
            if (!overlay.isConnected) return;
            ppMsg('pp-pw-msg', err.message, true);
        } finally {
            if (overlay.isConnected) { btn.disabled = false; btn.textContent = 'Change password'; }
        }
    });
    const dismissSel = overlay.querySelector('#pp-dismiss-delay');
    if (dismissSel) {
        dismissSel.value = localStorage.getItem('fluxdrop_tray_dismiss_ms') || '0';
        dismissSel.addEventListener('change', () => {
            localStorage.setItem('fluxdrop_tray_dismiss_ms', dismissSel.value);
        });
    }
}

        // ======================================================================
        // --- ADMIN PANEL ---
        // ======================================================================
async function openAdminPanel() {
    const existing = document.getElementById('admin-panel-overlay');
    if (existing) { existing.remove(); return; }

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'admin-panel-overlay';
    overlay.style.zIndex = '9000';
    overlay.innerHTML = `
        <div style="background:white;border-radius:16px;width:95vw;max-width:860px;
                    max-height:88vh;display:flex;flex-direction:column;overflow:hidden;
                    box-shadow:0 20px 60px rgba(0,0,0,0.3)">
            <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:18px 24px;
                        display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
                <div>
                    <div style="color:white;font-weight:700;font-size:18px">${t('menu_account_info_admin_panel')}</div>
                    <div style="color:rgba(255,255,255,.55);font-size:12px;margin-top:2px">${t('admin_panel_info')}</div>
                </div>
                <button id="ap-close" style="background:rgba(255,255,255,.15);border:none;border-radius:50%;
                    width:32px;height:32px;color:white;font-size:18px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div id="ap-stats" style="background:#f8fafc;border-bottom:1px solid #e2e8f0;
                padding:10px 24px;display:flex;gap:24px;flex-shrink:0;flex-wrap:wrap"></div>
            <div style="overflow-y:auto;flex:1;padding:16px 24px">
                <div id="ap-body">
                    <div style="display:flex;align-items:center;gap:12px;padding:24px 0;color:#64748b;font-size:14px">
                        <span style="display:inline-block;width:22px;height:22px;border:3px solid #e2e8f0;
                                     border-top-color:#3b82f6;border-radius:50%;
                                     animation:fd-spin 0.8s linear infinite;flex-shrink:0"></span>
                        ${t('admin_panel_loading')}
                    </div>
                </div>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });
    document.getElementById('ap-close').addEventListener('click', () => window.fdCloseOverlay(overlay));

    await _apLoadUsers();
}

async function _apLoadUsers() {
    const body = document.getElementById('ap-body');
    const statsBar = document.getElementById('ap-stats');
    if (!body) return;

    try {
        const data = await apiCall('/api/v1/admin/users', 'GET');
        const users = data.users || [];

        const totalUsage = users.reduce((s, u) => s + (u.usage_bytes || 0), 0);
        const adminCount = users.filter(u => u.is_admin).length;
        if (statsBar) statsBar.innerHTML = [
            `<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${users.length}</strong> ${t('admin_panel_user_count')}</span>`,
            `<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${adminCount}</strong> ${t('admin_panel_admin_count')}</span>`,
            `<span style="font-size:13px;color:#475569">${t('admin_panel_used')} <strong style="color:#1e293b">${_apFmtBytes(totalUsage)}</strong></span>`,
        ].join('<span style="color:#cbd5e1;margin:0 4px">|</span>');

        if (users.length === 0) {
            body.innerHTML = `<p style="color:#64748b;font-size:14px;padding:20px 0">${t('admin_panel_no_users')}</p>`;
            return;
        }

        if (!document.getElementById('ap-style')) {
            const st = document.createElement('style');
            st.id = 'ap-style';
            st.textContent = `
                .ap-row{display:grid;grid-template-columns:1fr 90px 140px 100px;gap:12px;
                    align-items:center;padding:10px 12px;border-radius:8px;transition:background .12s}
                .ap-row:hover{background:#f8fafc}
                .ap-row+.ap-row{border-top:1px solid #f1f5f9}
                .ap-bar-wrap{background:#e2e8f0;border-radius:4px;height:6px;overflow:hidden}
                .ap-bar-fill{height:100%;border-radius:4px;transition:width .3s}
                .ap-badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:11px;font-weight:600}
                .ap-btn{border:none;border-radius:6px;padding:4px 10px;font-size:12px;
                    font-weight:600;cursor:pointer;transition:opacity .15s}
                .ap-btn:hover{opacity:.85}
            `;
            document.head.appendChild(st);
        }

        body.innerHTML = `
            <div class="ap-row" style="font-size:12px;font-weight:700;color:#94a3b8;
                border-bottom:2px solid #e2e8f0;border-radius:0;padding-bottom:6px">
                <span>${t('admin_col_user')}</span><span>${t('admin_col_usage')}</span><span>${t('admin_col_quota')}</span>
                <span style="text-align:right">${t('fluxdrop_file_manager_actions')}</span>
            </div>` + users.map(u => _apRenderRow(u)).join('');

        body.querySelectorAll('.ap-edit-btn').forEach(btn => {
            btn.addEventListener('click', () => _apOpenEditModal(+btn.dataset.id, users));
        });
        body.querySelectorAll('.ap-del-btn').forEach(btn => {
            btn.addEventListener('click', () => _apDeleteUser(+btn.dataset.id, btn.dataset.name));
        });

    } catch (err) {
        const b = document.getElementById('ap-body');
        if (err.message !== 'SESSION_EXPIRED' && b) {
            b.innerHTML = `<p style="color:#ef4444;font-size:14px;padding:20px 0">${t('admin_panel_load_failed', { err: escapeHtml(err.message) })}</p>`;
        }
    }
}

function _apFmtBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576)    return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024)       return (b / 1024).toFixed(0) + ' KB';
    return b + ' B';
}

function _apRenderRow(u) {
    const pct = u.quota_bytes > 0 ? Math.min(100, (u.usage_bytes / u.quota_bytes) * 100) : 0;
    const barColor = pct >= 95 ? '#ef4444' : pct >= 75 ? '#f59e0b' : '#22c55e';
    const adminBadge = u.is_admin
        ? `<span class="ap-badge" style="background:#fef3c7;color:#92400e">${t('profile_info_admin_badge')}</span> ` : '';
    return `<div class="ap-row">
        <div>
            <div style="font-size:14px;font-weight:600;color:#1e293b">${adminBadge}${escapeHtml(u.username)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:1px">${escapeHtml(u.nickname||'')} · ${escapeHtml(u.email||'')}</div>
            <div style="font-size:11px;color:#cbd5e1;margin-top:1px">${t('admin_row_id_joined', { id: u.id, date: (u.created_at||'').slice(0,10) })}</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569;margin-bottom:3px">${_apFmtBytes(u.usage_bytes||0)}</div>
            <div class="ap-bar-wrap"><div class="ap-bar-fill" style="width:${pct.toFixed(1)}%;background:${barColor}"></div></div>
            <div style="font-size:10px;color:#94a3b8;margin-top:2px">${pct.toFixed(0)}%</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569">${_apFmtBytes(u.quota_bytes||0)}</div>
            ${u.quota_override
                ? `<div style="font-size:10px;color:#6366f1;margin-top:1px">${t('admin_panel_pinned_badge')}</div>`
                : `<div style="font-size:10px;color:#94a3b8;margin-top:1px">${t('admin_panel_dynamic_quota')}</div>`}
        </div>
        <div style="display:flex;gap:5px;justify-content:flex-end">
            <button class="ap-btn ap-edit-btn" data-id="${u.id}"
                style="background:#3b82f6;color:white">${t('admin_panel_edit_button')}</button>
            <button class="ap-btn ap-del-btn" data-id="${u.id}" data-name="${escapeHtmlAttr(u.username)}"
                style="background:#ef4444;color:white">${t('admin_panel_delete_button')}</button>
        </div>
    </div>`;
}

function _apOpenEditModal(userId, users) {
    const u = users.find(x => x.id === userId);
    if (!u) return;

    const existing = document.getElementById('ap-edit-overlay');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'ap-edit-overlay';
    modal.style.zIndex = '9500';
    modal.innerHTML = `
        <div style="background:white;border-radius:14px;width:95vw;max-width:460px;
                    overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.35)">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:16px 20px;
                        display:flex;align-items:center;justify-content:space-between">
                <div style="color:white;font-weight:700;font-size:16px">${t('admin_edit_title', { name: escapeHtml(u.username) })}</div>
                <button id="ap-edit-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:28px;height:28px;color:white;font-size:16px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div style="padding:20px;display:grid;gap:12px">
                <label style="font-size:13px;font-weight:600;color:#374151">${t('username_login')}
                    <input id="ape-username" type="text" value="${escapeHtmlAttr(u.username)}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">${t('admin_edit_nickname')}
                    <input id="ape-nickname" type="text" value="${escapeHtmlAttr(u.nickname||'')}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">${t('email')}
                    <input id="ape-email" type="email" value="${escapeHtmlAttr(u.email||'')}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <label style="font-size:13px;font-weight:600;color:#374151">${t('admin_edit_quota_gb')}
                        <input id="ape-quota" type="number" min="1" step="1"
                            value="${Math.round((u.quota_bytes||0)/(1024**3))}"
                            style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                   border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                   box-sizing:border-box;font-family:Inter,sans-serif">
                    </label>
                    <label style="font-size:13px;font-weight:600;color:#374151;display:flex;flex-direction:column">
                        <span>${t('admin_edit_flags')}</span>
                        <span style="display:flex;flex-direction:column;gap:6px;margin-top:8px">
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-is-admin" ${u.is_admin?'checked':''}> ${t('admin_edit_flag_admin')}
                            </label>
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-quota-override" ${u.quota_override?'checked':''}> ${t('admin_edit_flag_pin_quota')}
                            </label>
                        </span>
                    </label>
                </div>
                <div id="ape-error" style="display:none;color:#ef4444;font-size:13px;
                    background:#fef2f2;border-radius:6px;padding:6px 10px"></div>
            </div>
            <div style="padding:12px 20px 18px;display:flex;gap:8px;justify-content:flex-end;
                        border-top:1px solid #f1f5f9">
                <button id="ape-cancel" class="btn" style="background:#e2e8f0;color:#1e293b">${t('cancel')}</button>
                <button id="ape-save" class="btn" style="background:#3b82f6;min-width:80px">${t('admin_edit_save')}</button>
            </div>
        </div>`;
    document.body.appendChild(modal);

    modal.addEventListener('click', e => { if (e.target === modal) window.fdCloseOverlay(modal); });
    modal.querySelector('#ap-edit-close').addEventListener('click', () => window.fdCloseOverlay(modal));
    modal.querySelector('#ape-cancel').addEventListener('click', () => window.fdCloseOverlay(modal));

    modal.querySelector('#ape-save').addEventListener('click', async () => {
        if (!modal.isConnected) return;
        const saveBtn = modal.querySelector('#ape-save');
        const errEl   = modal.querySelector('#ape-error');
        const quotaGb = parseFloat(modal.querySelector('#ape-quota').value);
        if (isNaN(quotaGb) || quotaGb < 1) {
            errEl.textContent = t('admin_edit_quota_min_err');
            errEl.style.display = 'block'; return;
        }
        errEl.style.display = 'none';
        saveBtn.disabled = true; saveBtn.textContent = t('admin_edit_saving');
        try {
            await apiCall(`/api/v1/admin/users/${userId}`, 'PATCH', {
                username:       modal.querySelector('#ape-username').value.trim(),
                nickname:       modal.querySelector('#ape-nickname').value.trim(),
                email:          modal.querySelector('#ape-email').value.trim(),
                quota_bytes:    Math.round(quotaGb * 1024 ** 3),
                is_admin:       modal.querySelector('#ape-is-admin').checked ? 1 : 0,
                quota_override: modal.querySelector('#ape-quota-override').checked ? 1 : 0,
            });
            window.fdCloseOverlay(modal);
            await _apLoadUsers();
        } catch (err) {
            if (!modal.isConnected) return;
            saveBtn.disabled = false; saveBtn.textContent = t('admin_edit_save');
            if (err.message !== 'SESSION_EXPIRED') {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
            }
        }
    });
}

async function _apDeleteUser(userId, username) {
    const full = t('admin_delete_confirm', { name: username });
    const [titleLine, ...rest] = full.split('\n\n');
    const ok = await showConfirmModal({
        title: titleLine,
        message: rest.join('\n\n'),
    });
    if (!ok) return;
    try {
        await apiCall(`/api/v1/admin/users/${userId}`, 'DELETE');
        await _apLoadUsers();
    } catch (err) {
        if (err.message !== 'SESSION_EXPIRED') showMessage(t('admin_delete_failed'), err.message);
    }
}

        // ======================================================================
        // --- SHARE DIALOG (create a new share for a file/folder) ---
        // ======================================================================
async function openShareDialog(path, isDir) {
    const name = path.split('/').pop() || path;
    // Default expiry options: none, 1 day, 7 days, 30 days, custom
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'share-dialog-overlay';
    overlay.innerHTML = `
        <div class="modal-content" style="max-width:500px">
            <h3 style="font-size:18px;font-weight:700;margin-bottom:4px">${t('share_dlg_title', { name })}</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:16px">${isDir ? t('share_dlg_kind_folder') : t('share_dlg_kind_file')}: <code style="background:#f1f5f9;padding:1px 5px;border-radius:4px">${path}</code></p>

            <div style="display:grid;gap:10px;margin-bottom:18px">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-require-account" style="width:16px;height:16px">
                    <span style="font-size:14px">${t('share_dlg_require_account')}</span>
                </label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-stats" checked style="width:16px;height:16px">
                    <span style="font-size:14px">${t('share_dlg_track_stats')}</span>
                </label>

                <div style="display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;white-space:nowrap">${t('share_dlg_expires_label')}</span>
                    <select id="sh-expiry-preset" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="">${t('share_dlg_exp_never')}</option>
                        <option value="1">${t('share_dlg_exp_1d')}</option>
                        <option value="7">${t('share_dlg_exp_7d')}</option>
                        <option value="30">${t('share_dlg_exp_30d')}</option>
                        <option value="90">${t('share_dlg_exp_90d')}</option>
                        <option value="custom">${t('share_dlg_exp_custom')}</option>
                    </select>
                    <input type="date" id="sh-expiry-custom"
                        style="display:none;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px"
                        min="${new Date().toISOString().slice(0,10)}">
                </div>

                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-allow-preview" style="width:16px;height:16px">
                    <span style="font-size:14px">${t('share_dlg_allow_preview')}</span>
                </label>
                ${!isDir ? `<label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-cdn-embed" style="width:16px;height:16px">
                    <span style="font-size:14px">${t('share_dlg_allow_cdn')}</span>
                </label>` : ''}

                ${isDir ? `
                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;white-space:nowrap">${t('share_dlg_upload_who')}</span>
                    <select id="sh-upload-policy" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="none">${t('share_dlg_upload_none')}</option>
                        <option value="anon">${t('share_dlg_upload_anon')}</option>
                        <option value="auth">${t('share_dlg_upload_auth')}</option>
                    </select>
                </label>` : ''}
            </div>

            <div id="sh-result" style="display:none;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;margin-bottom:14px">
                <div style="font-size:12px;color:#166534;margin-bottom:6px;font-weight:600">${t('share_dlg_link_created')}</div>
                <div style="display:flex;gap:6px">
                    <input id="sh-link-box" type="text" readonly style="flex:1;font-size:12px;padding:6px;border:1px solid #ccc;border-radius:6px;background:white;color:#1e293b">
                    <button id="sh-copy-btn" style="background:#16a34a;color:white;border:none;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px">${t('share_dlg_copy')}</button>
                </div>
            </div>

            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="sh-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">${t('cancel')}</button>
                <button id="sh-create-btn" class="btn" style="background:#8b5cf6">${t('share_dlg_create')}</button>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    // Show/hide custom date picker based on preset
    const presetSel = document.getElementById('sh-expiry-preset');
    const customInput = document.getElementById('sh-expiry-custom');
    presetSel.addEventListener('change', () => {
        customInput.style.display = presetSel.value === 'custom' ? 'block' : 'none';
    });

    // Helper: resolve expiry to ISO string or null
    function resolveExpiry() {
        const preset = presetSel.value;
        if (!preset) return null;
        if (preset === 'custom') {
            return customInput.value ? new Date(customInput.value + 'T23:59:59').toISOString() : null;
        }
        const d = new Date();
        d.setDate(d.getDate() + parseInt(preset));
        return d.toISOString();
    }

    // Capture all element references immediately — before any async gap —
    // so we don't re-query after the overlay may have been removed.
    const shCancelBtn = overlay.querySelector('#sh-cancel-btn');
    const shCreateBtn = overlay.querySelector('#sh-create-btn');
    const shResult    = overlay.querySelector('#sh-result');
    const shLinkBox   = overlay.querySelector('#sh-link-box');
    const shCopyBtn   = overlay.querySelector('#sh-copy-btn');

    shCancelBtn.addEventListener('click', () => window.fdCloseOverlay(overlay));
    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });

    let _shareCreated = false;

    shCreateBtn.addEventListener('click', async () => {
        // Fix the duplication of the shared links at specific sequences
        if (_shareCreated) { window.fdCloseOverlay(overlay); return; }

        // Guard: if overlay was removed (e.g. Cancel clicked) before the
        // async chain settles, bail out silently.
        if (!overlay.isConnected) return;

        shCreateBtn.disabled = true;
        shCreateBtn.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px">' +
            '<svg style="animation:spin 0.8s linear infinite;width:14px;height:14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>' +
            t('share_dlg_creating') + '</span>';
        if (!document.getElementById('fd-spin-style')) {
            const st = document.createElement('style');
            st.id = 'fd-spin-style';
            st.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
            document.head.appendChild(st);
        }
        // Snapshot all form values synchronously before the await
        const uploadPolicy = overlay.querySelector('#sh-upload-policy')?.value ?? 'none';
        const reqBody = {
            path,
            is_dir: isDir,
            require_account: overlay.querySelector('#sh-require-account')?.checked ?? false,
            track_stats:     overlay.querySelector('#sh-stats')?.checked ?? false,
            allow_anon_upload: isDir ? uploadPolicy === 'anon' : false,
            allow_auth_upload: isDir ? uploadPolicy === 'auth' : false,
            allow_preview:   overlay.querySelector('#sh-allow-preview')?.checked ?? false,
            allow_cdn_embed: !isDir ? (overlay.querySelector('#sh-cdn-embed')?.checked ?? false) : false,
            expires_at: resolveExpiry(),
        };
        try {
            const data = await apiCall('/api/v1/shares', 'POST', reqBody);

            // Overlay might have been closed while the request was in-flight
            if (!overlay.isConnected) return;

            const shareUrl = `${window.location.origin}/share/${data.token}`;
            shResult.style.display = 'block';
            shLinkBox.value = shareUrl;

            function doCopy() {
                navigator.clipboard.writeText(shareUrl).then(() => {
                    shCopyBtn.textContent = t('share_dlg_copied');
                    shCopyBtn.style.background = '#15803d';
                    setTimeout(() => { shCopyBtn.textContent = t('share_dlg_copy'); shCopyBtn.style.background = '#16a34a'; }, 2000);
                }).catch(() => { shLinkBox.select(); });
            }
            shCopyBtn.addEventListener('click', doCopy);
            doCopy();

            shCreateBtn.textContent = t('share_dlg_done');
            shCreateBtn.style.background = '#16a34a';
            shCreateBtn.disabled = false;
            _shareCreated = true;
            // shCreateBtn.addEventListener('click', () => overlay.remove(), { once: true });
        } catch (err) {
            if (!overlay.isConnected) return; // session expired, DOM gone — stay silent
            shCreateBtn.disabled = false;
            shCreateBtn.textContent = t('share_dlg_create');
            if (err.message !== 'SESSION_EXPIRED') showMessage(t('share_dlg_failed'), err.message);
        }
    });
}

        // ======================================================================
        // --- SHARE MANAGER (list + manage existing shares) ---
        // ======================================================================
async function openShareManager() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'share-manager-overlay';
    overlay.innerHTML = `
        <div class="modal-content" style="max-width:640px;width:95vw;max-height:80vh;display:flex;flex-direction:column;padding:0;overflow:hidden">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid #e2e8f0;flex-shrink:0">
                <h3 style="font-size:18px;font-weight:700">🔗 Shared Links</h3>
                <button id="sm-close" style="background:none;border:none;font-size:20px;cursor:pointer;color:#64748b">✕</button>
            </div>
            <div id="sm-body" style="overflow-y:auto;padding:16px 20px;flex:1">
                <p style="color:#64748b;font-size:14px">Loading…</p>
            </div>
        </div>`;
    document.body.appendChild(overlay);
    document.getElementById('sm-close').addEventListener('click', () => window.fdCloseOverlay(overlay));
    overlay.addEventListener('click', e => { if (e.target === overlay) window.fdCloseOverlay(overlay); });

    await loadShareManager();
}

async function loadShareManager() {
    const body = document.getElementById('sm-body');
    if (!body) return;
    // Skeleton share cards while fetching
    body.innerHTML = Array.from({length: 3}, () => `
        <div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;margin-bottom:10px">
                <div>
                    <span style="display:inline-block;width:160px;height:15px;border-radius:4px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span><br>
                    <span style="display:inline-block;width:100px;height:11px;border-radius:4px;margin-top:6px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
                </div>
                <div style="display:flex;gap:6px">
                    <span style="display:inline-block;width:60px;height:28px;border-radius:6px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
                    <span style="display:inline-block;width:54px;height:28px;border-radius:6px;
                        background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%);
                        background-size:200% 100%;animation:fd-shimmer 1.4s infinite"></span>
                </div>
            </div>
        </div>`).join('');
    try {
        const data = await apiCall('/api/v1/shares', 'GET');
        const shares = data.shares || [];
        if (shares.length === 0) {
            body.innerHTML = '<p style="color:#64748b;font-size:14px">No shared links yet. Use the Share button on any file or folder.</p>';
            return;
        }
        body.innerHTML = shares.map(s => renderShareRow(s)).join('');
        _initTooltipFlip()
        body.querySelectorAll('.sm-delete-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!confirm('Delete this share link? Recipients will no longer be able to access it.')) return;
                try {
                    await apiCall(`/api/v1/shares/${btn.dataset.token}`, 'DELETE');
                    await loadShareManager();
                } catch(e) { showMessage('Error', e.message); }
            });
        });
        body.querySelectorAll('.sm-toggle').forEach(cb => {
            cb.addEventListener('change', async () => {
                const token = cb.dataset.token;
                const field = cb.dataset.field;
                try {
                    await apiCall(`/api/v1/shares/${token}`, 'PATCH', { [field]: cb.checked });
                } catch(e) { showMessage('Update failed', e.message); cb.checked = !cb.checked; }
            });
        });
        body.querySelectorAll('.sm-copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                navigator.clipboard.writeText(btn.dataset.url).then(() => {
                    const orig = btn.textContent;
                    btn.textContent = 'Copied!'; btn.style.background = '#16a34a';
                    setTimeout(() => { btn.textContent = orig; btn.style.background = '#3b82f6'; }, 1500);
                });
            });
        });
        body.querySelectorAll('.sm-stats-btn').forEach(btn => {
            btn.addEventListener('click', () => openShareStats(btn.dataset.token, btn.dataset.name));
        });

        // Expiry date input — save on change (blur or Enter)
        body.querySelectorAll('.sm-expiry-input').forEach(input => {
            const saveExpiry = async () => {
                const token = input.dataset.token;
                const val = input.value;
                const expires_at = val ? new Date(val + 'T23:59:59').toISOString() : null;
                try {
                    await apiCall(`/api/v1/shares/${token}`, 'PATCH', { expires_at });
                    // Refresh to show updated display
                    await loadShareManager();
                } catch(e) { showMessage('Update failed', e.message); }
            };
            input.addEventListener('change', saveExpiry);
        });

        // Expiry clear (✕) button — remove expiry
        body.querySelectorAll('.sm-expiry-clear').forEach(btn => {
            btn.addEventListener('click', async () => {
                const token = btn.dataset.token;
                try {
                    await apiCall(`/api/v1/shares/${token}`, 'PATCH', { expires_at: null });
                    await loadShareManager();
                } catch(e) { showMessage('Update failed', e.message); }
            });
        });
    } catch(e) {
        body.innerHTML = `<p style="color:#ef4444;font-size:14px">Failed to load shares: ${e.message}</p>`;
    }
}

function _initTooltipFlip() {
    document.querySelectorAll('.fd-tooltip-wrap').forEach(wrap => {
        wrap.addEventListener('mouseenter', () => {
            const rect = wrap.getBoundingClientRect();
            // If less than 120px above the element, flip the bubble downward
            wrap.classList.toggle('fd-tooltip-below', rect.top < 240);
        });
    });
}

function renderShareRow(s) {
    const shareUrl = `${window.location.origin}/share/${s.token}`;
    const urlEsc = escapeHtmlAttr(shareUrl);
    const nameEsc = escapeHtmlAttr(s.path.split('/').pop() || s.path);
    const pathEsc = escapeHtmlAttr(s.path);
    const created = s.created_at ? new Date(s.created_at).toLocaleDateString() : '?';

    // Format expiry for display and for the date input (YYYY-MM-DD)
    let expiryDisplay = `<span style="color:#94a3b8">${t('shares_info_never')}</span>`;
    let expiryInputVal = '';
    if (s.expires_at) {
        const expDate = new Date(s.expires_at);
        const isExpired = expDate < new Date();
        expiryDisplay = isExpired
            ? `<span style="color:#ef4444;font-weight:600">${t('shares_expired_label')} ${expDate.toLocaleDateString()}</span>`
            : `<span style="color:#f59e0b;font-weight:600">⏰ ${expDate.toLocaleDateString()}</span>`;
        expiryInputVal = expDate.toISOString().slice(0, 10);
    }

    return `<div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
            <div>
                <span style="font-weight:600;font-size:14px">${s.is_dir ? '📁' : '📄'} ${nameEsc}</span>
                <span style="font-size:11px;color:#94a3b8;margin-left:8px">${pathEsc}</span>
                <div style="font-size:11px;color:#64748b;margin-top:3px">
                    ${t('shares_info_created')} ${created} · ${t('shares_access_count', {n: s.access_count || 0})} · ${t('shares_expires_label')} ${expiryDisplay}
                </div>
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0;margin-left:8px">
                ${s.track_stats ? `<button class="sm-stats-btn" data-token="${s.token}" data-name="${nameEsc}"
                    style="background:#0ea5e9;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">${t('shares_stats_button')}</button>` : ''}
                <button class="sm-copy-btn" data-url="${urlEsc}"
                    style="background:#3b82f6;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">${t('shares_copy_link_button')}</button>
                <button class="sm-delete-btn" data-token="${s.token}"
                    style="background:#ef4444;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">${t('shares_revoke_button')}</button>
            </div>
        </div>

        <div style="display:flex;gap:12px 20px;flex-wrap:wrap;align-items:center">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="require_account" ${s.require_account ? 'checked' : ''}>
                ${t('shares_info_account_requirement')}
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="track_stats" ${s.track_stats ? 'checked' : ''}>
                ${t('shares_info_stats_tracking')}
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_preview" ${s.allow_preview ? 'checked' : ''}>
                ${t('shares_info_preview')}
            </label>
            ${!s.is_dir ? `<label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_cdn_embed" ${s.allow_cdn_embed ? 'checked' : ''}>
                ${t('shares_info_cdn_embed')}
            </label>` : ''}
            ${s.is_dir ? `
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_anon_upload" ${s.allow_anon_upload ? 'checked' : ''}>
                ${t('shares_info_uploads_anyone')}
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_auth_upload" ${s.allow_auth_upload ? 'checked' : ''}>
                ${t('shares_info_uploads_auth_only')}
            </label>` : ''}
            <div style="display:flex;align-items:center;gap:6px;font-size:13px">
                <span style="white-space:nowrap">${t('shares_info_expiry')}</span>
                <input type="date" class="sm-expiry-input" data-token="${s.token}"
                    value="${expiryInputVal}"
                    style="padding:3px 7px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;color:#1e293b">
                <button class="sm-expiry-clear" data-token="${s.token}"
                    style="background:none;border:1px solid #e2e8f0;border-radius:6px;padding:3px 7px;cursor:pointer;font-size:11px;color:#94a3b8"
                    title="${t('shares_expiry_remove_title')}">✕</button>
            </div>
        </div>
        ${s.allow_cdn_embed && !s.is_dir ? `
        <div style="margin-top:10px;padding:10px;background:#fefce8;border:1px solid #fde047;border-radius:8px">
            <div style="font-size:11px;color:#854d0e;font-weight:600;margin-bottom:5px">
                ${t('shares_cdn_embed_title')}
                <span class="fd-tooltip-wrap" id="cdn-tip-wrap">
                    <span class="fd-tooltip-icon" style="font-family: Playwrite Norge; font-style: italic;">i</span>
                    <div class="fd-tooltip-bubble">${t('shares_cdn_embed_tooltip')}</div>
                </span>
            </div>
            <div style="display:flex;gap:6px">
                <input type="text" readonly value="${urlEsc}" style="flex:1;font-size:11px;padding:4px 7px;border:1px solid #fde047;border-radius:5px;background:white;color:#1e293b">
                <button class="sm-copy-btn" data-url="${urlEsc}" style="background:#ca8a04;color:white;border:none;border-radius:5px;padding:4px 10px;cursor:pointer;font-size:11px">${t('shares_copy_button')}</button>
            </div>
        </div>` : '' }
    </div>`;
}

// Translates a share-access log's action code (view/download/embed/…) to a
// localized label. Falls back to the raw action code if no translation key
// exists for it, so unknown/future action types still render something.
function _shareActionLabel(action) {
    const code = action || 'view';
    const key  = 'share_action_' + code;
    const label = t(key);
    return label !== key ? label : code;
}

async function openShareStats(token, name) {
    try {
        const data = await apiCall(`/api/v1/shares/${token}/stats`, 'GET');
        const logs = data.logs || [];
        const _anonSpan = `<span style="color:#94a3b8">${t('shares_stats_anonymous')}</span>`;
        const rows = logs.length === 0
            ? `<tr><td colspan="3" style="padding:12px;color:#94a3b8;text-align:center">${t('shares_stats_no_accesses')}</td></tr>`
            : logs.map(l => `<tr style="border-top:1px solid #f1f5f9">
                <td style="padding:8px 12px;font-size:13px">${l.accessed_at ? new Date(l.accessed_at).toLocaleString() : '?'}</td>
                <td style="padding:8px 12px;font-size:13px">${l.username || _anonSpan}</td>
                <td style="padding:8px 12px;font-size:13px">${escapeHtmlAttr(_shareActionLabel(l.action))}</td>
            </tr>`).join('');
        showMessage(t('shares_stats_title', {name}),
            `<div style="text-align:left;max-height:300px;overflow-y:auto">` +
            `<table style="width:100%;border-collapse:collapse"><thead><tr style="background:#f8fafc">
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t('shares_stats_col_time')}</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t('shares_stats_col_user')}</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">${t('shares_stats_col_action')}</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`,
            true /* isHtml */
        );
    } catch(e) { showMessage('Stats error', e.message); }
}

        // ======================================================================
        // --- UPLOAD QUEUE PANEL ---
        // ======================================================================
/**
 * Shows a modal panel listing all queued (pending) uploads with the
 * ability to remove individual items before they start.
 */
function openUploadQueuePanel(onClose) {
    // Remove any existing panel
    document.getElementById('upload-queue-panel')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'upload-queue-panel';
    overlay.style.cssText = `
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.55);display:flex;align-items:center;
        justify-content:center;z-index:10000;font-family:Inter,sans-serif;
    `;

    function buildHTML() {
        const q = window._uploadQueue || [];
        const rows = q.length === 0
            ? `<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">${t('queue_empty')}</p>`
            : q.map((item, i) => `
                <div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #334155"
                     data-qi="${i}">
                    <span style="font-size:18px">📄</span>
                    <div style="flex:1;min-width:0">
                        <div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"
                             title="${escapeHtmlAttr(item.file.name)}">${escapeHtml(item.file.name)}</div>
                        <div style="font-size:11px;color:#94a3b8">
                            ${formatBytes(item.file.size)} · ${escapeHtml(item.destRel)}
                        </div>
                    </div>
                    <button class="qp-remove" data-qi="${i}"
                        style="background:#ef4444;color:white;border:none;border-radius:6px;
                               padding:4px 10px;cursor:pointer;font-size:12px;flex-shrink:0">
                        Remove
                    </button>
                </div>`).join('');

        return `
        <div style="background:#0f172a;border-radius:14px;padding:1.5rem;
                    width:95vw;max-width:560px;max-height:80vh;overflow-y:auto;
                    color:#e2e8f0;position:relative">
            <div style="display:flex;justify-content:space-between;align-items:center;
                        margin-bottom:1rem;border-bottom:1px solid #334155;padding-bottom:.75rem">
                <span style="font-weight:700;font-size:16px">📋 Upload Queue (${q.length} pending)</span>
                <button id="qp-close" style="background:rgba(255,255,255,0.1);border:none;color:white;
                    border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:16px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div id="qp-list">${rows}</div>
            ${q.length > 0 ? `<div style="margin-top:1rem;text-align:right">
                <button id="qp-clear-all"
                    style="background:#64748b;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px">Clear all</button>
            </div>` : ''}
        </div>`;
    }

    function render() {
        overlay.innerHTML = buildHTML();
        overlay.querySelector('#qp-close').addEventListener('click', () => {
            overlay.remove();
            if (onClose) onClose();
        });
        overlay.querySelector('#qp-clear-all')?.addEventListener('click', () => {
            window._uploadQueue = [];
            render();
            if (onClose) onClose();
        });
        overlay.querySelectorAll('.qp-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                const i = +btn.dataset.qi;
                window._uploadQueue.splice(i, 1);
                render();
                if (onClose) onClose();
            });
        });
        // Close on overlay click
        overlay.addEventListener('click', ev => {
            if (ev.target === overlay) { overlay.remove(); if (onClose) onClose(); }
        });
    }

    document.body.appendChild(overlay);
    render();
}

        // ======================================================================
        // --- INTERRUPTED UPLOADS MANAGER ---
        // ======================================================================
/**
 * Shows a modal panel listing all interrupted (localStorage-persisted) uploads.
 * Each item shows filename, size, destination, estimated progress, and offers
 * Resume (opens file picker for that file) or Discard buttons.
 */
function openInterruptedManager(onClose) {
    document.getElementById('interrupted-manager-panel')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'interrupted-manager-panel';
    overlay.className = 'modal-overlay';
    overlay.style.cssText = `
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.55);display:flex;align-items:center;
        justify-content:center;z-index:10000;font-family:Inter,sans-serif;
    `;

    function buildHTML(pending) {
        const rows = pending.length === 0
            ? `<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">No interrupted uploads found.</p>`
            : pending.map((meta, i) => {
                const pct = meta.total > 0
                    ? Math.min(100, Math.round(((meta.nextChunkIdx || 0) * (meta.chunkSize || 1)) / meta.total * 100))
                    : 0;
                const progressColor = '#22c55e';
                return `
                <div style="padding:12px 0;border-bottom:1px solid #334155" data-im="${i}">
                    <div style="display:flex;align-items:flex-start;gap:10px">
                        <span style="font-size:22px;margin-top:2px">📄</span>
                        <div style="flex:1;min-width:0">
                            <div style="font-weight:600;white-space:nowrap;overflow:hidden;
                                        text-overflow:ellipsis;margin-bottom:2px"
                                 title="${escapeHtmlAttr(meta.filename)}">${escapeHtml(meta.filename)}</div>
                            <div style="font-size:11px;color:#94a3b8;margin-bottom:6px">
                                ${formatBytes(meta.total)} · ${escapeHtml(meta.destRel)}
                            </div>
                            <div style="background:#1e293b;border-radius:4px;height:6px;margin-bottom:4px">
                                <div style="background:${progressColor};height:6px;border-radius:4px;width:${pct}%"></div>
                            </div>
                            <div style="font-size:11px;color:#64748b">${pct}% uploaded before interruption</div>
                        </div>
                        <div style="display:flex;flex-direction:column;gap:5px;flex-shrink:0">
                            <button class="im-resume" data-im="${i}"
                                style="background:#22c55e;color:white;border:none;border-radius:6px;
                                       padding:5px 12px;cursor:pointer;font-size:12px;font-weight:600">
                                ▶ Resume
                            </button>
                            <button class="im-discard" data-im="${i}"
                                style="background:#ef4444;color:white;border:none;border-radius:6px;
                                       padding:5px 12px;cursor:pointer;font-size:12px">
                                🗑 Discard
                            </button>
                        </div>
                    </div>
                </div>`;
            }).join('');

        return `
        <div class="fd-modal-panel-in" style="background:#0f172a;border-radius:14px;padding:1.5rem;
                    width:95vw;max-width:600px;max-height:82vh;overflow-y:auto;
                    color:#e2e8f0;position:relative">
            <div style="display:flex;justify-content:space-between;align-items:center;
                        margin-bottom:1rem;border-bottom:1px solid #334155;padding-bottom:.75rem">
                <span style="font-weight:700;font-size:16px">⟳ Interrupted Uploads (${pending.length})</span>
                <button id="im-close" style="background:rgba(255,255,255,0.1);border:none;color:white;
                    border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:16px;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <p style="font-size:12px;color:#64748b;margin-bottom:12px">
                To resume, click <strong style="color:#22c55e">Resume</strong> and select the same file from your computer.
                The upload will continue from where it left off.
            </p>
            <div id="im-list">${rows}</div>
            ${pending.length > 1 ? `<div style="margin-top:1rem;text-align:right">
                <button id="im-discard-all"
                    style="background:#64748b;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px">Discard all</button>
            </div>` : ''}
        </div>`;
    }

    async function doResume(meta) {
        // Ask server for authoritative chunk status first
        let startIdx = meta.nextChunkIdx || 0;
        try {
            const statusRes = await fetchWithFallback(
                `${API_BASE_URL}/api/v1/upload_session/${meta.uploadToken}/status`,
                { method: 'GET', headers: authToken ? { Authorization: `Bearer ${authToken}` } : {} }
            );
            if (statusRes.ok) {
                const st = await statusRes.json();
                if (st.missing_chunks && st.missing_chunks.length > 0) {
                    startIdx = st.missing_chunks[0];
                } else if (!st.missing_chunks || st.missing_chunks.length === 0) {
                    // Already complete on server — just finalize
                    await fetchWithFallback(
                        `${API_BASE_URL}/api/v1/upload_session/${meta.uploadToken}/complete`,
                        { method: 'POST', headers: authToken ? { Authorization: `Bearer ${authToken}` } : {} }
                    );
                    removeInterruptedUpload(meta.uploadToken);
                    if (onClose) onClose();
                    overlay.remove();
                    loadDirectory(currentPath);
                    return;
                }
            } else {
                // Session expired — remove stale record
                removeInterruptedUpload(meta.uploadToken);
                if (onClose) onClose();
                render(getAllInterruptedUploads());
                showMessage('Session expired', `The upload session for "${meta.filename}" has expired on the server. Please upload the file again.`);
                return;
            }
        } catch { /* proceed with stored chunk index */ }

        // Open file picker for just this file
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.style.display = 'none';
        document.body.appendChild(fileInput);
        fileInput.click();
        fileInput.addEventListener('change', async () => {
            document.body.removeChild(fileInput);
            if (!fileInput.files.length) return;
            const f = fileInput.files[0];
            if (f.name !== meta.filename || f.size !== meta.total) {
                showMessage('File mismatch',
                    `Expected "${meta.filename}" (${formatBytes(meta.total)}) but got "${f.name}" (${formatBytes(f.size)}). Please select the exact same file.`);
                return;
            }
            overlay.remove();
            uploadChunked(f, meta.destRel, {
                ownerType:        meta.ownerType,
                shareToken:       meta.shareToken || '',
                resumeToken:      meta.uploadToken,
                resumeFromChunk:  startIdx,
                resumeChunkSize:  meta.chunkSize,
                resumeAnonToken:  meta.anonDeviceToken,
            }).then(() => {
                loadDirectory(currentPath);
                if (onClose) onClose();
            }).catch(err => {
                if (err.name !== 'PauseSignal' && err.message !== 'Upload cancelled') {
                    showMessage('Resume failed', err.message);
                }
                if (onClose) onClose();
            });
        });
    }

    function closePanel() {
        _detachModalKeys();
        window.fdCloseOverlay(overlay);
        if (onClose) onClose();
    }

    function render(pending) {
        overlay.innerHTML = buildHTML(pending);

        overlay.querySelector('#im-close').addEventListener('click', closePanel);
        overlay.addEventListener('click', ev => {
            if (ev.target === overlay) closePanel();
        });
        // Esc closes the panel — Enter deliberately left unbound (no single
        // "confirm" action makes sense for this list of independent
        // Resume/Discard buttons; binding it could accidentally trigger a
        // buried default action from stray keyboard focus).
        _attachModalKeys(null, closePanel);

        overlay.querySelector('#im-discard-all')?.addEventListener('click', () => {
            getAllInterruptedUploads().forEach(m => removeInterruptedUpload(m.uploadToken));
            render(getAllInterruptedUploads());
            if (onClose) onClose();
        });

        overlay.querySelectorAll('.im-resume').forEach(btn => {
            btn.addEventListener('click', async () => {
                const pending = getAllInterruptedUploads();
                const meta = pending[+btn.dataset.im];
                if (!meta) return;
                await doResume(meta);
            });
        });

        overlay.querySelectorAll('.im-discard').forEach(btn => {
            btn.addEventListener('click', () => {
                const pending = getAllInterruptedUploads();
                const meta = pending[+btn.dataset.im];
                if (!meta) return;
                removeInterruptedUpload(meta.uploadToken);
                // Best-effort server cancel
                fetchWithFallback(
                    `${API_BASE_URL}/api/v1/upload_session/${meta.uploadToken}/cancel`,
                    { method: 'DELETE', headers: authToken ? { Authorization: `Bearer ${authToken}` } : {} }
                ).catch(() => {});
                render(getAllInterruptedUploads());
                if (onClose) onClose();
            });
        });
    }

    document.body.appendChild(overlay);
    render(getAllInterruptedUploads());
}

        // ======================================================================
        // --- INITIALIZATION ---
        // ======================================================================
document.addEventListener('DOMContentLoaded', () => {
    // ── Service Worker registration ───────────────────────────────────────
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register(
            _APP_BASE + '/sw.js',
            { scope: _APP_BASE + '/' }
        ).catch(err => {
            // Registration failure is non-fatal; app still works online.
            // Log it though — a failed registration is worth knowing about.
            console.warn('[FluxDrop] SW registration failed:', err);
        });
    }

    // ── Offline / online banner ───────────────────────────────────────────
    // We don't trust navigator.onLine alone — it can be true even when the
    // server is unreachable (captive portals, DNS failure, etc.).  Instead we
    // probe the server's /api/v1/upload_session/config endpoint (tiny, no auth,
    // no side effects) to confirm real connectivity before removing the banner.
    let _probeTimer = null;
    let _isOffline  = false;

    function createOfflineBanner() {
        if (document.getElementById('offline-banner')) return;
        const banner = document.createElement('div');
        banner.id = 'offline-banner';
        banner.style.cssText = [
            'position:fixed;top:0;left:0;width:100%;z-index:99999',
            'background:#1e293b;color:#e2e8f0',
            'display:flex;align-items:center;justify-content:center;gap:10px',
            'padding:10px 16px;font-family:Inter,sans-serif;font-size:14px',
            'font-weight:500;box-shadow:0 2px 8px rgba(0,0,0,0.3)',
            'transform:translateY(-100%);transition:transform 0.3s ease',
        ].join(';');
        banner.innerHTML = `
            <span style="font-size:18px">📡</span>
            <span id="offline-banner-text">Seems like you're offline. Please connect to the internet to access FluxDrop.</span>
        `;
        document.body.prepend(banner);
        requestAnimationFrame(() => requestAnimationFrame(() => {
            banner.style.transform = 'translateY(0)';
        }));
    }

    function removeOfflineBanner() {
        const banner = document.getElementById('offline-banner');
        if (!banner) return;
        banner.style.transform = 'translateY(-100%)';
        setTimeout(() => banner.remove(), 320);
    }

    async function probeConnectivity() {
        // A HEAD request to the config endpoint is ~200 bytes and requires no auth
        try {
            const r = await fetch(`${API_BASE_URL}/api/v1/upload_session/config`, {
                method: 'HEAD', cache: 'no-store',
                signal: AbortSignal.timeout(4000),
            });
            return r.ok || r.status < 500; // 4xx = server reachable, counts as online
        } catch {
            return false;
        }
    }

    function startOnlineProbe() {
        if (_probeTimer) return;
        _probeTimer = setInterval(async () => {
            const reachable = await probeConnectivity();
            if (reachable) {
                _isOffline = false;
                removeOfflineBanner();
                clearInterval(_probeTimer);
                _probeTimer = null;
            } else {
                // Still down — update banner text to show retrying
                const txt = document.getElementById('offline-banner-text');
                if (txt) txt.textContent = "You're offline — retrying connection…";
            }
        }, 5000); // probe every 5 s until back online
    }

    function goOffline() {
        if (_isOffline) return;
        _isOffline = true;
        createOfflineBanner();
        startOnlineProbe();
    }

    function onlineEventFired() {
        // Browser fired 'online' — probe first, don't trust it blindly
        probeConnectivity().then(ok => {
            if (ok) { _isOffline = false; removeOfflineBanner(); clearInterval(_probeTimer); _probeTimer = null; }
            // if probe fails, goOffline() keeps the banner up and probe loop running
        });
    }

    window.addEventListener('offline', goOffline);
    window.addEventListener('online',  onlineEventFired);

    // Initial check: if navigator says offline immediately show banner + probe loop
    if (!navigator.onLine) {
        goOffline();
    }

    // Replace the existing keydown listener (around line 2689 in original):
    document.addEventListener('keydown', e => {
        if (e.key !== 'Escape') return;
        // Priority order: preview → move dialog → share dialog → share manager → message modal
        if (!document.getElementById('preview-modal').classList.contains('hidden')) {
            closePreview();
        } else if (document.getElementById('mv-dialog-overlay')) {
            window.fdCloseOverlay(document.getElementById('mv-dialog-overlay'));
        } else if (document.getElementById('share-dialog-overlay')) {
            window.fdCloseOverlay(document.getElementById('share-dialog-overlay'));
        } else if (document.getElementById('ap-edit-overlay')) {
            window.fdCloseOverlay(document.getElementById('ap-edit-overlay'));
        } else if (document.getElementById('admin-panel-overlay')) {
            window.fdCloseOverlay(document.getElementById('admin-panel-overlay'));
        } else if (document.getElementById('profile-panel-overlay')) {
            window.fdCloseOverlay(document.getElementById('profile-panel-overlay'));
        } else if (document.getElementById('share-manager-overlay')) {
            window.fdCloseOverlay(document.getElementById('share-manager-overlay'));
        } else if (document.getElementById('profile-menu-modal')) {
            window.fdCloseOverlay(document.getElementById('profile-menu-modal'));
        } else {
            hideModal('message-modal');
        }
    });

    // Del key: trash the current selection. Guarded so it never fires while
    // typing (rename fields, filter boxes, etc.) or while another overlay
    // (preview, move/share dialogs, admin/profile panels, trash view) is on
    // top of the file list — those should own Delete/text-input semantics.
    document.addEventListener('keydown', e => {
        if (e.key !== 'Delete') return;
        const ae = document.activeElement;
        if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.isContentEditable)) return;
        if (!document.getElementById('preview-modal').classList.contains('hidden')) return;
        if (document.getElementById('mv-dialog-overlay') || document.getElementById('share-dialog-overlay') ||
            document.getElementById('ap-edit-overlay') || document.getElementById('admin-panel-overlay') ||
            document.getElementById('profile-panel-overlay') || document.getElementById('share-manager-overlay') ||
            document.getElementById('profile-menu-modal') || document.getElementById('trash-overlay')) return;
        if (_selectedPaths.size === 0) return;
        e.preventDefault();
        _trashSelectedPaths([..._selectedPaths]);
    });
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('verified')) {
        showMessage('Verification Successful', 'Your account is verified. Please log in.');
        // Clean the URL
        window.history.replaceState({}, document.title, window.location.pathname);
    }

    // ── App version / stale-cache check ──────────────────────────────────────
    // After the first render we silently probe index.html and script.js with
    // cache:no-store to get their current Last-Modified dates from the server.
    // If either differs from what the running page loaded, the user is on a
    // stale cached version and we show a soft "update available" banner.
    //
    // Why Last-Modified and not ETag?  The HTTPS server sends Last-Modified
    // for all files served via SimpleHTTPRequestHandler; ETags are not set.
    // A mismatch means the file on disk changed since this tab was loaded.
    //
    // We wait 2s after DOMContentLoaded so the check doesn't compete with the
    // initial API calls (list, foldersize, policy) for the limited connections.
    renderApp();
    setTimeout(async () => {
        // Only bother when a SW is actually controlling this page
        if (!('serviceWorker' in navigator) || !navigator.serviceWorker.controller) return;

        // If this page load was triggered by _fdHardReload (user clicked the
        // update banner), the page is already running the latest code — skip
        // the staleness check so the banner doesn't immediately reappear.
        try {
            if (sessionStorage.getItem('fd_just_updated') === '1') {
                sessionStorage.removeItem('fd_just_updated');
                return;
            }
        } catch (_) {}

        // Step 0: Compare embedded SCRIPT_VERSION with the SW's cache name version.
        // When they match the SW is already serving this exact build — no probe needed.
        // (Skip this gate if the build script didn't substitute the version token.)
        if (!SCRIPT_VERSION_RAW.includes('@@')) {
            try {
                const swVer = await new Promise((resolve, reject) => {
                    const ch = new MessageChannel();
                    ch.port1.onmessage = e => (e.data?.version ? resolve(e.data.version) : reject());
                    navigator.serviceWorker.controller.postMessage({ type: 'GET_VERSION' }, [ch.port2]);
                    setTimeout(() => reject(new Error('sw-timeout')), 3000);
                });
                if (swVer === SCRIPT_VERSION) return; // versions match — skip probe
            } catch (_) { /* SW didn't respond or version mismatch — fall through */ }
        }

        // Step 1: File-level staleness probe.
        // FIX: was Promise.any() which resolves with the FIRST settled value regardless
        // of whether it is true or false — so if index.html resolved first with `false`,
        // the whole check returned "not stale" even when script.js was stale.
        // Correct approach: Promise.all + .some().
        const TRACKED = [
            _APP_BASE + '/index.html',
            _APP_BASE + '/script.js',
        ];

        try {
            const cache = await caches.open('fluxdrop-v-604d7592'); // replaced by build.sh — do not edit manually

            const stalenessChecks = await Promise.all(
                TRACKED.map(async (url) => {
                    try {
                        const netResp = await fetch(url, {
                            method: 'HEAD',
                            cache:  'no-store',
                            signal: AbortSignal.timeout(8000),
                        });
                        if (!netResp.ok) return false; // server error → don't nag

                        const cached = await cache.match(url, { ignoreMethod: true });
                        if (!cached) return true; // not in cache → stale

                        // Compare by ETag first, Last-Modified as fallback, Content-Length last
                        const netEtag   = netResp.headers.get('ETag');
                        const cacheEtag = cached.headers.get('ETag');
                        if (netEtag && cacheEtag) return netEtag !== cacheEtag;

                        const netMod   = netResp.headers.get('Last-Modified');
                        const cacheMod = cached.headers.get('Last-Modified');
                        if (netMod && cacheMod) return netMod !== cacheMod;

                        const netLen   = netResp.headers.get('Content-Length');
                        const cacheLen = cached.headers.get('Content-Length');
                        if (netLen && cacheLen && netLen !== cacheLen) return true;

                        return false; // headers absent or identical — assume fresh
                    } catch {
                        return false; // network error for this file → don't nag
                    }
                })
            );

            if (stalenessChecks.some(s => s)) {
                _showUpdateBanner();
            }
        } catch {
            // Non-fatal — if the check fails silently the user just won't see
            // the banner.  They can always hard-reload (F5 / ⌘R) manually.
        }
    }, 2000);
});
        // ======================================================================
        // --- FOOTER UI ---
        // ======================================================================
function initFooter() {
    const footer = document.createElement('footer');
    footer.id = 'fluxdrop-footer';

    // Static flow — sits below #app-root.  The <body> is already a flex-col
    // with min-h-screen, so on short pages this naturally reaches the bottom.
    // On tall pages (long file listings) the footer is simply below the card,
    // never overlapping content.
    Object.assign(footer.style, {
        width: '100%',
        maxWidth: '64rem',  // matches max-w-5xl
        marginTop: 'auto',
        paddingTop: '0.75rem',
        paddingBottom: '0.5rem',
        color: '#a0aec0',
        fontSize: '11px',
        fontFamily: 'sans-serif',
        fontWeight: '300',
        textAlign: 'right',
        lineHeight: '1.5',
    });


    // Inject retry-pulse keyframe once (shared by upload + download trays)
    if (!document.getElementById('fd-retry-pulse-style')) {
        const _rps = document.createElement('style');
        _rps.id = 'fd-retry-pulse-style';
        _rps.textContent = '@keyframes fd-retry-pulse{0%,100%{opacity:1}50%{opacity:.45}}';
        document.head.appendChild(_rps);
    }
    // Helper to generate the HTML
    const renderContent = (swVer, srvVer) => `
        <div>FluxDrop Preview Program | <a href="https://github.com/ArsenijN/server/" style="color: #a0a0a0; text-decoration: underline;">GitHub repo</a></div>
        <div>&copy; 2025-2026 by Arsenii Nochevnyi.</div>
        <div><button onclick="showPolicyModal('tos')" style="background:none; border:none; color:#a0a0a0; cursor:pointer; text-decoration:underline; padding:0; font:inherit;">TOS</button> | <button onclick="showPolicyModal('pp')" style="background:none; border:none; color:#a0a0a0; cursor:pointer; text-decoration:underline; padding:0; font:inherit;">Privacy Policy</button></div>
        <div style="opacity:.7">Script v.${SCRIPT_VERSION} · SW v.${swVer} · Server v.${srvVer || '?'}</div>
    `;

    let _swVer = '...', _srvVer = '...';
    const _footerUpdate = () => { footer.innerHTML = renderContent(_swVer, _srvVer); };

    footer.innerHTML = renderContent(_swVer, _srvVer);
    document.body.appendChild(footer);

    // Request the exact Service Worker version
    if (navigator.serviceWorker && navigator.serviceWorker.controller) {
        const messageChannel = new MessageChannel();
        messageChannel.port1.onmessage = (event) => {
            if (event.data && event.data.version) {
                _swVer = event.data.version;
                _footerUpdate();
            }
        };
        navigator.serviceWorker.controller.postMessage({ type: 'GET_VERSION' }, [messageChannel.port2]);
    } else {
        _swVer = 'N/A';
        _footerUpdate();
    }

    // Fetch server version from status endpoint (no auth required)
    fetch(API_BASE_URL + '/api/v1/status.json', { cache: 'no-store' })
        .then(r => r.ok ? r.json() : null)
        .then(d => { if (d && d.server_version) { _srvVer = d.server_version; _footerUpdate(); } })
        .catch(() => { _srvVer = '?'; _footerUpdate(); });
}

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', initFooter);