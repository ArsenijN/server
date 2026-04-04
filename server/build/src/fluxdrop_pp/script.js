// ======================================================================
        // --- CONFIGURATION ---
        // ======================================================================
// Prefer HTTPS, but fall back to HTTP if HTTPS is unreachable
const API_HTTPS = `https://${window.location.hostname}:64800`;
const API_HTTP  = `http://${window.location.hostname}:63512`;

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
function showModal(id) { document.getElementById(id).classList.remove('hidden'); }
function hideModal(id) { document.getElementById(id).classList.add('hidden'); }

function stripInternalPrefix(path) {
    return path.replace(/^\/FluxDrop\/\d+\//, '/');
}

function escapeHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showMessage(title, content, isHtml = false) {
    document.getElementById('message-modal-title').textContent = title;
    const el = document.getElementById('message-modal-content');
    if (isHtml) { el.innerHTML = content; } else { el.textContent = content; }
    showModal('message-modal');
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

        // ======================================================================
        // --- UI RENDERING & ROUTING ---
        // ======================================================================
function renderAuthControls() {
    if (authToken) {
        authControls.innerHTML = `
            <div class="flex items-center gap-3">
                <span class="font-medium text-blue-900">Welcome, ${currentUsername}!</span>
                <button id="profile-btn" title="Profile & Settings"
                    style="width:36px;height:36px;border-radius:50%;background:#3b82f6;border:2px solid #93c5fd;
                            color:white;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;
                            transition:background .2s;" onmouseenter="this.style.background='#2563eb'" onmouseleave="this.style.background='#3b82f6'">
                    👤
                </button>
                <button id="logout-btn" class="btn bg-red-500 hover:bg-red-600 text-sm">Logout</button>
            </div>
        `;
        document.getElementById('logout-btn').addEventListener('click', handleLogout);
        document.getElementById('profile-btn').addEventListener('click', openProfileMenu);
    } else {
        authControls.innerHTML = `
            <div class="flex items-center gap-4">
                <button id="show-login-btn" class="btn text-sm">Login</button>
                <button id="show-register-btn" class="btn bg-green-500 hover:bg-green-600 text-sm">Register</button>
            </div>
        `;
        document.getElementById('show-login-btn').addEventListener('click', () => renderApp('login'));
        document.getElementById('show-register-btn').addEventListener('click', () => renderApp('register'));
    }
}

function renderApp(route = 'login') {
    renderAuthControls();
    if (!authToken) {
        if (route === 'register') renderRegisterView();
        else renderLoginView();
        return;
    }
// If authenticated, render the main app view (file browser)
renderFileBrowserView();

}

function renderLoginView() {
    appRoot.innerHTML = `
        <div class="card">
            <h2 class="text-2xl font-semibold mb-6 text-center text-blue-800">Login</h2>
            <form id="login-form" class="space-y-4">
                <input type="text" id="username" class="w-full p-3 border rounded-lg" placeholder="Username" required>
                <input type="password" id="password" class="w-full p-3 border rounded-lg" placeholder="Password" required>
                <button type="submit" class="btn w-full">Login</button>
            </form>
        </div>
    `;
    document.getElementById('login-form').addEventListener('submit', handleLogin);
}

function renderRegisterView() {
    appRoot.innerHTML = `
        <div class="card">
            <h2 class="text-2xl font-semibold mb-6 text-center text-blue-800">Register</h2>
            <form id="register-form" class="space-y-4">
                <input type="text" id="reg-username" class="w-full p-3 border rounded-lg" placeholder="Username (for login)" required>
                <input type="text" id="reg-nickname" class="w-full p-3 border rounded-lg" placeholder="Nickname (publicly visible)" required>
                <input type="email" id="reg-email" class="w-full p-3 border rounded-lg" placeholder="Email Address" required>
                <input type="password" id="reg-password" class="w-full p-3 border rounded-lg" placeholder="Password" required>
                <button type="submit" class="btn w-full">Register</button>
            </form>
        </div>
    `;
    document.getElementById('register-form').addEventListener('submit', handleRegister);
}

function renderFileBrowserView() {
    // Simple file browser UI: listing, upload, create folder, rename, delete, preview
    appRoot.innerHTML = `
        <div class="card" style="min-height:520px">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-2xl font-semibold text-blue-800">File Browser</h2>
                <div class="flex gap-2">
                    <button id="btn-up" class="btn bg-gray-300 text-black text-sm">Up</button>
                    <button id="btn-refresh" class="btn text-sm">Refresh</button>
                    <button id="btn-create-folder" class="btn bg-gray-200 text-black text-sm">New Folder</button>
                    <button id="btn-browse-cdn" class="btn bg-yellow-300 text-black text-sm">Browse CDN</button>
                    <button id="btn-trash" class="btn text-sm" style="background:#dc2626;color:#fff" title="Trash bin">🗑 Trash</button>
                    <button id="btn-folders-mixed" class="btn text-sm" title="Toggle folders-first vs mixed sorting"></button>
                </div>
            </div>

            <div id="path-breadcrumb" class="text-sm text-gray-600 mb-4"></div>

            <div class="mb-4">
                <form id="upload-form" class="flex gap-2 items-center flex-wrap">
                    <input type="file" id="upload-file" class="p-2 border rounded" multiple />
                    <button type="button" id="btn-folder-toggle" class="btn text-sm"
                        style="background:#0ea5e9" title="Switch to folder upload mode">📁 Folder</button>
                    <label class="text-sm"><input type="checkbox" id="upload-protected" /> Protected</label>
                    <button class="btn" id="btn-upload-submit" type="submit">Upload</button>
                    <span id="upload-spinner" style="display:none;font-size:18px;animation:spin 0.8s linear infinite">⏳</span>
                    <button type="button" id="btn-show-queue"
                        class="btn text-sm hidden"
                        style="background:#6366f1"
                        title="View upload queue">
                        📋 Queue (<span id="queue-count">0</span>)
                    </button>
                    <button type="button" id="btn-resume-interrupted"
                        class="btn text-sm hidden"
                        style="background:#f59e0b"
                        title="Manage interrupted uploads">
                        ⟳ Interrupted (<span id="interrupted-count">0</span>)
                    </button>
                </form>
            </div>

            <div id="file-list" class="mt-4" style="min-height:320px"></div>
        </div>
    `;

    document.getElementById('btn-refresh').addEventListener('click', () => loadDirectory(currentPath));
    document.getElementById('btn-up').addEventListener('click', () => {
        if (currentPath === '/' || currentPath === '/cdn') return;
        // strip trailing slash
        let p = currentPath.replace(/\/+$/, '');
        let idx = p.lastIndexOf('/');
        if (idx <= 0) p = '/'; else p = p.slice(0, idx);
        currentPath = p;
        loadDirectory(currentPath);
    });
    document.getElementById('btn-create-folder').addEventListener('click', promptCreateFolder);
    document.getElementById('btn-browse-cdn').addEventListener('click', () => { currentPath = '/cdn'; loadDirectory(currentPath); });
    document.getElementById('btn-trash').addEventListener('click', openTrashView);
    // Folders-first toggle
    function updateFoldersMixedBtn() {
        const btn = document.getElementById('btn-folders-mixed');
        if (!btn) return;
        btn.textContent = sortFoldersMixed ? '🔀 Mixed' : '📁 Folders first';
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
            _folderBtn.textContent = '📄 Files';
            _folderBtn.style.background = '#6366f1';
            _folderBtn.title = 'Switch back to file upload mode';
        } else {
            _fileInput.removeAttribute('webkitdirectory');
            _fileInput.removeAttribute('mozdirectory');
            _fileInput.setAttribute('multiple', '');
            _folderBtn.textContent = '📁 Folder';
            _folderBtn.style.background = '#0ea5e9';
            _folderBtn.title = 'Switch to folder upload mode';
        }
        _fileInput.value = '';
    });

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
    const shimmer = [
        'background:linear-gradient(90deg,#e2e8f0 25%,#f1f5f9 50%,#e2e8f0 75%)',
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
            <td style="padding:9px 8px;vertical-align:middle">
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
                html += `<button onclick="loadDirectory('/')" style="background:none;border:none;color:#3b82f6;cursor:pointer;font-weight:600;padding:0 2px">🏠 root</button>`;
            } else {
                built = built.endsWith('/') ? built + seg : built + '/' + seg;
                const bp = built;
                html += ` <span style="color:#94a3b8">/</span> `;
                const isLast = idx === segs.length - 1;
                if (isLast) {
                    html += `<span style="color:#1e293b;font-weight:600">${escapeHtml(seg)}</span>`;
                } else {
                    html += `<button onclick="loadDirectory('${escapeHtmlAttr(bp)}')" style="background:none;border:none;color:#3b82f6;cursor:pointer;padding:0 2px">${escapeHtml(seg)}</button>`;
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
            { key: 'mtime', label: 'Modified',  align: 'left'  },
        ];
        const thStyle = (align) =>
            `padding:8px;font-size:12px;font-weight:600;color:#64748b;text-align:${align};` +
            `user-select:none;white-space:nowrap;`;
        const btnStyle =
            `background:none;border:none;cursor:pointer;font-size:12px;font-weight:700;` +
            `color:#64748b;padding:0;display:inline-flex;align-items:center;gap:3px;`;
        const ths = cols.map(c => {
            const arrow = currentSort.key === c.key
                ? (currentSort.dir === 'asc' ? ' ▲' : ' ▼')
                : ' ⇅';
            const activeStyle = currentSort.key === c.key
                ? 'color:#2563eb;' : '';
            return `<th style="${thStyle(c.align)}">
                <button onclick="window._sortBy('${c.key}')"
                    style="${btnStyle}${activeStyle}">${c.label}<span style="font-size:10px;opacity:.7">${arrow}</span></button>
            </th>`;
        }).join('');
        return `<thead><tr style="border-bottom:2px solid #e2e8f0">
            ${ths}
            <th style="${thStyle('right')}">Actions</th>
        </tr></thead>`;
    }

    const TABLE_WRAP = `<table style="width:100%;table-layout:fixed;border-collapse:collapse">
        <colgroup>
            <col style="width:36%">
            <col style="width:10%">
            <col style="width:16%">
            <col style="width:38%">
        </colgroup>`;

    // Show skeleton rows immediately so the table shape appears while fetching
    fileList.innerHTML = TABLE_WRAP + sortHeaders() +
        `<tbody>${skeletonRows(7)}</tbody></table>`;

    try {
        const endpoint = path === '/' ? '/api/v1/list/' : `/api/v1/list${encodePath(path)}`;
        const data = await apiCall(endpoint, 'GET', null, true);
        const entries = data.entries || [];
        if (entries.length === 0) {
            fileList.innerHTML = `<p class="text-sm text-gray-600" style="padding:1rem">(empty)</p>`;
            return;
        }
        const sorted = sortEntries(entries);
        const rows = sorted.map(e => renderEntryRow(e)).join('');
        fileList.innerHTML = TABLE_WRAP + sortHeaders() +
            `<tbody>${rows}</tbody></table>`;
        attachRowListeners();
    } catch (err) {
        fileList.innerHTML = `<p class="text-sm text-red-600" style="padding:1rem">Failed to load directory: ${err.message}</p>`;
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
    const nameEsc    = escapeHtml(e.name);
    const path       = e.path;
    const safePA     = escapeHtmlAttr(path);
    // Folders show '—' initially; size is loaded lazily via loadFolderSize()
    const sizeStr    = e.is_dir
        ? `<span class="folder-size-cell" data-path="${safePA}" style="color:#94a3b8">…</span>`
        : formatBytes(e.size);

    // Name cell: plain <button> instead of <a> — no href, no status-bar tooltip in any browser
    const TD_NAME = 'style="padding:9px 8px;vertical-align:middle;overflow:hidden"';
    const nameBtn = e.is_dir
        ? `<button class="open-btn" data-path="${safePA}"
               style="background:none;border:none;cursor:pointer;font-weight:600;
                      color:#2563eb;font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%"
               title="${safePA}">📁 ${nameEsc}</button>`
        : `<button class="preview-btn" data-path="${safePA}"
               style="background:none;border:none;cursor:pointer;font-weight:500;
                      color:#1e293b;font-size:14px;text-align:left;padding:0;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%"
               title="${safePA}">📄 ${nameEsc}</button>`;

    const uploaderLine = e.uploader
        ? `<div style="font-size:11px;color:#94a3b8;margin-top:2px">by ${escapeHtml(e.uploader)}</div>`
        : '';

    // Action buttons — compact, always single row
    const p = { path: safePA };
    const pd = { path: safePA, isdir: e.is_dir ? '1' : '0' };
    const btnOpen     = _ab('Open',     'open-btn',     '#3b82f6', p);
    const btnDl       = _ab('Download', 'download-btn', '#3b82f6', p);
    const btnZip      = _ab('⬇ ZIP',   'zip-btn',      '#0891b2', p);
    const btnPreview  = _ab('Preview',  'preview-btn',  '#f59e0b', p);
    const btnShare    = _ab('Share',    'share-btn',    '#8b5cf6', pd);
    const btnTrash    = _ab('🗑',        'delete-btn',   '#dc2626', p);
    const btnMove     = _ab('Move/Rename', 'move-btn',  '#64748b', p);

    const actionBtns = e.is_dir
        ? [btnOpen, btnZip, btnShare, btnTrash, btnMove].join(' ')
        : [btnDl, btnPreview, btnShare, btnTrash, btnMove].join(' ');
    const TD_COMMON  = 'style="padding:9px 8px;vertical-align:middle;white-space:nowrap"';
    const TD_ACTIONS = 'style="padding:9px 8px;vertical-align:middle;text-align:right;min-width:220px"';

    return `<tr class="border-t" style="transition:background 0.12s" onmouseenter="this.style.background='#f8fafc'" onmouseleave="this.style.background=''">
        <td ${TD_NAME}>${nameBtn}${uploaderLine}</td>
        <td ${TD_COMMON} class="text-sm text-gray-500">${sizeStr}</td>
        <td ${TD_COMMON} class="text-sm text-gray-500">${e.mtime}</td>
        <td ${TD_ACTIONS}>${actionBtns}</td>
    </tr>`;
}

// Expose some functions globally for callers; listeners will invoke these.
window.enterDir = function(path) {
    // Navigate into a directory and update currentPath
    loadDirectory(path);
}


        // ======================================================================
        // --- DOWNLOAD MANAGER (resumable, progress-tracked) ---
        // NOTE: renderDownloadTray uses stable DOM patching so button clicks are
        // never lost mid-stream (no full innerHTML replacement while downloading).
        // ======================================================================
// Active downloads map: path -> { dlToken, totalSize, bytesReceived,
//   chunks[], abortController, status, filename }
const activeDownloads = new Map();

// Render (or update) the floating download tray.
// Uses stable DOM patching: the tray container and each row are only
// created once; subsequent calls only update text/bar/class values so
// buttons are never re-created mid-click.
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
    }

    if (activeDownloads.size === 0) {
        tray.innerHTML = '';
        return;
    }

    // --- Header (create once) ---
    let header = tray.querySelector('.dl-tray-header');
    if (!header) {
        header = document.createElement('div');
        header.className = 'dl-tray-header';
        header.style.cssText = 'padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;';
        header.innerHTML = `<span class="dl-count"></span><span style="cursor:pointer;opacity:.6" id="dl-tray-close">✕</span>`;
        tray.prepend(header);
        header.querySelector('#dl-tray-close').addEventListener('click', () => { tray.innerHTML = ''; });
    }
    header.querySelector('.dl-count').textContent = `📥 Downloads (${activeDownloads.size})`;

    // Remove rows for finished+dismissed entries
    tray.querySelectorAll('.dl-row').forEach(row => {
        if (!activeDownloads.has(row.dataset.dlPath)) row.remove();
    });

    // Create or update one row per active download
    for (const [path, dl] of activeDownloads) {
        const pct = dl.totalSize ? Math.round(dl.bytesReceived / dl.totalSize * 100) : 0;
        const recv = formatBytes(dl.bytesReceived);
        const total = dl.totalSize ? formatBytes(dl.totalSize) : '?';
        const name = dl.filename || path.split('/').pop();

        let row = tray.querySelector(`.dl-row[data-dl-path="${CSS.escape(path)}"]`);
        if (!row) {
            // Build the row skeleton once
            row = document.createElement('div');
            row.className = 'dl-row';
            row.dataset.dlPath = path;
            row.style.cssText = 'padding:10px 14px;border-bottom:1px solid #1e293b';
            row.innerHTML = `
                <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span class="dl-name" title="${name}" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:180px"></span>
                    <span class="dl-bytes" style="color:#94a3b8"></span>
                </div>
                <div style="background:#334155;border-radius:4px;height:6px;margin-bottom:6px">
                    <div class="dl-bar" style="background:#3b82f6;height:6px;border-radius:4px;width:0%;transition:width .3s"></div>
                </div>
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span class="dl-status" style="color:#64748b"></span>
                    <div class="dl-actions"></div>
                </div>`;
            tray.appendChild(row);
            tray.scrollTop = tray.scrollHeight;  // auto-scroll to newest entry

            // Wire up stable button references stored on the row element
            const actionsDiv = row.querySelector('.dl-actions');

            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = 'Cancel';
            cancelBtn.style.cssText = 'background:#ef4444;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px';
            cancelBtn.addEventListener('click', () => cancelDownload(path));

            const resumeBtn = document.createElement('button');
            resumeBtn.textContent = 'Resume';
            resumeBtn.style.cssText = 'background:#3b82f6;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px';
            resumeBtn.addEventListener('click', () => resumeDownload(encodeURIComponent(path)));

            const pauseCancelBtn = document.createElement('button');
            pauseCancelBtn.textContent = 'Cancel';
            pauseCancelBtn.style.cssText = 'background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px';
            pauseCancelBtn.addEventListener('click', () => cancelDownload(path));

            const dismissBtn = document.createElement('button');
            dismissBtn.textContent = 'Dismiss';
            dismissBtn.style.cssText = 'background:#64748b;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px';
            dismissBtn.addEventListener('click', () => { activeDownloads.delete(path); renderDownloadTray(); });

            row._btns = { cancelBtn, resumeBtn, pauseCancelBtn, dismissBtn, actionsDiv };
        }

        // Update dynamic fields
        const statusMap = { downloading: '⬇', paused: '⏸', error: '⚠', done: '✅' };
        row.querySelector('.dl-name').textContent = (statusMap[dl.status] || '') + ' ' + name;
        row.querySelector('.dl-bytes').textContent = `${recv} / ${total}`;
        row.querySelector('.dl-bar').style.width = pct + '%';

        // Status line: speed · ETA while downloading, plain label otherwise
        let dlStatusText = dl.status;
        if (dl.status === 'downloading') {
            const parts = [];
            if (dl.speed != null) parts.push(formatSpeed(dl.speed));
            if (dl.eta   != null) parts.push('ETA ' + formatEta(dl.eta));
            if (parts.length) dlStatusText = parts.join(' · ');
        } else if (dl.status === 'error') {
            dlStatusText = '⚠ ' + (dl.error || 'failed');
        }
        row.querySelector('.dl-status').textContent = dlStatusText;

        // Swap action buttons without re-creating them
        const { actionsDiv, cancelBtn, resumeBtn, pauseCancelBtn, dismissBtn } = row._btns;
        actionsDiv.innerHTML = '';
        if (dl.status === 'downloading') {
            actionsDiv.appendChild(cancelBtn);
        } else if (dl.status === 'paused' || dl.status === 'error') {
            actionsDiv.appendChild(resumeBtn);
            actionsDiv.appendChild(pauseCancelBtn);
        } else if (dl.status === 'done') {
            actionsDiv.appendChild(dismissBtn);
        }
    }
}

function formatBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
    return (b/1073741824).toFixed(2) + ' GB';
}

// Mint a download token from the server
async function mintDownloadToken(path) {
    const data = await apiCall('/api/v1/download_token', 'POST', { path });
    return data; // { download_token, path, expires_in, total_size, bytes_confirmed }
}

// Core streaming download — starts from `resumeFrom` bytes
async function streamDownload(path, dl) {
    dl.status = 'downloading';
    dl.abortController = new AbortController();
    renderDownloadTray();

    try {
        const urlPath = `/api/v1/download${encodePath(path)}`;
        const dlUrl = `${API_BASE_URL}${urlPath}?dl_token=${encodeURIComponent(dl.dlToken)}`;

        const headers = {};
        if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
        if (dl.bytesReceived > 0) {
            headers['Range'] = `bytes=${dl.bytesReceived}-`;
        }

        const resp = await fetchWithFallback(dlUrl, {
            headers,
            signal: dl.abortController.signal
        });

        if (!resp.ok && resp.status !== 206) {
            throw new Error(`Server returned ${resp.status}`);
        }

        // Update total size from Content-Range if we resumed
        const cr = resp.headers.get('Content-Range');
        if (cr) {
            const m = cr.match(/bytes \d+-\d+\/(\d+)/);
            if (m) dl.totalSize = parseInt(m[1]);
        } else {
            const cl = resp.headers.get('Content-Length');
            if (cl) dl.totalSize = parseInt(cl);
        }
        renderDownloadTray();

        const reader = resp.body.getReader();
        let dlLastLoaded = dl.bytesReceived;
        let dlLastTime   = Date.now();
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            dl.chunks.push(value);
            dl.bytesReceived += value.byteLength;
            const now = Date.now();
            const dt  = (now - dlLastTime) / 1000;
            if (dt >= 0.3) {
                dl.speed = (dl.bytesReceived - dlLastLoaded) / dt;
                dl.eta   = (dl.speed > 0 && dl.totalSize)
                    ? (dl.totalSize - dl.bytesReceived) / dl.speed
                    : null;
                dlLastLoaded = dl.bytesReceived;
                dlLastTime   = now;
            }
            renderDownloadTray();
        }

        // Stitch all chunks and trigger browser save
        const blob = new Blob(dl.chunks);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = dl.filename;
        a.click();
        URL.revokeObjectURL(a.href);

        dl.status = 'done';
        renderDownloadTray();

    } catch (err) {
        if (err.name === 'AbortError') {
            dl.status = 'paused';
        } else {
            console.error('Download error:', err);
            dl.status = 'error';
            dl.error = err.message;
        }
        renderDownloadTray();
    }
}

window.downloadFile = async function(path) {
    if (activeDownloads.has(path)) {
        // Already tracked — just re-render tray
        renderDownloadTray();
        return;
    }
    try {
        const tokenData = await mintDownloadToken(path);
        const dl = {
            dlToken: tokenData.download_token,
            totalSize: tokenData.total_size || null,
            bytesReceived: 0,
            chunks: [],
            filename: path.split('/').pop(),
            status: 'downloading',
            abortController: null,
            error: null,
            speed: null,
            eta: null,
        };
        activeDownloads.set(path, dl);
        renderDownloadTray();
        await streamDownload(path, dl);
    } catch (err) {
        showMessage('Download failed', err.message);
    }
}

window.resumeDownload = async function(safePath) {
    const path = decodeURIComponent(safePath);
    const dl = activeDownloads.get(path);
    if (!dl) return;
    try {
        // Re-mint a fresh token (old one may have expired)
        const tokenData = await mintDownloadToken(path);
        dl.dlToken = tokenData.download_token;
        // server bytes_confirmed is the authoritative resume point;
        // if our in-memory bytesReceived is less, trust the smaller value
        // to avoid gaps. If more, keep ours (server may have restarted).
        const serverConfirmed = tokenData.bytes_confirmed || 0;
        if (serverConfirmed < dl.bytesReceived) {
            // Trim chunks back to serverConfirmed
            let kept = 0;
            const trimmed = [];
            for (const chunk of dl.chunks) {
                if (kept >= serverConfirmed) break;
                if (kept + chunk.byteLength <= serverConfirmed) {
                    trimmed.push(chunk);
                    kept += chunk.byteLength;
                } else {
                    trimmed.push(chunk.slice(0, serverConfirmed - kept));
                    kept = serverConfirmed;
                }
            }
            dl.chunks = trimmed;
            dl.bytesReceived = kept;
        }
        dl.speed = null;
        dl.eta   = null;
        await streamDownload(path, dl);
    } catch (err) {
        showMessage('Resume failed', err.message);
    }
}

window.cancelDownload = function(path) {
    // path may be raw or encoded — normalise
    try { path = decodeURIComponent(path); } catch(e) {}
    const dl = activeDownloads.get(path);
    if (dl && dl.abortController) dl.abortController.abort();
    activeDownloads.delete(path);
    renderDownloadTray();
}

        // ======================================================================
        // --- MEDIA PREVIEW ---
        // ======================================================================
const EXT_IMAGE   = new Set(['jpg','jpeg','png','gif','webp','bmp','svg','ico','avif','tiff','tif']);
const EXT_IMAGE_HEIC = new Set(['heic','heif']);  // decoded client-side via heic2any
const EXT_VIDEO   = new Set(['mp4','webm','ogg','ogv','mov','m4v','mkv','avi']);
const EXT_AUDIO   = new Set(['mp3','wav','flac','aac','ogg','oga','m4a','opus','weba']);
const EXT_TEXT    = new Set(['txt','md','js','ts','jsx','tsx','py','sh','bash','json','xml','yaml','yml','toml','ini','cfg','conf','html','htm','css','scss','less','csv','log','env','rs','go','c','cpp','h','java','rb','php','swift','kt','sql','r','lua']);
const EXT_ARCHIVE = new Set(['zip','tar','gz','tgz','bz2','tbz2','xz','txz']);

function fileCategory(path) {
    const ext = (path.split('.').pop() || '').toLowerCase();
    if (EXT_IMAGE.has(ext))      return 'image';
    if (EXT_IMAGE_HEIC.has(ext)) return 'heic';
    if (EXT_VIDEO.has(ext))      return 'video';
    if (EXT_AUDIO.has(ext))      return 'audio';
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
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/heic2any/0.0.4/heic2any.min.js';
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
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
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
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/js-untar/2.0.0/untar.min.js';
        s.onload  = () => { _untarLoaded = true; resolve(); };
        s.onerror = () => reject(new Error('Failed to load js-untar'));
        document.head.appendChild(s);
    });
}

window.closePreview = function() {
    const modal = document.getElementById('preview-modal');
    modal.classList.add('hidden');
    const body = document.getElementById('preview-body');
    body.querySelectorAll('video,audio').forEach(el => { el.pause(); el.src = ''; });
    body.innerHTML = '';
    document.getElementById('preview-download-btn').style.display = 'none';
};

// Render a read-only archive file tree inside the preview body element.
// entries: array of { name, size, isDir }  (normalised by each format handler)
function _renderArchiveTree(bodyEl, entries, archiveName) {
    if (!entries.length) {
        bodyEl.innerHTML = '<div style="padding:2rem;text-align:center;color:#94a3b8">Archive is empty.</div>';
        return;
    }

    // Build a tree structure from flat paths
    function buildTree(entries) {
        const root = { children: {}, files: [] };
        for (const e of entries) {
            const parts = e.name.replace(/\\/g, '/').replace(/\/$/, '').split('/');
            if (e.isDir || parts.length > 1) {
                // directory node — walk/create path
                let node = root;
                const dirParts = e.isDir ? parts : parts.slice(0, -1);
                for (const part of dirParts) {
                    if (!node.children[part]) node.children[part] = { children: {}, files: [] };
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
    const filename = path.split('/').pop();
    const cat = fileCategory(path);
    const modal = document.getElementById('preview-modal');
    const titleEl = document.getElementById('preview-title');
    const bodyEl = document.getElementById('preview-body');
    const dlBtn = document.getElementById('preview-download-btn');

    titleEl.textContent = filename;
    bodyEl.innerHTML = '<p style="color:#64748b;padding:2rem;text-align:center">Loading…</p>';
    dlBtn.style.display = 'none';
    modal.classList.remove('hidden');

    try {
        const tokenData = await mintDownloadToken(path);
        const urlPath = `/api/v1/download${encodePath(path)}`;
        const dlUrl = `${API_BASE_URL}${urlPath}?dl_token=${encodeURIComponent(tokenData.download_token)}`;

        if (cat === 'image') {
            bodyEl.innerHTML = `<img src="${dlUrl}" alt="${escapeHtml(filename)}" style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto">`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'heic') {
            bodyEl.innerHTML = '<p style="color:#94a3b8;padding:2rem;text-align:center">Decoding HEIC…</p>';
            await _loadHeic2any();
            const resp = await fetchWithFallback(dlUrl, authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {});
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

        } else if (cat === 'text') {
            const resp = await fetchWithFallback(dlUrl, authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {});
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const text = await resp.text();
            const ext = (path.split('.').pop() || '').toLowerCase();
            bodyEl.innerHTML = `<pre class="lang-${ext}">${escapeHtml(text.slice(0, 50000))}${text.length > 50000 ? '\n\n… (truncated)' : ''}</pre>`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else if (cat === 'archive') {
            const ext = (path.split('.').pop() || '').toLowerCase();
            bodyEl.innerHTML = '<p style="color:#94a3b8;padding:2rem;text-align:center">Reading archive…</p>';

            const isZip = ext === 'zip';
            const isTar = ['tar', 'gz', 'tgz'].includes(ext);
            const noPreview = ['bz2', 'tbz2', 'xz', 'txz'].includes(ext);

            if (noPreview) {
                bodyEl.innerHTML = `<div style="padding:3rem 1rem;text-align:center">
                    <div style="font-size:3rem;margin-bottom:1rem">🗜</div>
                    <div style="color:#94a3b8">${escapeHtml(filename)}</div>
                    <p style="color:#64748b;font-size:14px;margin-top:8px">
                        .${ext} preview isn't supported in browser.<br>Download and extract locally.
                    </p></div>`;
                dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };
            } else if (isZip || isTar) {
                // Use the server-side archive_tree endpoint — reads only the central
                // directory / tar headers, never the compressed file data.
                // This is O(entry-count) rather than O(file-size).
                try {
                    const tokenResp = await apiCall('/api/v1/download_token', 'POST', { path }, true);
                    const dlToken   = tokenResp.download_token;

                    const encodedPath = path.split('/').map(encodeURIComponent).join('/');
                    const treeUrl = `${API_BASE_URL}/api/v1/archive_tree${encodedPath}?dl_token=${encodeURIComponent(dlToken)}`;
                    const treeResp = await fetchWithFallback(treeUrl, {
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
                    <p style="color:#64748b;font-size:14px">No preview available for this archive type.</p>
                </div>`;
                dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };
            }
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => downloadFile(path);

        } else {
            bodyEl.innerHTML = `<div style="padding:3rem 1rem;text-align:center"><div style="font-size:3.5rem;margin-bottom:1rem">📄</div><div style="color:#94a3b8;margin-bottom:1rem">${escapeHtml(filename)}</div><p style="color:#64748b;font-size:14px">No preview available for this file type.</p></div>`;
            dlBtn.style.display = 'inline-flex'; dlBtn.onclick = () => { closePreview(); downloadFile(path); };
        }
    } catch (err) {
        bodyEl.innerHTML = `<p style="color:#ef4444;padding:2rem;text-align:center">Preview failed: ${escapeHtml(String(err))}</p>`;
    }
};

window.previewText = window.previewFile;

// After the table is inserted we need to hook up click handlers for the
// various buttons.  We read the path from the `data-path` attribute, so
// we no longer need to worry about quoting/escaping in the HTML.
function attachRowListeners() {
    document.querySelectorAll('#file-list .open-btn').forEach(btn => {
        btn.addEventListener('click', (e) => { e.preventDefault(); enterDir(btn.dataset.path); });
    });
    document.querySelectorAll('#file-list .download-btn').forEach(btn => {
        btn.addEventListener('click', () => downloadFile(btn.dataset.path));
    });
    document.querySelectorAll('#file-list .zip-btn').forEach(btn => {
        btn.addEventListener('click', () => downloadFolderZip(btn.dataset.path));
    });
    document.querySelectorAll('#file-list .preview-btn').forEach(btn => {
        btn.addEventListener('click', (e) => { e.preventDefault(); previewFile(btn.dataset.path); });
    });
    document.querySelectorAll('#file-list .delete-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteItem(btn.dataset.path));
    });
    document.querySelectorAll('#file-list .move-btn').forEach(btn => {
        btn.addEventListener('click', () => openMoveDialog(btn.dataset.path));
    });
    document.querySelectorAll('#file-list .share-btn').forEach(btn => {
        btn.addEventListener('click', () => openShareDialog(btn.dataset.path, btn.dataset.isdir === '1'));
    });

    // Lazy folder sizes — fire requests after the table is visible
    // Use staggered setTimeout to avoid hammering the server for large listings
    document.querySelectorAll('#file-list .folder-size-cell').forEach((cell, idx) => {
        setTimeout(() => loadFolderSize(cell), idx * 80);
    });
}

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

// Stream-download a folder as ZIP using the existing download tray.
// The server sends Content-Length so progress works just like a file download.
window.downloadFolderZip = async function(path) {
    const zipPath = '__zip__' + path;  // synthetic key so it doesn't collide with file paths
    if (activeDownloads.has(zipPath)) { renderDownloadTray(); return; }
    const folderName = path.split('/').filter(Boolean).pop() || 'download';
    const filename   = folderName + '.zip';
    try {
        // We don't use mintDownloadToken for ZIP — the session token in the
        // Authorization header is sufficient (Bearer sent by fetchWithFallback).
        const dl = {
            dlToken: null,       // not used — ZIP endpoint accepts session auth
            totalSize: null,
            bytesReceived: 0,
            chunks: [],
            filename,
            status: 'downloading',
            abortController: null,
            error: null,
            speed: null,
            eta: null,
        };
        activeDownloads.set(zipPath, dl);
        renderDownloadTray();

        const zipUrl = `${API_BASE_URL}/api/v1/zip${encodePath(path)}`;
        dl.abortController = new AbortController();
        const resp = await fetchWithFallback(zipUrl, {
            headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
            signal: dl.abortController.signal,
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
            throw new Error(err.error || `HTTP ${resp.status}`);
        }
        const cl = resp.headers.get('Content-Length');
        if (cl) dl.totalSize = parseInt(cl);
        renderDownloadTray();

        const reader = resp.body.getReader();
        let lastLoaded = 0, lastTime = Date.now();
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            dl.chunks.push(value);
            dl.bytesReceived += value.byteLength;
            const now = Date.now(), dt = (now - lastTime) / 1000;
            if (dt >= 0.3) {
                dl.speed = (dl.bytesReceived - lastLoaded) / dt;
                dl.eta   = (dl.speed > 0 && dl.totalSize)
                    ? (dl.totalSize - dl.bytesReceived) / dl.speed : null;
                lastLoaded = dl.bytesReceived; lastTime = now;
            }
            renderDownloadTray();
        }
        const blob = new Blob(dl.chunks, { type: 'application/zip' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob); a.download = filename; a.click();
        URL.revokeObjectURL(a.href);
        dl.status = 'done';
        renderDownloadTray();
    } catch (err) {
        const dl = activeDownloads.get(zipPath);
        if (dl) {
            if (err.name === 'AbortError') { dl.status = 'paused'; }
            else { dl.status = 'error'; dl.error = err.message; }
            renderDownloadTray();
        } else {
            showMessage('ZIP download failed', err.message);
        }
    }
}

window.deleteItem = async function(path) {
    const disp = stripInternalPrefix(path);
    if (!confirm('Move to Trash: ' + disp + '?')) return;
    try {
        const res = await apiCall('/api/v1/trash', 'POST', { path });
        const days = res.retention_days || 30;
        showMessage('Moved to Trash',
            disp + ' was moved to Trash and will be kept for ' + days + ' days.\n'
            + 'Open Trash (🗑) to restore or permanently delete it.');
        loadDirectory(currentPath);
    } catch (err) {
        showMessage('Failed', err.message);
    }
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
                <button onclick="document.getElementById('trash-overlay').remove()"
                    style="background:rgba(255,255,255,.15);border:none;color:white;
                           border-radius:6px;padding:4px 10px;cursor:pointer;font-size:14px">✕</button>
            </div>
            <div id="trash-notice" style="display:none;padding:8px 20px;background:#fef3c7;
                border-bottom:1px solid #fde68a;font-size:12px;color:#92400e"></div>
            <div style="padding:12px 20px;border-bottom:1px solid #e2e8f0;display:flex;
                        justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                <span style="font-size:12px;color:#64748b">
                    Files are automatically deleted after their retention period.
                    Trash does not count toward your storage quota.
                </span>
                <button id="trash-empty-btn"
                    style="background:#ef4444;color:white;border:none;border-radius:7px;
                           padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;
                           white-space:nowrap">
                    Empty Trash
                </button>
            </div>
            <div id="trash-body" style="max-height:55vh;overflow-y:auto;padding:8px 0">
                <div style="padding:24px;text-align:center;color:#94a3b8">Loading…</div>
            </div>
        </div>`;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

    await _refreshTrashView();

    document.getElementById('trash-empty-btn').addEventListener('click', async () => {
        if (!confirm('Permanently delete everything in Trash? This cannot be undone.')) return;
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
    subtitle.textContent = `${items.length} item${items.length !== 1 ? 's' : ''}`;

    if (data.notice && notice) {
        notice.textContent = '⚠ ' + data.notice;
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
        if (d <= 0) return '<span style="color:#ef4444">Expiring soon</span>';
        if (d === 1) return '<span style="color:#f59e0b">1 day left</span>';
        if (d <= 3) return `<span style="color:#f59e0b">${d} days left</span>`;
        return `<span style="color:#64748b">${d} days left</span>`;
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
                    Deleted ${fmtDate(item.deleted_at)}
                </div>
            </div>
            <div style="flex-shrink:0;font-size:11px;text-align:right;min-width:70px">
                ${daysLeft(item.expires_at)}
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0">
                <button class="trash-restore-btn" data-id="${item.id}"
                    style="background:#22c55e;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px;font-weight:600">
                    Restore
                </button>
                <button class="trash-del-btn" data-id="${item.id}"
                    style="background:#ef4444;color:white;border:none;border-radius:6px;
                           padding:4px 10px;cursor:pointer;font-size:12px">
                    Delete
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
            const row = body.querySelector(`.trash-row[data-id="${id}"]`);
            const name = row?.querySelector('div > div')?.textContent?.trim() || 'this item';
            if (!confirm(`Permanently delete "${name}"? This cannot be undone.`)) return;
            try {
                await apiCall(`/api/v1/trash/${id}`, 'DELETE');
                await _refreshTrashView();
            } catch (err) {
                alert('Delete failed: ' + err.message);
            }
        });
    });
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

    function setTab(tab) {
        activeTab = tab;
        overlay.querySelectorAll('.mv-tab').forEach(b => {
            b.classList.toggle('mv-active', b.dataset.tab === tab);
        });
        $('mv-tab-move').style.display   = (tab === 'move' || tab === 'copy') ? '' : 'none';
        $('mv-tab-rename').style.display = (tab === 'rename') ? '' : 'none';
        const confirmBtn = $('mv-confirm-btn');
        if (tab === 'move')   { confirmBtn.textContent = 'Move here';    confirmBtn.style.background = '#3b82f6'; }
        if (tab === 'copy')   { confirmBtn.textContent = 'Copy here';    confirmBtn.style.background = '#0ea5e9'; }
        if (tab === 'rename') { confirmBtn.textContent = 'Rename';       confirmBtn.style.background = '#8b5cf6'; }
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
                showMessage('Invalid name', 'Name cannot be empty or contain slashes.'); return;
            }
            const newPath = srcDir === '/' ? '/' + newName : srcDir + '/' + newName;
            confirmBtn.disabled = true; confirmBtn.textContent = 'Renaming…';
            try {
                await apiCall('/api/v1/rename', 'POST', { old: srcPath, new: newPath });
                overlay.remove(); loadDirectory(currentPath);
            } catch (err) {
                confirmBtn.disabled = false; confirmBtn.textContent = 'Rename';
                if (err.message !== 'SESSION_EXPIRED') showMessage('Rename failed', err.message);
            }
            return;
        }

        // Move or Copy
        if (!destFolder) { showMessage('No destination', 'Please select a destination folder.'); return; }
        const newPath = (destFolder.endsWith('/') ? destFolder : destFolder + '/') + srcName;
        if (activeTab === 'move') {
            if (newPath === srcPath) { showMessage('Same location', 'The destination is the same as the source.'); return; }
            confirmBtn.disabled = true; confirmBtn.textContent = 'Moving…';
            try {
                await apiCall('/api/v1/rename', 'POST', { old: srcPath, new: newPath });
                overlay.remove(); loadDirectory(currentPath);
            } catch (err) {
                confirmBtn.disabled = false; confirmBtn.textContent = 'Move here';
                if (err.message !== 'SESSION_EXPIRED') showMessage('Move failed', err.message);
            }
        } else {
            // Copy — use copy endpoint if available, else show message
            if (newPath === srcPath) { showMessage('Same location', 'The destination is the same as the source.'); return; }
            confirmBtn.disabled = true; confirmBtn.textContent = 'Copying…';
            try {
                await apiCall('/api/v1/copy', 'POST', { src: srcPath, dest: newPath });
                overlay.remove(); loadDirectory(currentPath);
            } catch (err) {
                confirmBtn.disabled = false; confirmBtn.textContent = 'Copy here';
                if (err.message !== 'SESSION_EXPIRED') showMessage('Copy failed', err.message);
            }
        }
    });

    // ── Close / cancel ─────────────────────────────────────────────────────
    $('mv-cancel-btn').addEventListener('click', () => overlay.remove());
    $('mv-close').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

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
    const name = prompt('Folder name (relative to current folder):', 'NewFolder');
    if (!name) return;
    try {
        // Use the new mkdir API to create the folder directly under the current path.
        // Ensure we join paths correctly.
        let targetPath = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
        await apiCall('/api/v1/mkdir', 'POST', { path: targetPath }, true);
        showMessage('Folder created', name);
        loadDirectory(currentPath);
    } catch (err) {
        // Fallback to placeholder upload if mkdir fails for some reason
        try {
            const fd = new FormData();
            fd.append('fileToUpload', new Blob(['']), '.placeholder');
            // Upload placeholder into the target directory (fallback)
            let endpointPath = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
            const endpoint = `/api/v1/upload/${encodePath(endpointPath)}`;
            await uploadFormData(endpoint, fd);
            showMessage('Folder created (via fallback)', name);
            loadDirectory(currentPath);
        } catch (err2) {
            showMessage('Create folder failed', err.message || String(err2));
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
        totalChunks     = Math.ceil(file.size / chunkSize) || 1;
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

        // ── Init session (no blocking whole-file SHA — server verifies after assembly) ──
        const tentativeTotalChunks = Math.ceil(file.size / serverChunkSize) || 1;
        const initBody = {
            filename:     file.name,
            dest_path:    destRel,
            total_size:   file.size,
            total_chunks: tentativeTotalChunks,
            sha256:       null,
            owner_type:   ownerType,
            share_token:  shareToken,
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
        totalChunks     = Math.ceil(file.size / chunkSize) || 1;
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
    // Send up to CONCURRENCY chunks at a time for much faster uploads.
    const CONCURRENCY = 8;

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
        samplerLoaded = Math.min(file.size, samplerLoaded + delta);
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

            let chunkSentPrev = 0; // bytes already fed to sampler from this XHR

            xhr.upload.onprogress = (e) => {
                if (!e.lengthComputable) return;
                const delta  = e.loaded - chunkSentPrev;
                chunkSentPrev = e.loaded;
                if (delta > 0) samplerOnBytes(delta);
            };

            xhr.onload = () => {
                activeXhrs.delete(idx);
                // Credit any bytes not yet counted via onprogress
                const remaining = blob.size - chunkSentPrev;
                if (remaining > 0) samplerOnBytes(remaining);
                renderUploadTray();
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve();
                } else {
                    let msg = `Chunk ${idx} failed: HTTP ${xhr.status}`;
                    try { const j = JSON.parse(xhr.responseText); if (j.error) msg = j.error; } catch {}
                    reject(new Error(msg));
                }
            };

            xhr.onerror = () => { activeXhrs.delete(idx); reject(new Error(`Chunk ${idx} network error`)); };
            xhr.onabort = () => {
                activeXhrs.delete(idx);
                const e = new Error('Upload cancelled');
                e.name  = 'AbortError';
                reject(e);
            };

            xhr.open('POST', `${API_BASE_URL}/api/v1/upload_session/${uploadToken}/chunk/${idx}`);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            if (chunkHash) xhr.setRequestHeader('X-Chunk-SHA256', chunkHash);
            const ah = authHeaders(anonDeviceToken);
            for (const [k, v] of Object.entries(ah)) xhr.setRequestHeader(k, v);
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
                    // Abort triggered by either pause or cancel
                    if (ul.paused && !ul.cancelled) {
                        // Pause: back up nextIdx to this chunk so it gets re-sent on resume.
                        // Use min in case multiple workers abort simultaneously.
                        if (idx < nextIdx) nextIdx = idx;
                        return;
                    }
                    // Cancel
                    ul.cancelled = true;
                    return;
                }
                if (ul.cancelled) return;
                uploadError = err;
                return;
            }
        }
    }

    // Launch CONCURRENCY workers and wait for all to finish
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));

    if (ul.paused && !ul.cancelled) {
        // Workers exited due to pause — don't complete, just leave state as paused.
        // nextIdx was backed up to the lowest aborted chunk index by the workers.
        ul.nextChunk = nextIdx;
        const e = new Error('Upload paused');
        e.name = 'PauseSignal';
        throw e;
    }
    if (ul.cancelled) {
        ul.status = 'cancelled';
        removeInterruptedUpload(uploadToken);
        if (anonDeviceToken) removeAnonDeviceToken(uploadToken);
        renderUploadTray();
        // Tell the server to immediately delete the tmp chunks
        fetchWithFallback(`${API_BASE_URL}/api/v1/upload_session/${uploadToken}/cancel`, {
            method: 'DELETE',
            headers: authHeaders(anonDeviceToken),
        }).catch(() => {}); // best-effort, ignore errors
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
    ul.speed  = null;
    ul.eta    = null;
    renderUploadTray();
    removeInterruptedUpload(uploadToken);
    if (anonDeviceToken) removeAnonDeviceToken(uploadToken);

    return await completeRes.json();
}

async function handleUploadForm(e) {
    e.preventDefault();
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
            showMessage('Upload successful', `${items[0].file.name} uploaded successfully.`);
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
        // Start first immediately, then drain queue sequentially
        async function drainQueue(startItem) {
            let item = startItem;
            while (item) {
                try {
                    await uploadChunked(item.file, item.destRel, { ownerType: item.ownerType });
                    loadDirectory(currentPath);
                } catch (err) {
                    if (err.name !== 'PauseSignal' && err.message !== 'Upload cancelled') {
                        showMessage('Upload failed', `${item.file.name}: ${err.message || String(err)}`);
                    }
                }
                // Next from queue
                if (window._uploadQueue && window._uploadQueue.length > 0) {
                    item = window._uploadQueue.shift();
                    refreshQ();
                } else {
                    item = null;
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
    }

    if (activeUploads.size === 0) {
        tray.innerHTML = '';
        return;
    }

    // Header
    let header = tray.querySelector('.ul-tray-header');
    if (!header) {
        header = document.createElement('div');
        header.className = 'ul-tray-header';
        header.style.cssText = 'padding:10px 14px 6px;font-weight:700;font-size:14px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;';
        header.innerHTML = `<span class="ul-count"></span><span style="cursor:pointer;opacity:.6" id="ul-tray-close">✕</span>`;
        tray.prepend(header);
        header.querySelector('#ul-tray-close').addEventListener('click', () => { tray.innerHTML = ''; });
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
            tray.scrollTop = tray.scrollHeight;  // auto-scroll to newest entry

            const actionsDiv = row.querySelector('.ul-actions');

            const dismissBtn = document.createElement('button');
            dismissBtn.textContent = 'Dismiss';
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
                }).catch(err => {
                    if (err.name === 'PauseSignal' || err.message === 'Upload cancelled') return;
                    showMessage('Upload failed', err.message);
                });
            });

            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = '✕ Cancel';
            cancelBtn.style.cssText = 'background:#ef4444;color:#fff;border:none;border-radius:5px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:4px';
            cancelBtn.addEventListener('click', () => {
                ul.cancelled = true;
                ul.paused = false;
                if (ul.abortController) ul.abortController.abort();
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

        const statusMap = { uploading: '⬆', verifying: '🔍', done: '✅', error: '⚠', paused: '⏸', cancelled: '🚫' };
        row.querySelector('.ul-name').textContent = (statusMap[ul.status] || '') + ' ' + ul.filename;
        row.querySelector('.ul-bytes').textContent = `${sent} / ${total}`;
        const bar = row.querySelector('.ul-bar');
        // During verification use verifyPct for the bar so it visually advances
        const displayPct = (ul.status === 'verifying' && ul.verifyPct != null && ul.verifyPct > 0)
            ? ul.verifyPct
            : pct;
        bar.style.width = displayPct + '%';
        bar.style.background = ul.status === 'paused' ? '#f59e0b' : ul.status === 'error' || ul.status === 'cancelled' ? '#ef4444' : ul.status === 'verifying' ? '#a78bfa' : '#22c55e';

        let statusText = ul.status;
        if (ul.status === 'uploading') {
            const parts = [];
            if (ul.speed != null) parts.push(formatSpeed(ul.speed));
            if (ul.eta != null) parts.push('ETA ' + formatEta(ul.eta));
            if (parts.length) statusText = parts.join(' · ');
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
        renderApp('login'); // Show login form after successful registration message
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
        renderApp(); // Re-render the app in its logged-in state
    } catch (error) {
        showMessage('Login Failed', error.message);
    }
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
function openProfileMenu() {
    // Close if already open
    const existing = document.getElementById('profile-menu-modal');
    if (existing) { existing.remove(); return; }

    const overlay = document.createElement('div');
    overlay.id = 'profile-menu-modal';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:8000;display:flex;align-items:flex-start;justify-content:flex-end;padding:70px 1rem 0 0';
    overlay.innerHTML = `
        <div id="profile-menu-panel" style="background:white;border-radius:14px;box-shadow:0 8px 32px rgba(0,0,0,0.18);min-width:260px;overflow:hidden;animation:fadeSlideDown .15s ease">
            <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:18px 20px;display:flex;align-items:center;gap:12px">
                <div style="width:46px;height:46px;border-radius:50%;background:rgba(255,255,255,0.25);display:flex;align-items:center;justify-content:center;font-size:22px">👤</div>
                <div>
                    <div style="color:white;font-weight:700;font-size:15px">${currentUsername}</div>
                    <div style="color:rgba(255,255,255,0.75);font-size:12px">FluxDrop account</div>
                </div>
            </div>
            <div id="pm-quota-bar" style="padding:10px 16px 6px;border-bottom:1px solid #f1f5f9">
                <div style="font-size:11px;color:#94a3b8;margin-bottom:4px">Storage — loading…</div>
                <div style="background:#e2e8f0;border-radius:4px;height:5px;overflow:hidden">
                    <div id="pm-quota-fill" style="height:100%;border-radius:4px;background:#3b82f6;width:0%;transition:width .4s"></div>
                </div>
            </div>
            <div style="padding:8px 0">
                <button class="profile-menu-item" id="pm-profile">👤 My Profile</button>
                <button class="profile-menu-item" id="pm-shares">🔗 Shared Links</button>
                <button class="profile-menu-item" id="pm-beacon">📡 IP Beacon</button>
                <div style="height:1px;background:#f1f5f9;margin:4px 0"></div>
                ${isAdmin ? '<button class="profile-menu-item" id="pm-admin">⚙️ Admin Panel</button>' : ''}
                <button class="profile-menu-item" id="pm-logout" style="color:#ef4444">🚪 Logout</button>
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

    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    document.getElementById('pm-profile').addEventListener('click', () => { overlay.remove(); openProfilePanel(); });
    document.getElementById('pm-shares').addEventListener('click', () => { overlay.remove(); openShareManager(); });
    document.getElementById('pm-beacon').addEventListener('click', () => {
        overlay.remove();
        // Open IP Beacon — session validation is handled server-side via the
        // FluxDrop cookie/header.  Do NOT pass authToken as ?token= because
        // that query param is consumed by ip_lookup.html as a beacon lookup
        // token (primary/read), which is a completely different credential.
        window.location.href = '/beacon/ui';
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
        bar.querySelector('div').textContent = `Storage — ${fmt(used)} of ${fmt(quota)} used (${pct.toFixed(0)}%)`;
        fill.style.width   = pct.toFixed(1) + '%';
        fill.style.background = color;
    }).catch(() => {
        const bar = document.getElementById('pm-quota-bar');
        if (bar) bar.querySelector('div').textContent = 'Storage — unavailable';
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
        <div style="background:white;border-radius:16px;width:95vw;max-width:500px;
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
                <div id="pp-quota-card" style="background:#f8fafc;border-radius:10px;padding:14px 16px">
                    <div style="font-size:13px;color:#64748b;margin-bottom:8px">Loading storage info…</div>
                </div>

                <!-- Edit profile section -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">Profile info</div>
                    <div style="display:grid;gap:10px">
                        <label style="font-size:13px;font-weight:600;color:#374151">Nickname (display name)
                            <input id="pp-nickname" type="text" placeholder="Loading…"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">Email
                            <input id="pp-email" type="email" placeholder="Loading…"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <div id="pp-profile-msg" style="display:none;font-size:13px;border-radius:6px;padding:6px 10px"></div>
                        <button id="pp-save-profile" class="btn" style="justify-self:end;padding:.5rem 1.25rem">Save changes</button>
                    </div>
                </div>

                <hr style="border:none;border-top:1px solid #e2e8f0;margin:0">

                <!-- Change password section -->
                <div>
                    <div style="font-size:13px;font-weight:700;color:#374151;margin-bottom:10px;
                                text-transform:uppercase;letter-spacing:.05em">Change password</div>
                    <div style="display:grid;gap:10px">
                        <label style="font-size:13px;font-weight:600;color:#374151">Current password
                            <input id="pp-cur-pw" type="password" autocomplete="current-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">New password
                            <input id="pp-new-pw" type="password" autocomplete="new-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <label style="font-size:13px;font-weight:600;color:#374151">Confirm new password
                            <input id="pp-confirm-pw" type="password" autocomplete="new-password"
                                style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                       border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                       box-sizing:border-box;font-family:Inter,sans-serif">
                        </label>
                        <div id="pp-pw-msg" style="display:none;font-size:13px;border-radius:6px;padding:6px 10px"></div>
                        <button id="pp-change-pw" class="btn" style="justify-self:end;padding:.5rem 1.25rem;background:#6366f1">Change password</button>
                    </div>
                </div>

                <!-- Account info footer -->
                <div id="pp-account-info" style="font-size:12px;color:#94a3b8;padding-bottom:4px"></div>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    overlay.querySelector('#pp-close').addEventListener('click', () => overlay.remove());

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
            ? '<span style="color:#6366f1;font-size:11px;margin-left:6px">📌 pinned by admin</span>'
            : '<span style="color:#94a3b8;font-size:11px;margin-left:6px">adjusts with server load</span>';
        overlay.querySelector('#pp-quota-card').innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px">
                <span style="font-size:13px;font-weight:600;color:#374151">Storage quota</span>
                <span style="font-size:13px;color:#475569">${fmt(used)} <span style="color:#94a3b8">of</span> ${fmt(quota)}</span>
            </div>
            <div style="background:#e2e8f0;border-radius:6px;height:8px;overflow:hidden;margin-bottom:6px">
                <div style="height:100%;border-radius:6px;background:${barColor};width:${pct.toFixed(1)}%;transition:width .4s"></div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-size:12px;color:#64748b">${pct.toFixed(1)}% used — ${fmt(quota - used)} free${pinNote}</span>
                ${pct >= 95 ? '<span style="font-size:12px;color:#ef4444;font-weight:600">⚠ Quota nearly full</span>' : ''}
            </div>`;

        // Fill in editable fields
        overlay.querySelector('#pp-nickname').value = me.nickname || '';
        overlay.querySelector('#pp-email').value    = me.email    || '';

        // Account info footer
        overlay.querySelector('#pp-account-info').innerHTML =
            `ID ${me.id} · username: <strong>${escapeHtml(me.username)}</strong> · joined ${(me.created_at||'').slice(0,10)}` +
            (me.is_admin ? ' · <span style="color:#92400e;background:#fef3c7;padding:1px 6px;border-radius:999px;font-weight:600">admin</span>' : '');

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
                    <div style="color:white;font-weight:700;font-size:18px">⚙️ Admin Panel</div>
                    <div style="color:rgba(255,255,255,.55);font-size:12px;margin-top:2px">FluxDrop user management</div>
                </div>
                <button id="ap-close" style="background:rgba(255,255,255,.15);border:none;border-radius:50%;
                    width:32px;height:32px;color:white;font-size:18px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div id="ap-stats" style="background:#f8fafc;border-bottom:1px solid #e2e8f0;
                padding:10px 24px;display:flex;gap:24px;flex-shrink:0;flex-wrap:wrap"></div>
            <div style="overflow-y:auto;flex:1;padding:16px 24px">
                <div id="ap-body">
                    <div style="color:#64748b;font-size:14px;padding:20px 0">Loading users…</div>
                </div>
            </div>
        </div>`;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    document.getElementById('ap-close').addEventListener('click', () => overlay.remove());

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
            `<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${users.length}</strong> users</span>`,
            `<span style="font-size:13px;color:#475569"><strong style="color:#1e293b">${adminCount}</strong> admin(s)</span>`,
            `<span style="font-size:13px;color:#475569">Total used: <strong style="color:#1e293b">${_apFmtBytes(totalUsage)}</strong></span>`,
        ].join('<span style="color:#cbd5e1;margin:0 4px">|</span>');

        if (users.length === 0) {
            body.innerHTML = '<p style="color:#64748b;font-size:14px;padding:20px 0">No users found.</p>';
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
                <span>User</span><span>Usage</span><span>Quota</span>
                <span style="text-align:right">Actions</span>
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
            b.innerHTML = `<p style="color:#ef4444;font-size:14px;padding:20px 0">Failed to load: ${escapeHtml(err.message)}</p>`;
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
        ? `<span class="ap-badge" style="background:#fef3c7;color:#92400e">admin</span> ` : '';
    return `<div class="ap-row">
        <div>
            <div style="font-size:14px;font-weight:600;color:#1e293b">${adminBadge}${escapeHtml(u.username)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:1px">${escapeHtml(u.nickname||'')} · ${escapeHtml(u.email||'')}</div>
            <div style="font-size:11px;color:#cbd5e1;margin-top:1px">ID ${u.id} · joined ${(u.created_at||'').slice(0,10)}</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569;margin-bottom:3px">${_apFmtBytes(u.usage_bytes||0)}</div>
            <div class="ap-bar-wrap"><div class="ap-bar-fill" style="width:${pct.toFixed(1)}%;background:${barColor}"></div></div>
            <div style="font-size:10px;color:#94a3b8;margin-top:2px">${pct.toFixed(0)}%</div>
        </div>
        <div>
            <div style="font-size:12px;color:#475569">${_apFmtBytes(u.quota_bytes||0)}</div>
            ${u.quota_override
                ? '<div style="font-size:10px;color:#6366f1;margin-top:1px">📌 pinned</div>'
                : '<div style="font-size:10px;color:#94a3b8;margin-top:1px">dynamic</div>'}
        </div>
        <div style="display:flex;gap:5px;justify-content:flex-end">
            <button class="ap-btn ap-edit-btn" data-id="${u.id}"
                style="background:#3b82f6;color:white">Edit</button>
            <button class="ap-btn ap-del-btn" data-id="${u.id}" data-name="${escapeHtmlAttr(u.username)}"
                style="background:#ef4444;color:white">Del</button>
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
                <div style="color:white;font-weight:700;font-size:16px">Edit: ${escapeHtml(u.username)}</div>
                <button id="ap-edit-close" style="background:rgba(255,255,255,.2);border:none;border-radius:50%;
                    width:28px;height:28px;color:white;font-size:16px;cursor:pointer;
                    display:flex;align-items:center;justify-content:center">✕</button>
            </div>
            <div style="padding:20px;display:grid;gap:12px">
                <label style="font-size:13px;font-weight:600;color:#374151">Username (login)
                    <input id="ape-username" type="text" value="${escapeHtmlAttr(u.username)}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">Nickname (display)
                    <input id="ape-nickname" type="text" value="${escapeHtmlAttr(u.nickname||'')}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <label style="font-size:13px;font-weight:600;color:#374151">Email
                    <input id="ape-email" type="email" value="${escapeHtmlAttr(u.email||'')}"
                        style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                               border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                               box-sizing:border-box;font-family:Inter,sans-serif">
                </label>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <label style="font-size:13px;font-weight:600;color:#374151">Quota (GB)
                        <input id="ape-quota" type="number" min="1" step="1"
                            value="${Math.round((u.quota_bytes||0)/(1024**3))}"
                            style="display:block;width:100%;margin-top:4px;padding:7px 10px;
                                   border:1px solid #e2e8f0;border-radius:8px;font-size:14px;
                                   box-sizing:border-box;font-family:Inter,sans-serif">
                    </label>
                    <label style="font-size:13px;font-weight:600;color:#374151;display:flex;flex-direction:column">
                        <span>Flags</span>
                        <span style="display:flex;flex-direction:column;gap:6px;margin-top:8px">
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-is-admin" ${u.is_admin?'checked':''}> Admin
                            </label>
                            <label style="display:flex;align-items:center;gap:7px;font-weight:400;cursor:pointer">
                                <input type="checkbox" id="ape-quota-override" ${u.quota_override?'checked':''}> Pin quota
                            </label>
                        </span>
                    </label>
                </div>
                <div id="ape-error" style="display:none;color:#ef4444;font-size:13px;
                    background:#fef2f2;border-radius:6px;padding:6px 10px"></div>
            </div>
            <div style="padding:12px 20px 18px;display:flex;gap:8px;justify-content:flex-end;
                        border-top:1px solid #f1f5f9">
                <button id="ape-cancel" class="btn" style="background:#e2e8f0;color:#1e293b">Cancel</button>
                <button id="ape-save" class="btn" style="background:#3b82f6;min-width:80px">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);

    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    modal.querySelector('#ap-edit-close').addEventListener('click', () => modal.remove());
    modal.querySelector('#ape-cancel').addEventListener('click', () => modal.remove());

    modal.querySelector('#ape-save').addEventListener('click', async () => {
        if (!modal.isConnected) return;
        const saveBtn = modal.querySelector('#ape-save');
        const errEl   = modal.querySelector('#ape-error');
        const quotaGb = parseFloat(modal.querySelector('#ape-quota').value);
        if (isNaN(quotaGb) || quotaGb < 1) {
            errEl.textContent = 'Quota must be at least 1 GB.';
            errEl.style.display = 'block'; return;
        }
        errEl.style.display = 'none';
        saveBtn.disabled = true; saveBtn.textContent = 'Saving…';
        try {
            await apiCall(`/api/v1/admin/users/${userId}`, 'PATCH', {
                username:       modal.querySelector('#ape-username').value.trim(),
                nickname:       modal.querySelector('#ape-nickname').value.trim(),
                email:          modal.querySelector('#ape-email').value.trim(),
                quota_bytes:    Math.round(quotaGb * 1024 ** 3),
                is_admin:       modal.querySelector('#ape-is-admin').checked ? 1 : 0,
                quota_override: modal.querySelector('#ape-quota-override').checked ? 1 : 0,
            });
            modal.remove();
            await _apLoadUsers();
        } catch (err) {
            if (!modal.isConnected) return;
            saveBtn.disabled = false; saveBtn.textContent = 'Save';
            if (err.message !== 'SESSION_EXPIRED') {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
            }
        }
    });
}

async function _apDeleteUser(userId, username) {
    if (!confirm(`Delete user "${username}"?\n\nAccount and sessions will be removed. Files on disk are kept.`)) return;
    try {
        await apiCall(`/api/v1/admin/users/${userId}`, 'DELETE');
        await _apLoadUsers();
    } catch (err) {
        if (err.message !== 'SESSION_EXPIRED') showMessage('Delete failed', err.message);
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
            <h3 style="font-size:18px;font-weight:700;margin-bottom:4px">🔗 Share "${name}"</h3>
            <p style="font-size:13px;color:#64748b;margin-bottom:16px">${isDir ? 'Folder' : 'File'}: <code style="background:#f1f5f9;padding:1px 5px;border-radius:4px">${path}</code></p>

            <div style="display:grid;gap:10px;margin-bottom:18px">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-require-account" style="width:16px;height:16px">
                    <span style="font-size:14px"><strong>Require FluxDrop account</strong> to access</span>
                </label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-stats" checked style="width:16px;height:16px">
                    <span style="font-size:14px"><strong>Track access stats</strong> (who/when accessed)</span>
                </label>

                <div style="display:flex;align-items:center;gap:10px">
                    <span style="font-size:14px;font-weight:600;white-space:nowrap">⏰ Expires:</span>
                    <select id="sh-expiry-preset" style="flex:1;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;background:white">
                        <option value="">Never (permanent)</option>
                        <option value="1">1 day</option>
                        <option value="7">7 days</option>
                        <option value="30">30 days</option>
                        <option value="90">90 days</option>
                        <option value="custom">Custom date…</option>
                    </select>
                    <input type="date" id="sh-expiry-custom"
                        style="display:none;padding:6px 10px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px"
                        min="${new Date().toISOString().slice(0,10)}">
                </div>

                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-allow-preview" style="width:16px;height:16px">
                    <span style="font-size:14px"><strong>Allow file preview</strong> — visitors can preview files without downloading</span>
                </label>
                ${!isDir ? `<label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-cdn-embed" style="width:16px;height:16px">
                    <span style="font-size:14px"><strong>Allow CDN embedding</strong> — link acts as a direct media URL (for Discord, websites, etc.)</span>
                </label>` : ''}

                ${isDir ? `
                <hr style="border:none;border-top:1px solid #e2e8f0;margin:2px 0">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-anon-upload" style="width:16px;height:16px">
                    <span style="font-size:14px"><strong>Allow anyone to upload</strong> into this folder</span>
                </label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" id="sh-auth-upload" style="width:16px;height:16px">
                    <span style="font-size:14px"><strong>Allow registered users to upload</strong> into this folder</span>
                </label>` : ''}
            </div>

            <div id="sh-result" style="display:none;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;margin-bottom:14px">
                <div style="font-size:12px;color:#166534;margin-bottom:6px;font-weight:600">Share link created:</div>
                <div style="display:flex;gap:6px">
                    <input id="sh-link-box" type="text" readonly style="flex:1;font-size:12px;padding:6px;border:1px solid #ccc;border-radius:6px;background:white;color:#1e293b">
                    <button id="sh-copy-btn" style="background:#16a34a;color:white;border:none;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px">Copy</button>
                </div>
            </div>

            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="sh-cancel-btn" class="btn" style="background:#e2e8f0;color:#1e293b">Cancel</button>
                <button id="sh-create-btn" class="btn" style="background:#8b5cf6">Create Share Link</button>
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

    shCancelBtn.addEventListener('click', () => overlay.remove());

    let _shareCreated = false;

    shCreateBtn.addEventListener('click', async () => {
        // Fix the duplication of the shared links at specific sequences
        if (_shareCreated) { overlay.remove(); return; }

        // Guard: if overlay was removed (e.g. Cancel clicked) before the
        // async chain settles, bail out silently.
        if (!overlay.isConnected) return;

        shCreateBtn.disabled = true;
        shCreateBtn.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px">' +
            '<svg style="animation:spin 0.8s linear infinite;width:14px;height:14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>' +
            'Creating…</span>';
        if (!document.getElementById('fd-spin-style')) {
            const st = document.createElement('style');
            st.id = 'fd-spin-style';
            st.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
            document.head.appendChild(st);
        }
        // Snapshot all form values synchronously before the await
        const reqBody = {
            path,
            is_dir: isDir,
            require_account: overlay.querySelector('#sh-require-account')?.checked ?? false,
            track_stats:     overlay.querySelector('#sh-stats')?.checked ?? false,
            allow_anon_upload: isDir ? (overlay.querySelector('#sh-anon-upload')?.checked ?? false) : false,
            allow_auth_upload: isDir ? (overlay.querySelector('#sh-auth-upload')?.checked ?? false) : false,
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
                    shCopyBtn.textContent = '✓ Copied!';
                    shCopyBtn.style.background = '#15803d';
                    setTimeout(() => { shCopyBtn.textContent = 'Copy'; shCopyBtn.style.background = '#16a34a'; }, 2000);
                }).catch(() => { shLinkBox.select(); });
            }
            shCopyBtn.addEventListener('click', doCopy);
            doCopy();

            shCreateBtn.textContent = 'Done ✓';
            shCreateBtn.style.background = '#16a34a';
            shCreateBtn.disabled = false;
            _shareCreated = true;
            // shCreateBtn.addEventListener('click', () => overlay.remove(), { once: true });
        } catch (err) {
            if (!overlay.isConnected) return; // session expired, DOM gone — stay silent
            shCreateBtn.disabled = false;
            shCreateBtn.textContent = 'Create Share Link';
            if (err.message !== 'SESSION_EXPIRED') showMessage('Share failed', err.message);
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
        <div class="modal-content" style="max-width:640px;width:95vw;max-height:80vh;overflow-y:auto">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                <h3 style="font-size:18px;font-weight:700">🔗 Shared Links</h3>
                <button id="sm-close" style="background:none;border:none;font-size:20px;cursor:pointer;color:#64748b">✕</button>
            </div>
            <div id="sm-body"><p style="color:#64748b;font-size:14px">Loading…</p></div>
        </div>`;
    document.body.appendChild(overlay);
    document.getElementById('sm-close').addEventListener('click', () => overlay.remove());

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

function renderShareRow(s) {
    const shareUrl = `${window.location.origin}/share/${s.token}`;
    const urlEsc = escapeHtmlAttr(shareUrl);
    const nameEsc = escapeHtmlAttr(s.path.split('/').pop() || s.path);
    const pathEsc = escapeHtmlAttr(s.path);
    const created = s.created_at ? new Date(s.created_at).toLocaleDateString() : '?';

    // Format expiry for display and for the date input (YYYY-MM-DD)
    let expiryDisplay = '<span style="color:#94a3b8">Never</span>';
    let expiryInputVal = '';
    if (s.expires_at) {
        const expDate = new Date(s.expires_at);
        const isExpired = expDate < new Date();
        expiryDisplay = isExpired
            ? `<span style="color:#ef4444;font-weight:600">Expired ${expDate.toLocaleDateString()}</span>`
            : `<span style="color:#f59e0b;font-weight:600">⏰ ${expDate.toLocaleDateString()}</span>`;
        expiryInputVal = expDate.toISOString().slice(0, 10);
    }

    return `<div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
            <div>
                <span style="font-weight:600;font-size:14px">${s.is_dir ? '📁' : '📄'} ${nameEsc}</span>
                <span style="font-size:11px;color:#94a3b8;margin-left:8px">${pathEsc}</span>
                <div style="font-size:11px;color:#64748b;margin-top:3px">
                    Created ${created} · ${s.access_count || 0} access(es) · Expires: ${expiryDisplay}
                </div>
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0;margin-left:8px">
                ${s.track_stats ? `<button class="sm-stats-btn" data-token="${s.token}" data-name="${nameEsc}"
                    style="background:#0ea5e9;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">Stats</button>` : ''}
                <button class="sm-copy-btn" data-url="${urlEsc}"
                    style="background:#3b82f6;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">Copy Link</button>
                <button class="sm-delete-btn" data-token="${s.token}"
                    style="background:#ef4444;color:white;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px">Revoke</button>
            </div>
        </div>

        <div style="display:flex;gap:12px 20px;flex-wrap:wrap;align-items:center">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="require_account" ${s.require_account ? 'checked' : ''}>
                Require account
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="track_stats" ${s.track_stats ? 'checked' : ''}>
                Track stats
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_preview" ${s.allow_preview ? 'checked' : ''}>
                Allow preview
            </label>
            ${!s.is_dir ? `<label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_cdn_embed" ${s.allow_cdn_embed ? 'checked' : ''}>
                CDN embed
            </label>` : ''}
            ${s.is_dir ? `
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_anon_upload" ${s.allow_anon_upload ? 'checked' : ''}>
                Anyone can upload
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
                <input type="checkbox" class="sm-toggle" data-token="${s.token}" data-field="allow_auth_upload" ${s.allow_auth_upload ? 'checked' : ''}>
                Auth users can upload
            </label>` : ''}
            <div style="display:flex;align-items:center;gap:6px;font-size:13px">
                <span style="white-space:nowrap">⏰ Expiry:</span>
                <input type="date" class="sm-expiry-input" data-token="${s.token}"
                    value="${expiryInputVal}"
                    style="padding:3px 7px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;color:#1e293b">
                <button class="sm-expiry-clear" data-token="${s.token}"
                    style="background:none;border:1px solid #e2e8f0;border-radius:6px;padding:3px 7px;cursor:pointer;font-size:11px;color:#94a3b8"
                    title="Remove expiry (make permanent)">✕</button>
            </div>
        </div>
        ${s.allow_cdn_embed && !s.is_dir ? `
        <div style="margin-top:10px;padding:10px;background:#fefce8;border:1px solid #fde047;border-radius:8px">
            <div style="font-size:11px;color:#854d0e;font-weight:600;margin-bottom:5px">🌐 CDN Embed URL (direct media link):</div>
            <div style="display:flex;gap:6px">
                <input type="text" readonly value="${urlEsc}" style="flex:1;font-size:11px;padding:4px 7px;border:1px solid #fde047;border-radius:5px;background:white;color:#1e293b">
                <button class="sm-copy-btn" data-url="${urlEsc}" style="background:#ca8a04;color:white;border:none;border-radius:5px;padding:4px 10px;cursor:pointer;font-size:11px">Copy</button>
            </div>
            <div style="font-size:10px;color:#92400e;margin-top:4px">Use this URL directly in &lt;img&gt;, &lt;video&gt;, Discord, etc.</div>
        </div>` : ''}
    </div>`;
}

async function openShareStats(token, name) {
    try {
        const data = await apiCall(`/api/v1/shares/${token}/stats`, 'GET');
        const logs = data.logs || [];
        const rows = logs.length === 0 ? '<tr><td colspan="3" style="padding:12px;color:#94a3b8;text-align:center">No accesses recorded yet</td></tr>' :
            logs.map(l => `<tr style="border-top:1px solid #f1f5f9">
                <td style="padding:8px 12px;font-size:13px">${l.accessed_at ? new Date(l.accessed_at).toLocaleString() : '?'}</td>
                <td style="padding:8px 12px;font-size:13px">${l.username || '<span style="color:#94a3b8">anonymous</span>'}</td>
                <td style="padding:8px 12px;font-size:13px">${escapeHtmlAttr(l.action || 'view')}</td>
            </tr>`).join('');
        showMessage(`📊 Stats: ${name}`,
            `<div style="text-align:left;max-height:300px;overflow-y:auto">` +
            `<table style="width:100%;border-collapse:collapse"><thead><tr style="background:#f8fafc">
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">Time</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">User</th>
                <th style="padding:8px 12px;font-size:12px;color:#64748b;font-weight:600;text-align:left">Action</th>
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
            ? `<p style="color:#94a3b8;text-align:center;padding:1.5rem 0">Queue is empty.</p>`
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
        <div style="background:#0f172a;border-radius:14px;padding:1.5rem;
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

    function render(pending) {
        overlay.innerHTML = buildHTML(pending);

        overlay.querySelector('#im-close').addEventListener('click', () => {
            overlay.remove(); if (onClose) onClose();
        });
        overlay.addEventListener('click', ev => {
            if (ev.target === overlay) { overlay.remove(); if (onClose) onClose(); }
        });

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
        navigator.serviceWorker.register('/sw.js').catch(() => {
            // Registration failure is non-fatal; app still works online
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
            document.getElementById('mv-dialog-overlay').remove();
        } else if (document.getElementById('share-dialog-overlay')) {
            document.getElementById('share-dialog-overlay').remove();
        } else if (document.getElementById('ap-edit-overlay')) {
            document.getElementById('ap-edit-overlay').remove();
        } else if (document.getElementById('admin-panel-overlay')) {
            document.getElementById('admin-panel-overlay').remove();
        } else if (document.getElementById('profile-panel-overlay')) {
            document.getElementById('profile-panel-overlay').remove();
        } else if (document.getElementById('share-manager-overlay')) {
            document.getElementById('share-manager-overlay').remove();
        } else if (document.getElementById('profile-menu-modal')) {
            document.getElementById('profile-menu-modal').remove();
        } else {
            hideModal('message-modal');
        }
    });
    // Check if user was redirected from a verification link
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('verified')) {
        showMessage('Verification Successful', 'Your account is verified. Please log in.');
        // Clean the URL
        window.history.replaceState({}, document.title, window.location.pathname);
    }
    renderApp();
});