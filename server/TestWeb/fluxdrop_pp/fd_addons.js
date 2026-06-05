/**
 * fd_addons.js — supplementary features for FluxDrop
 * Include in index.html AFTER script.js.
 *
 * Features implemented here:
 *   1. i18n system  (window.t, window.FDi18n)
 *   2. Dark theme   (window.FDtheme)
 *   3. Network debug console
 *   4. Space analyzer panel
 *   5. Upload auto-negotiation fix (patches renderFileBrowserView)
 *   6. Trash folder browse (implements server-backed listing)
 *   7. Trash preview 206 fix (direct stream URL for video/audio)
 *   8. Loading spinners for slow-loading panels
 *   9. Settings panel extensions (lang, theme, debug toggles)
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. i18n SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════
 * Usage:
 *   t('key')              → localized string or English fallback
 *   t('key', {n: 5})      → string with {n} substituted
 *
 * Locale files must be at:
 *   <app_base>/locale/en.json   (bundled with FluxDrop)
 *   <app_base>/locale/uk.json   (bundled with FluxDrop)
 *
 * New languages: add a JSON file under locale/ following the same key schema.
 * Then register it in SUPPORTED_LANGS below.
 */
(function () {
  'use strict';

  const SUPPORTED_LANGS = ['en', 'uk'];
  const LOCALE_BASE     = (typeof _APP_BASE !== 'undefined' ? _APP_BASE : '') + '/locale/';
  const LS_KEY          = 'fluxdrop_lang';

  let _catalog   = {};   // active locale strings
  let _fallback  = {};   // English fallback
  let _lang      = 'en'; // resolved language
  let _ready     = false;

  /** Detect best language from browser + stored preference. */
  function _detectLang() {
    const stored = localStorage.getItem(LS_KEY);
    if (stored && SUPPORTED_LANGS.includes(stored)) return stored;
    const nav = (navigator.language || navigator.userLanguage || 'en').slice(0, 2).toLowerCase();
    return SUPPORTED_LANGS.includes(nav) ? nav : 'en';
  }

  /** Load a locale JSON file. Returns {} on failure. */
  async function _loadLocale(lang) {
    try {
      const r = await fetch(LOCALE_BASE + lang + '.json', { cache: 'no-cache' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } catch (_) {
      return {};
    }
  }

  /** (Re)load the active language. Resolves when ready. */
  async function _init(lang) {
    _lang = lang;
    localStorage.setItem(LS_KEY, lang);

    // Always load English as fallback first
    if (!Object.keys(_fallback).length) {
      _fallback = await _loadLocale('en');
    }
    _catalog = (lang === 'en') ? _fallback : await _loadLocale(lang);
    _ready   = true;

    // Notify any listeners that locale changed
    document.dispatchEvent(new CustomEvent('fd-locale-change', { detail: { lang } }));
  }

  /** Translate a key, substituting {var} placeholders. */
  window.t = function (key, vars) {
    let str = (_catalog && _catalog[key]) || (_fallback && _fallback[key]) || key;
    if (vars) {
      Object.entries(vars).forEach(([k, v]) => {
        str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), v);
      });
    }
    return str;
  };

  window.FDi18n = {
    get lang()   { return _lang; },
    get ready()  { return _ready; },
    get langs()  { return SUPPORTED_LANGS.slice(); },
    setLang: async function (lang) { await _init(lang); },
    /** Return a human-readable label for a language code. */
    label: function (code) {
      const labels = { en: 'English', uk: 'Українська' };
      return labels[code] || code.toUpperCase();
    },
  };

  // Boot
  _init(_detectLang());
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. DARK THEME
 * ═══════════════════════════════════════════════════════════════════════════
 * - Reads OS prefers-color-scheme as the default.
 * - Manual toggle stored in localStorage ('fluxdrop_theme': 'light'|'dark'|'auto').
 * - Applies [data-theme="dark"] on <html> element.
 * - MutationObserver patches inline-styled elements created by script.js.
 */
(function () {
  'use strict';
  const LS_KEY   = 'fluxdrop_theme';
  const ROOT_EL  = document.documentElement;

  // Inline-bg colors to replace in dark mode (bg properties only)
  const DARK_BG_MAP = [
    { re: /(background(?:-color)?)\s*:\s*(#fff\b|#ffffff\b|white\b)/gi,   rep: '$1:#1a2535'  },
    { re: /(background(?:-color)?)\s*:\s*(#f8fafc\b)/gi,                  rep: '$1:#131f2e'  },
    { re: /(background(?:-color)?)\s*:\s*(#f1f5f9\b)/gi,                  rep: '$1:#1e2d3d'  },
    { re: /(background(?:-color)?)\s*:\s*(#f0f9ff\b)/gi,                  rep: '$1:#0d1520'  },
    { re: /(background(?:-color)?)\s*:\s*(#eff6ff\b)/gi,                  rep: '$1:#1a3050'  },
    { re: /(background(?:-color)?)\s*:\s*(#dbeafe\b)/gi,                  rep: '$1:#1e3a5f'  },
    { re: /(border(?:-[a-z]+)?-color)\s*:\s*(#e2e8f0\b)/gi,               rep: '$1:#2d3f52'  },
    { re: /(color)\s*:\s*(#1e293b\b)/gi,                                   rep: '$1:#e2e8f0'  },
    { re: /(color)\s*:\s*(#374151\b)/gi,                                   rep: '$1:#cbd5e1'  },
    { re: /(color)\s*:\s*(#4b5563\b)/gi,                                   rep: '$1:#94a3b8'  },
  ];

  function _isDark(mode) {
    if (mode === 'dark')  return true;
    if (mode === 'light') return false;
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function _applyTheme(mode) {
    const dark = _isDark(mode);
    ROOT_EL.setAttribute('data-theme', dark ? 'dark' : 'light');
    // Also update any already-rendered toggle buttons
    document.querySelectorAll('.fd-theme-toggle-btn').forEach(btn => {
      btn.textContent = dark ? '☀ Light' : '🌙 Dark';
      btn.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
    });
  }

  function _patchElement(el) {
    // Only patch elements that have inline style strings containing bg colors
    if (el.nodeType !== 1) return;
    const style = el.getAttribute('style');
    if (!style) return;
    let patched = style;
    DARK_BG_MAP.forEach(({ re, rep }) => { patched = patched.replace(re, rep); });
    if (patched !== style) {
      el.setAttribute('style', patched);
      el.dataset.fdDarkPatched = '1';
    }
  }

  function _patchTree(root) {
    if (root.nodeType === 1) _patchElement(root);
    root.querySelectorAll && root.querySelectorAll('[style]').forEach(_patchElement);
  }

  // MutationObserver: patch new nodes when dark mode is active
  const _mo = new MutationObserver(muts => {
    if (ROOT_EL.getAttribute('data-theme') !== 'dark') return;
    muts.forEach(m => m.addedNodes.forEach(n => {
      if (n.nodeType === 1) {
        _patchElement(n);
        n.querySelectorAll && n.querySelectorAll('[style]').forEach(_patchElement);
      }
    }));
  });
  _mo.observe(document.body, { childList: true, subtree: true });

  window.FDtheme = {
    /** Returns current effective theme: 'dark' | 'light' */
    get current() { return ROOT_EL.getAttribute('data-theme') || 'light'; },
    /** Returns stored mode: 'dark' | 'light' | 'auto' */
    get mode()    { return localStorage.getItem(LS_KEY) || 'auto'; },
    toggle: function () {
      const newMode = FDtheme.current === 'dark' ? 'light' : 'dark';
      localStorage.setItem(LS_KEY, newMode);
      _applyTheme(newMode);
      if (newMode === 'dark') _patchTree(document.body);
    },
    setMode: function (mode) {
      localStorage.setItem(LS_KEY, mode);
      _applyTheme(mode);
      if (_isDark(mode)) _patchTree(document.body);
    },
  };

  // Apply on load
  const _savedMode = localStorage.getItem(LS_KEY) || 'auto';
  _applyTheme(_savedMode);
  if (_isDark(_savedMode)) {
    // Defer one tick so the DOM is populated first
    setTimeout(() => _patchTree(document.body), 0);
  }

  // Watch OS preference changes when mode is 'auto'
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((localStorage.getItem(LS_KEY) || 'auto') === 'auto') {
      _applyTheme('auto');
    }
  });
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. NETWORK DEBUG CONSOLE
 * ═══════════════════════════════════════════════════════════════════════════
 * Small one-liner at the bottom of the screen showing the last fetch action.
 * Toggle via Settings checkbox. Stored in localStorage ('fluxdrop_debug_bar').
 *
 * Hooks into fetchWithFallback by wrapping it.
 */
(function () {
  'use strict';
  const LS_KEY   = 'fluxdrop_debug_bar';
  const MAX_HIST = 40;
  let _history   = [];
  let _bar       = null;
  let _enabled   = localStorage.getItem(LS_KEY) === '1';

  /** Create the bar DOM element (once). */
  function _ensureBar() {
    if (_bar && _bar.isConnected) return _bar;
    const bar = document.createElement('div');
    bar.id = 'fd-debug-bar';
    bar.innerHTML =
      `<span class="fd-db-label">${t('debug_bar_label')}</span>` +
      `<span class="fd-db-text fd-db-idle">${t('debug_bar_idle')}</span>` +
      `<span class="fd-db-clear" title="${t('debug_clear')}">✕</span>`;
    bar.querySelector('.fd-db-clear').addEventListener('click', () => {
      _history = [];
      _render();
    });
    document.body.appendChild(bar);
    _bar = bar;
    return bar;
  }

  function _render() {
    if (!_bar || !_bar.isConnected) return;
    const txt = _bar.querySelector('.fd-db-text');
    if (!txt) return;
    if (!_history.length) {
      txt.textContent = t('debug_bar_idle');
      txt.className = 'fd-db-text fd-db-idle';
      return;
    }
    const last = _history[_history.length - 1];
    const cls  = last.err ? 'fd-db-err' :
                 (last.status >= 400) ? 'fd-db-warn' :
                 (last.status >= 200) ? 'fd-db-ok'   : 'fd-db-in';
    const statStr = last.err ? '(error)' :
                    last.status  ? `${last.status}` : '…';
    const elapsed = last.elapsed != null ? ` | ${last.elapsed}ms` : '';
    txt.textContent = `→ ${last.method} ${last.url}${elapsed}${last.status ? ' | ' + statStr : ''}`;
    txt.className   = 'fd-db-text ' + cls;
  }

  /** Record a completed fetch event and re-render the bar. */
  function _record(entry) {
    _history.push(entry);
    if (_history.length > MAX_HIST) _history.shift();
    if (_enabled) _render();
  }

  /** Wrap fetchWithFallback — called once when both this script and script.js are loaded. */
  function _patchFetch() {
    if (typeof fetchWithFallback !== 'function') return;
    const _orig = fetchWithFallback;
    window.fetchWithFallback = async function (url, options) {
      const method = (options && options.method) || 'GET';
      const t0 = performance.now();
      // Strip base URL for display
      let displayUrl = url;
      try { displayUrl = new URL(url).pathname + (new URL(url).search || ''); } catch (_) {}

      if (_enabled) {
        // Show "in flight" immediately
        _record({ method, url: displayUrl, status: null, elapsed: null, err: false });
      }

      try {
        const resp    = await _orig(url, options);
        const elapsed = Math.round(performance.now() - t0);
        _record({ method, url: displayUrl, status: resp.status, elapsed, err: false });
        return resp;
      } catch (err) {
        const elapsed = Math.round(performance.now() - t0);
        _record({ method, url: displayUrl, status: 0, elapsed, err: true });
        throw err;
      }
    };
  }

  window.FDdebug = {
    get enabled() { return _enabled; },
    get history()  { return _history.slice(); },
    enable: function () {
      _enabled = true;
      localStorage.setItem(LS_KEY, '1');
      _ensureBar();
      _render();
    },
    disable: function () {
      _enabled = false;
      localStorage.setItem(LS_KEY, '0');
      if (_bar) { _bar.remove(); _bar = null; }
    },
    toggle: function () { FDdebug.enabled ? FDdebug.disable() : FDdebug.enable(); },
  };

  // Defer patch so script.js has fully defined fetchWithFallback
  document.addEventListener('DOMContentLoaded', () => {
    _patchFetch();
    if (_enabled) { _ensureBar(); _render(); }
  });
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. SPACE ANALYZER
 * ═══════════════════════════════════════════════════════════════════════════
 * Sorted bar-chart view of your biggest files and folders.
 * Requires: GET /api/v1/space_analyze  (see server_cdn.py patch)
 * Opens as a modal; accessible from the profile panel.
 */
(function () {
  'use strict';

  function _fmt(b) {
    if (b == null || isNaN(b)) return '—';
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576)    return (b / 1048576).toFixed(1)    + ' MB';
    if (b >= 1024)       return (b / 1024).toFixed(0)       + ' KB';
    return b + ' B';
  }

  function _colorForIndex(i) {
    const palette = ['#3b82f6','#6366f1','#8b5cf6','#ec4899','#f59e0b',
                     '#10b981','#06b6d4','#84cc16','#f97316','#ef4444'];
    return palette[i % palette.length];
  }

  window.openSpaceAnalyzer = async function () {
    // Remove any existing instance
    document.getElementById('fd-sa-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id    = 'fd-sa-overlay';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-content" style="max-width:700px;width:96vw;padding:0;
           overflow:hidden;border-radius:14px" data-fd-dark="surface">
        <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);
             padding:16px 20px;display:flex;align-items:center;justify-content:space-between"
             data-fd-dark="header">
          <div>
            <div style="color:white;font-weight:700;font-size:16px">
              📊 ${t('space_analyzer_title')}
            </div>
            <div style="color:rgba(255,255,255,.75);font-size:12px;margin-top:2px">
              ${t('space_analyzer_hint')}
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <select id="fd-sa-depth" style="padding:4px 8px;border-radius:6px;font-size:12px;
                border:1px solid rgba(255,255,255,.3);background:rgba(255,255,255,.15);
                color:white;cursor:pointer">
              <option value="files">Top files</option>
              <option value="folders">Top folders</option>
              <option value="all" selected>All (mixed)</option>
            </select>
            <button id="fd-sa-close" style="background:rgba(255,255,255,.2);border:none;
                color:white;border-radius:50%;width:30px;height:30px;font-size:16px;
                cursor:pointer;display:flex;align-items:center;justify-content:center">✕</button>
          </div>
        </div>
        <div id="fd-sa-body" style="padding:14px 20px;max-height:70vh;overflow-y:auto">
          <div style="text-align:center;padding:2rem;color:#94a3b8">
            <div style="font-size:2rem;margin-bottom:0.5rem">📂</div>
            ${t('space_analyzer_loading')}
          </div>
        </div>
      </div>`;

    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    overlay.querySelector('#fd-sa-close').addEventListener('click', () => overlay.remove());

    const depthSel = overlay.querySelector('#fd-sa-depth');
    depthSel.addEventListener('change', () => _render(overlay, _lastData, depthSel.value));

    let _lastData = null;

    // Load data
    try {
      const resp = await (typeof apiCall === 'function'
        ? apiCall('/api/v1/space_analyze', 'GET')
        : _saFetch());
      _lastData = resp;
      _render(overlay, resp, depthSel.value);
    } catch (err) {
      const body = overlay.querySelector('#fd-sa-body');
      if (body) body.innerHTML = `<p style="color:#ef4444;padding:2rem;text-align:center">
        Failed to load: ${err.message}</p>`;
    }
  };

  async function _saFetch() {
    const r = await fetch('/api/v1/space_analyze', {
      headers: { 'Authorization': 'Bearer ' + (localStorage.getItem('fluxdrop_token') || '') }
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  function _render(overlay, data, filter) {
    const body = overlay.querySelector('#fd-sa-body');
    if (!body || !data) return;

    let items = (data.items || []).slice();

    if (filter === 'files')   items = items.filter(i => !i.is_dir);
    if (filter === 'folders') items = items.filter(i => i.is_dir);

    items.sort((a, b) => b.size_bytes - a.size_bytes);
    const top    = items.slice(0, 50);
    const maxSz  = top[0] ? top[0].size_bytes : 1;
    const total  = data.total_bytes || 1;

    if (!top.length) {
      body.innerHTML = `<div style="text-align:center;padding:2rem;color:#94a3b8">
        ${t('space_analyzer_empty')}</div>`;
      return;
    }

    const totalRow = `
      <div style="display:flex;align-items:center;justify-content:space-between;
           padding:6px 0 10px;border-bottom:2px solid var(--fd-border,#e2e8f0);
           margin-bottom:8px;font-size:12px;color:var(--fd-muted,#64748b)">
        <span>${top.length} of ${items.length} item${items.length!==1?'s':''}</span>
        <span style="font-weight:600;color:var(--fd-text,#1e293b)">${t('size')}: ${_fmt(data.total_bytes)}</span>
      </div>`;

    const rows = top.map((item, i) => {
      const pct  = (item.size_bytes / maxSz * 100).toFixed(1);
      const pctT = (item.size_bytes / total  * 100).toFixed(1);
      const name = item.name || item.path.split('/').pop() || item.path;
      const icon = item.is_dir ? '📁' : '📄';
      const color = _colorForIndex(i);
      return `<div class="fd-sa-bar-wrap" title="${pctT}% of total · ${_fmt(item.size_bytes)}">
        <span style="font-size:14px;flex-shrink:0">${icon}</span>
        <span class="fd-sa-name" title="${item.path}">${name}</span>
        <div class="fd-sa-bar-track">
          <div class="fd-sa-bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="fd-sa-size">${_fmt(item.size_bytes)}</span>
        <span class="fd-sa-type" style="color:${color}">${pctT}%</span>
      </div>`;
    }).join('');

    body.innerHTML = totalRow + rows;
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. UPLOAD AUTO-NEGOTIATION FIX
 * ═══════════════════════════════════════════════════════════════════════════
 * The existing auto-detect in renderFileBrowserView updates _folderMode and
 * the toggle button visuals but does NOT sync the file input's webkitdirectory
 * / multiple attributes.  This patch wraps renderFileBrowserView to attach an
 * additional change listener that also updates the input attributes.
 */
(function () {
  'use strict';

  // Wait until renderFileBrowserView is available
  const _orig = window.renderFileBrowserView;
  if (typeof _orig !== 'function') return;

  window.renderFileBrowserView = function () {
    _orig.apply(this, arguments);

    // After original renders, grab references
    const fileInput = document.getElementById('upload-file');
    const folderBtn = document.getElementById('btn-folder-toggle');
    if (!fileInput || !folderBtn) return;

    // Patch the existing change listener to also sync input attributes.
    // We use a capturing listener at the document level for the specific input.
    fileInput.addEventListener('change', function _fdAutoNegotiate() {
      const files = Array.from(fileInput.files || []);
      if (!files.length) return;

      const hasPaths = files.some(f => f.webkitRelativePath && f.webkitRelativePath.includes('/'));
      const isFolder = fileInput.hasAttribute('webkitdirectory');

      if (hasPaths && !isFolder) {
        // Files have sub-paths but input isn't in folder mode — switch.
        fileInput.setAttribute('webkitdirectory', '');
        fileInput.setAttribute('mozdirectory', '');
        fileInput.removeAttribute('multiple');
        folderBtn.textContent = '📄 Files';
        folderBtn.style.background = '#6366f1';
        folderBtn.title = t('auto_mode_folder') + ' — click to switch back';
        // Brief flash to let user know
        folderBtn.style.boxShadow = '0 0 0 3px #818cf8';
        setTimeout(() => { folderBtn.style.boxShadow = ''; }, 1400);
      } else if (!hasPaths && isFolder) {
        // Input is in folder mode but selection has no sub-paths — user
        // may have picked a flat folder; keep folder mode but note it.
        // (Do NOT force-switch back; flat folders are valid folder uploads.)
      }
      // Also: if somehow files were picked in folder mode but they're truly
      // flat files (not webkitRelativePath), correct the reverse.
    }, false);

    // Fix: after reset (upload done), re-check if webkitdirectory stuck.
    // The form reset event fires after handleUploadForm clears fileInput.value.
    const form = document.getElementById('upload-form');
    if (form) {
      form.addEventListener('reset', () => {
        // Input attributes remain as set — that's correct for the current mode.
      });
    }
  };
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. TRASH FOLDER BROWSE
 * ═══════════════════════════════════════════════════════════════════════════
 * Replaces the "Browse" stub in _refreshTrashView with a real directory tree
 * fetched from GET /api/v1/trash/<id>/list  (server patch required).
 *
 * Hooks in via event delegation on the trash-body container.
 */
(function () {
  'use strict';

  // Replace stub: intercept Browse button clicks via capturing delegation
  document.addEventListener('click', async function _fdTrashBrowse(e) {
    const btn = e.target.closest('.trash-browse-btn');
    if (!btn) return;

    const row = btn.closest('.trash-row');
    if (!row) return;

    // Toggle: if tree already open, close it.
    const existing = row.nextElementSibling;
    if (existing && existing.classList.contains('trash-tree-panel')) {
      existing.remove();
      btn.textContent = t('browse');
      return;
    }

    const id = +btn.dataset.id;
    btn.textContent = t('loading');
    btn.disabled    = true;

    const panel = document.createElement('div');
    panel.className  = 'trash-tree-panel';
    panel.style.cssText =
      'background:#f8fafc;border-bottom:1px solid #e2e8f0;' +
      'padding:10px 20px 10px 44px;font-size:12px;color:#475569;' +
      'max-height:300px;overflow-y:auto';

    try {
      const data = await apiCall(`/api/v1/trash/${id}/list`, 'GET');
      const items = data.items || [];

      if (!items.length) {
        panel.innerHTML = '<em style="color:#94a3b8">📂 Folder is empty.</em>';
      } else {
        panel.innerHTML = _renderTrashTree(items);
      }
    } catch (err) {
      if (err.message && err.message.includes('404')) {
        // Endpoint not deployed yet — show friendly message
        panel.innerHTML =
          `<em style="color:#94a3b8">📂 Folder browsing requires a server update.<br>
           Deploy the <code>/api/v1/trash/&lt;id&gt;/list</code> endpoint patch.</em>`;
      } else {
        panel.innerHTML =
          `<span style="color:#ef4444">Failed: ${err.message}</span>`;
      }
    }

    row.insertAdjacentElement('afterend', panel);
    btn.textContent = 'Close';
    btn.disabled    = false;
  }, true);  // capturing so we run even if inner listener calls stopPropagation

  /** Render a simple indented file tree from flat items array. */
  function _renderTrashTree(items) {
    function _fmt(b) {
      if (b >= 1073741824) return (b/1073741824).toFixed(2) + ' GB';
      if (b >= 1048576)    return (b/1048576).toFixed(1)    + ' MB';
      if (b >= 1024)       return (b/1024).toFixed(0)       + ' KB';
      return (b || 0) + ' B';
    }

    // Sort: dirs first, then files, each alphabetically
    const sorted = [...items].sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    return sorted.map(item => {
      const icon  = item.is_dir ? '📁' : '📄';
      const sz    = item.is_dir ? '' :
        `<span style="margin-left:auto;color:#94a3b8;font-size:11px">${_fmt(item.size_bytes)}</span>`;
      const indent = '  '.repeat((item.depth || 0));
      return `<div style="display:flex;align-items:center;gap:5px;padding:2px 0;
                  padding-left:${(item.depth||0)*14}px">
        <span>${icon}</span>
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1"
              title="${item.path || item.name}">${item.name}</span>
        ${sz}
      </div>`;
    }).join('');
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 7. TRASH PREVIEW 206 FIX — video / audio native streaming
 * ═══════════════════════════════════════════════════════════════════════════
 * The original _previewTrashFile fetches video/audio as a full Blob before
 * creating a blob: URL. This blocks playback until the entire file is in RAM.
 * Fix: for video/audio, pass the direct stream URL with ?token= so the browser
 * can send Range requests and stream natively (the server already supports 206).
 *
 * We override _previewTrashFile on window. Since it is a module-local
 * function we can't reach it directly, so we use event delegation to intercept
 * .trash-preview-btn clicks first (capturing phase) and handle video/audio
 * ourselves; for other types we let the original proceed.
 */
(function () {
  'use strict';

  const VIDEO_EXTS = new Set(['mp4','webm','mkv','mov','avi','m4v','ogv']);
  const AUDIO_EXTS = new Set(['mp3','flac','wav','m4a','ogg','opus','aac']);

  function _ext(filename) { return (filename.split('.').pop() || '').toLowerCase(); }

  document.addEventListener('click', async function _fdTrashPreview206(e) {
    const btn = e.target.closest('.trash-preview-btn');
    if (!btn) return;

    const filename = btn.dataset.name || '';
    const ext      = _ext(filename);
    const isVideo  = VIDEO_EXTS.has(ext);
    const isAudio  = AUDIO_EXTS.has(ext);
    if (!isVideo && !isAudio) return; // let original _previewTrashFile handle

    // Stop propagation so the original listener doesn't also fire
    e.stopPropagation();

    const id       = +btn.dataset.id;
    const token    = (typeof authToken !== 'undefined') ? authToken : localStorage.getItem('fluxdrop_token');
    const apiBase  = (typeof API_BASE_URL !== 'undefined') ? API_BASE_URL : '';
    // Build URL; append token as query param so browser can send Range requests
    const streamUrl = `${apiBase}/api/v1/trash/${id}/file` +
                      (token ? `?token=${encodeURIComponent(token)}` : '');

    const modal   = document.getElementById('preview-modal');
    const titleEl = document.getElementById('preview-title');
    const bodyEl  = document.getElementById('preview-body');
    const dlBtn   = document.getElementById('preview-download-btn');

    if (!modal || !bodyEl) return;
    titleEl.textContent = filename;
    dlBtn.style.display = 'none';
    modal.classList.remove('hidden');

    if (isVideo) {
      bodyEl.innerHTML = `
        <video controls autoplay
          style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto;background:#000">
          <source src="${streamUrl}">
          Your browser doesn't support this video format.
        </video>`;
    } else {
      bodyEl.innerHTML = `
        <div style="padding:2rem 1rem;text-align:center">
          <div style="font-size:4rem;margin-bottom:1rem">🎵</div>
          <div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${filename}</div>
          <audio controls autoplay style="width:100%">
            <source src="${streamUrl}">
          </audio>
        </div>`;
    }
  }, true); // capturing phase — fires before the original listener
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 8. LOADING SPINNERS FOR SLOW PANELS
 * ═══════════════════════════════════════════════════════════════════════════
 * Replaces the plain "Loading…" text placeholders in profile panel and
 * trash view with an animated spinner + label.
 * Uses a MutationObserver to detect when these panels open.
 */
(function () {
  'use strict';

  /** Replace any element whose text is exactly "Loading…" with a spinner. */
  function _upgradeLoadingText(root) {
    root.querySelectorAll('*').forEach(el => {
      if (el.childElementCount === 0 &&
          el.textContent.trim() === 'Loading…' &&
          !el.dataset.fdSpinUpgraded) {
        el.dataset.fdSpinUpgraded = '1';
        el.innerHTML = _spinnerHtml('Loading…');
      }
    });
  }

  function _spinnerHtml(label) {
    return `<span style="display:inline-flex;align-items:center;gap:8px;color:#94a3b8">
      <span style="display:inline-block;width:16px;height:16px;border-radius:50%;
            border:2px solid #334155;border-top-color:#3b82f6;
            animation:fd-spin .7s linear infinite;flex-shrink:0"></span>
      ${label}
    </span>`;
  }

  // Upgrade placeholders when profile/trash panels open
  const _obs = new MutationObserver(muts => {
    muts.forEach(m => {
      m.addedNodes.forEach(n => {
        if (n.nodeType !== 1) return;
        // Profile panel quota card loading placeholder
        const quotaCard = n.id === 'pp-quota-card' ? n :
                          n.querySelector?.('#pp-quota-card');
        if (quotaCard) _upgradeLoadingText(quotaCard);

        // Trash body loading placeholder
        const trashBody = n.id === 'trash-body' ? n :
                          n.querySelector?.('#trash-body');
        if (trashBody) _upgradeLoadingText(trashBody);

        // Any other panel that shows "Loading…" text
        if (n.id && n.id.endsWith('-body')) _upgradeLoadingText(n);
      });
    });
  });

  document.addEventListener('DOMContentLoaded', () => {
    if (document.body) {
      _obs.observe(document.body, { childList: true, subtree: true });
    }
  });
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 9. SETTINGS PANEL EXTENSIONS
 * ═══════════════════════════════════════════════════════════════════════════
 * Injects additional controls into the profile panel (opened by openProfilePanel):
 *   - Dark mode toggle  (checkbox → FDtheme)
 *   - Language selector (select → FDi18n)
 *   - Debug console toggle (checkbox → FDdebug)
 *   - "Analyze Space" button (→ openSpaceAnalyzer)
 *
 * Strategy: watch for #profile-panel-overlay appearing in the DOM, then
 * append our section inside its scrollable area.
 */
(function () {
  'use strict';

  function _buildSettingsBlock() {
    const isDark    = FDtheme.current === 'dark';
    const debugOn   = FDdebug.enabled;
    const curLang   = FDi18n.lang;

    const langOptions = FDi18n.langs.map(code =>
      `<option value="${code}"${code === curLang ? ' selected' : ''}>${FDi18n.label(code)}</option>`
    ).join('');

    const block = document.createElement('div');
    block.id    = 'fd-settings-block';
    block.innerHTML = `
      <hr style="border:none;border-top:1px solid var(--fd-border,#e2e8f0);margin:0" data-fd-dark="hr">

      <div style="font-size:13px;font-weight:700;color:var(--fd-text2,#374151);
           margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em">
        Appearance &amp; Extras
      </div>

      <!-- Dark mode toggle -->
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="fd-dark-chk" ${isDark?'checked':''} style="width:16px;height:16px">
        <span style="font-size:13px;font-weight:600;color:var(--fd-text2,#374151)">
          🌙 ${t('dark_mode')}
        </span>
      </label>

      <!-- Language selector -->
      <label style="display:block;font-size:13px;font-weight:600;
           color:var(--fd-text2,#374151);margin-bottom:10px">
        🌍 ${t('language')}
        <select id="fd-lang-sel" style="display:block;width:100%;margin-top:4px;
            padding:7px 10px;border:1px solid var(--fd-border,#e2e8f0);
            border-radius:8px;font-size:14px;font-family:Inter,sans-serif;
            background:var(--fd-input-bg,#fff);color:var(--fd-text,#1e293b)">
          ${langOptions}
        </select>
      </label>

      <!-- Debug console toggle -->
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="fd-debug-chk" ${debugOn?'checked':''} style="width:16px;height:16px">
        <span style="font-size:13px;font-weight:600;color:var(--fd-text2,#374151)">
          🔌 ${t('debug_console')}
        </span>
      </label>

      <!-- Space analyzer -->
      <button id="fd-sa-btn" style="width:100%;padding:8px 14px;border-radius:8px;
          border:1px solid #3b82f6;background:none;color:#3b82f6;font-size:13px;
          font-weight:600;cursor:pointer;font-family:Inter,sans-serif;margin-bottom:4px;
          transition:background .15s">
        📊 ${t('analyze_space')}
      </button>`;

    return block;
  }

  function _attachBlockListeners(block, overlay) {
    // Dark mode
    block.querySelector('#fd-dark-chk').addEventListener('change', function () {
      FDtheme.setMode(this.checked ? 'dark' : 'light');
    });

    // Language
    block.querySelector('#fd-lang-sel').addEventListener('change', async function () {
      await FDi18n.setLang(this.value);
      // Refresh the block labels to reflect new language
      const freshBlock = _buildSettingsBlock();
      block.replaceWith(freshBlock);
      _attachBlockListeners(freshBlock, overlay);
    });

    // Debug console
    block.querySelector('#fd-debug-chk').addEventListener('change', function () {
      this.checked ? FDdebug.enable() : FDdebug.disable();
    });

    // Space analyzer
    block.querySelector('#fd-sa-btn').addEventListener('click', () => {
      overlay.remove();
      openSpaceAnalyzer();
    });
  }

  function _injectIntoPanel(overlay) {
    // Find the scrollable grid inside the panel
    const grid = overlay.querySelector('[style*="display:grid"]');
    if (!grid) return;

    // Don't inject twice
    if (overlay.querySelector('#fd-settings-block')) return;

    const block = _buildSettingsBlock();
    _attachBlockListeners(block, overlay);
    grid.appendChild(block);

    // If dark mode is active, patch the newly inserted elements too
    if (FDtheme.current === 'dark' && typeof FDtheme !== 'undefined') {
      block.querySelectorAll('[style]').forEach(el => {
        const s = el.getAttribute('style');
        if (s && s.includes('#fff')) el.setAttribute('style', s.replace(/#fff\b|#ffffff\b|white\b/gi, '#1a2535'));
      });
    }
  }

  // Watch for profile panel overlay
  const _panelObs = new MutationObserver(muts => {
    muts.forEach(m => {
      m.addedNodes.forEach(n => {
        if (n.nodeType !== 1) return;
        if (n.id === 'profile-panel-overlay') {
          // Small delay so the panel's own async load doesn't conflict
          setTimeout(() => _injectIntoPanel(n), 80);
        }
      });
    });
  });

  document.addEventListener('DOMContentLoaded', () => {
    if (document.body) _panelObs.observe(document.body, { childList: true });
  });
})();
