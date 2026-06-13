/**
 * fd_addons.js — supplementary features for FluxDrop  (v2 — patch round)
 * Include in index.html AFTER script.js.
 *
 * Sections:
 *   1. i18n system  (window.t, window.FDi18n, + DOM text translation)
 *   2. Dark theme   (save/restore inline styles; proper light↔dark cycle)
 *   3. Network debug console  (z-index: max int)
 *   4. Space analyzer  (file-manager drill-down navigation)
 *   5. Upload: folder drag-drop detection + 409 conflict error display
 *   6. Trash folder browse  (server-backed listing)
 *   7. Trash preview 206 fix  (direct stream URL for video/audio)
 *   8. Loading spinners
 *   9. Settings panel extensions
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. i18n SYSTEM
 * ═══════════════════════════════════════════════════════════════════════════
 * t('key') / t('key', {n:5})  — translate a key.
 *
 * Initialisation order:
 *   1. fd_locale_bundle.js (loaded BEFORE this file via <script> in HTML)
 *      defines window._FD_LOCALES synchronously.
 *   2. fd_addons.js runs — _initSync() reads _FD_LOCALES immediately.
 *      t() is ready BEFORE any render function in script.js fires.
 *   3. Fallback: if the bundle is missing, _initAsync() fetches locale JSON
 *      over the network — this risks t() returning bare keys on first paint,
 *      but works as graceful degradation.
 *
 * DOM translation:
 *   _translateSubtree(el) walks text nodes and replaces any whose trimmed
 *   text exactly matches an English catalog string.
 *   MutationObserver calls this on every new subtree — because _ready=true
 *   synchronously, ALL dynamic nodes rendered by script.js are translated
 *   the moment they enter the DOM.
 */
(function () {
  'use strict';

  const SUPPORTED_LANGS = ['en', 'uk'];
  const LOCALE_BASE     = '/fluxdrop_pp/locale/';
  const LS_KEY          = 'fluxdrop_lang';

  let _catalog  = {};
  let _fallback = {};
  let _revMap   = {};
  let _lang     = 'en';
  let _ready    = false;

  function _detectLang() {
    const stored = localStorage.getItem(LS_KEY);
    if (stored && SUPPORTED_LANGS.includes(stored)) return stored;
    const nav = (navigator.language || 'en').slice(0, 2).toLowerCase();
    return SUPPORTED_LANGS.includes(nav) ? nav : 'en';
  }

  function _buildRevMap(catalog) {
    const map = {};
    Object.entries(catalog).forEach(([k, v]) => {
      if (typeof v === 'string' && v.length > 1 && !v.includes('{'))
        map[v] = k;
    });
    return map;
  }

  /** Synchronous init from fd_locale_bundle.js. Returns true on success. */
  function _initSync() {
    const bundle = window._FD_LOCALES;
    if (!bundle || typeof bundle !== 'object') return false;
    const lang   = _detectLang();
    _lang        = lang;
    localStorage.setItem(LS_KEY, lang);
    _fallback    = bundle['en']  || {};
    _catalog     = bundle[lang]  || _fallback;
    _revMap      = _buildRevMap(_fallback);
    _ready       = true;
    return true;
  }

  /** Async fallback when bundle is unavailable. */
  async function _loadLocale(lang) {
    try {
      const r = await fetch(LOCALE_BASE + lang + '.json', { cache: 'no-cache' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } catch (_) { return {}; }
  }

  async function _initAsync(lang) {
    _lang = lang;
    localStorage.setItem(LS_KEY, lang);
    if (!Object.keys(_fallback).length) _fallback = await _loadLocale('en');
    _catalog = (lang === 'en') ? _fallback : await _loadLocale(lang);
    _revMap  = _buildRevMap(_fallback);
    _ready   = true;
    document.dispatchEvent(new CustomEvent('fd-locale-change', { detail: { lang } }));
    if (document.body) _translateSubtree(document.body);
  }

  window.t = function (key, vars) {
    let str = (_catalog[key]) || (_fallback[key]) || key;
    if (vars) Object.entries(vars).forEach(([k, v]) => {
      str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), v);
    });
    return str;
  };

  /** Re-initialise with a new language (called from Settings panel). */
  async function _setLang(lang) {
    if (window._FD_LOCALES) {
      _lang    = lang;
      localStorage.setItem(LS_KEY, lang);
      _catalog = window._FD_LOCALES[lang] || _fallback;
    } else {
      await _initAsync(lang);
    }
    document.dispatchEvent(new CustomEvent('fd-locale-change', { detail: { lang } }));
    if (document.body) _translateSubtree(document.body);
  }

  /** Translate text nodes and key attributes inside `root`. */
  function _translateSubtree(root) {
    if (!_ready || _lang === 'en') return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    let node;
    while ((node = walker.nextNode())) {
      const txt = node.textContent.trim();
      if (txt && _revMap[txt]) {
        const translated = t(_revMap[txt]);
        if (translated !== txt)
          node.textContent = node.textContent.replace(txt, translated);
      }
    }
    root.querySelectorAll && root.querySelectorAll('[title],[placeholder],[aria-label]').forEach(el => {
      ['title', 'placeholder', 'aria-label'].forEach(attr => {
        const v = el.getAttribute(attr);
        if (v && _revMap[v.trim()]) {
          const translated = t(_revMap[v.trim()]);
          if (translated !== v.trim()) el.setAttribute(attr, translated);
        }
      });
    });
  }

  // MutationObserver — translate newly inserted nodes
  const _i18nObs = new MutationObserver(muts => {
    if (!_ready || _lang === 'en') return;
    muts.forEach(m => m.addedNodes.forEach(n => {
      if (n.nodeType === 1) _translateSubtree(n);
    }));
  });
  document.addEventListener('DOMContentLoaded', () => {
    _i18nObs.observe(document.body, { childList: true, subtree: true });
    if (_ready && _lang !== 'en') _translateSubtree(document.body);
  });

  window.FDi18n = {
    get lang()  { return _lang; },
    get ready() { return _ready; },
    get langs() { return SUPPORTED_LANGS.slice(); },
    setLang: _setLang,
    label:   function (c) { return { en: 'English', uk: 'Українська' }[c] || c.toUpperCase(); },
  };

  // ── Boot ─────────────────────────────────────────────────────────────────
  if (!_initSync()) {
    console.warn('[FDi18n] fd_locale_bundle.js not loaded — falling back to async fetch. '
               + 'First-paint t() calls may return bare keys.');
    _initAsync(_detectLang());
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. DARK THEME
 * ═══════════════════════════════════════════════════════════════════════════
 * Key fix vs v1: before patching an element's inline styles, save the
 * original in data-fd-orig-style.  Restoring to light mode iterates all
 * patched elements and reinstates the saved originals, so text/bg colors
 * return to their correct values without a page reload.
 */
(function () {
  'use strict';
  const LS_KEY   = 'fluxdrop_theme';
  const ROOT_EL  = document.documentElement;

  // Patterns applied to inline style strings in dark mode
  const DARK_MAPS = [
    // backgrounds — surface variants
    { re: /(background(?:-color)?)\s*:\s*(#fff\b|#ffffff\b|white\b)/gi,  rep: '$1:#1a2535' },
    { re: /(background(?:-color)?)\s*:\s*(#f8fafc\b)/gi,                 rep: '$1:#131f2e' },
    { re: /(background(?:-color)?)\s*:\s*(#f1f5f9\b)/gi,                 rep: '$1:#1e2d3d' },
    { re: /(background(?:-color)?)\s*:\s*(#f0f9ff\b)/gi,                 rep: '$1:#0d1520' },
    { re: /(background(?:-color)?)\s*:\s*(#f9fafb\b|#f4f4f5\b)/gi,       rep: '$1:#1e2d3d' },
    { re: /(background(?:-color)?)\s*:\s*(#eff6ff\b)/gi,                 rep: '$1:#1a3050' },
    { re: /(background(?:-color)?)\s*:\s*(#dbeafe\b)/gi,                 rep: '$1:#1e3a5f' },
    { re: /(background(?:-color)?)\s*:\s*(#e2e8f0\b)/gi,                 rep: '$1:#2d3f52' },
    // borders
    { re: /(border(?:-[a-z]+)?-color)\s*:\s*(#e2e8f0\b)/gi,              rep: '$1:#2d3f52' },
    { re: /(border(?:-[a-z]+)?-color)\s*:\s*(#f1f5f9\b)/gi,              rep: '$1:#2d3f52' },
    { re: /(border(?:-[a-z]+)?-color)\s*:\s*(#bfdbfe\b)/gi,              rep: '$1:#2563eb' },
    // height:1px dividers rendered as background
    { re: /(background)\s*:\s*(#f1f5f9\b)/gi,                            rep: '$1:#2d3f52' },
    // text colors
    { re: /\bcolor\s*:\s*(#1e293b\b)/gi,                                  rep: 'color:#e2e8f0' },
    { re: /\bcolor\s*:\s*(#374151\b)/gi,                                  rep: 'color:#cbd5e1' },
    { re: /\bcolor\s*:\s*(#4b5563\b)/gi,                                  rep: 'color:#94a3b8' },
    { re: /\bcolor\s*:\s*(#475569\b)/gi,                                  rep: 'color:#94a3b8' },
    { re: /\bcolor\s*:\s*(#64748b\b)/gi,                                  rep: 'color:#94a3b8' },
    { re: /\bcolor\s*:\s*(#1e40af\b)/gi,                                  rep: 'color:#60a5fa' },
    { re: /\bcolor\s*:\s*(#1d4ed8\b)/gi,                                  rep: 'color:#60a5fa' },
  ];

  function _isDark(mode) {
    if (mode === 'dark')  return true;
    if (mode === 'light') return false;
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function _applyTheme(mode) {
    const dark = _isDark(mode);
    ROOT_EL.setAttribute('data-theme', dark ? 'dark' : 'light');
    document.querySelectorAll('.fd-theme-toggle-btn').forEach(btn => {
      btn.textContent = dark ? '☀ Light' : '🌙 Dark';
    });
  }

  /** Patch an element's inline style for dark mode; save original first. */
  function _patchEl(el) {
    if (el.nodeType !== 1) return;
    const style = el.getAttribute('style');
    if (!style) return;
    // Save original before first patch
    if (!el.hasAttribute('data-fd-orig-style')) {
      el.setAttribute('data-fd-orig-style', style);
    }
    let patched = style;
    DARK_MAPS.forEach(({ re, rep }) => { patched = patched.replace(re, rep); });
    if (patched !== style) {
      el.setAttribute('style', patched);
      el.dataset.fdDarkPatched = '1';
    }
  }

  /** Restore an element's inline style to its saved original. */
  function _restoreEl(el) {
    const orig = el.getAttribute('data-fd-orig-style');
    if (orig !== null) {
      el.setAttribute('style', orig);
    } else {
      // No original saved — element may not have had a style to begin with
    }
    delete el.dataset.fdDarkPatched;
  }

  /** Patch all styled descendants of root. */
  function _patchTree(root) {
    if (root.nodeType === 1) _patchEl(root);
    root.querySelectorAll && root.querySelectorAll('[style]').forEach(_patchEl);
  }

  /** Restore all previously patched elements to light-mode originals. */
  function _restoreAll() {
    document.querySelectorAll('[data-fd-dark-patched]').forEach(_restoreEl);
  }

  // MutationObserver: patch new nodes when dark mode is active
  const _mo = new MutationObserver(muts => {
    if (ROOT_EL.getAttribute('data-theme') !== 'dark') return;
    muts.forEach(m => m.addedNodes.forEach(n => {
      if (n.nodeType === 1) {
        _patchEl(n);
        n.querySelectorAll && n.querySelectorAll('[style]').forEach(_patchEl);
      }
    }));
  });
  _mo.observe(document.documentElement, { childList: true, subtree: true });

  window.FDtheme = {
    get current() { return ROOT_EL.getAttribute('data-theme') || 'light'; },
    get mode()    { return localStorage.getItem(LS_KEY) || 'auto'; },

    toggle: function () {
      const newMode = FDtheme.current === 'dark' ? 'light' : 'dark';
      FDtheme.setMode(newMode);
    },

    setMode: function (mode) {
      localStorage.setItem(LS_KEY, mode);
      _applyTheme(mode);
      if (_isDark(mode)) {
        _patchTree(document.body);
      } else {
        // Restore all patched inline styles so light mode is fully clean
        _restoreAll();
      }
      // Update any open settings checkboxes
      document.querySelectorAll('#fd-dark-chk').forEach(chk => {
        chk.checked = (FDtheme.current === 'dark');
      });
    },
  };

  // Apply on load
  const _savedMode = localStorage.getItem(LS_KEY) || 'auto';
  _applyTheme(_savedMode);
  if (_isDark(_savedMode)) {
    setTimeout(() => _patchTree(document.body), 0);
  }

  // Watch OS preference when mode = 'auto'
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if ((localStorage.getItem(LS_KEY) || 'auto') === 'auto') {
      _applyTheme('auto');
      if (_isDark('auto')) _patchTree(document.body); else _restoreAll();
    }
  });
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. NETWORK DEBUG CONSOLE
 * ═══════════════════════════════════════════════════════════════════════════
 * z-index is set to CSS max integer (2147483647) so it is ALWAYS on top.
 * Do not lower this value — the console must remain visible over every modal.
 */
(function () {
  'use strict';
  const LS_KEY   = 'fluxdrop_debug_bar';
  const MAX_HIST = 40;
  /* NOTE: z-index 2147483647 is the maximum allowed by CSS spec.
   * It is intentionally set to this value so the debug bar renders above
   * every possible overlay.  Do NOT lower it. */
  const Z_DEBUG  = 2147483647;
  let _history   = [];
  let _bar       = null;
  let _enabled   = localStorage.getItem(LS_KEY) === '1';

  function _ensureBar() {
    if (_bar && _bar.isConnected) return _bar;
    const bar = document.createElement('div');
    bar.id = 'fd-debug-bar';
    // Inline the critical z-index so it can never be overridden by a stylesheet
    bar.style.cssText =
      'position:fixed;bottom:30px;left:0;right:0;height:22px;line-height:22px;' +
      'background:rgba(15,23,42,0.95);color:#94a3b8;font-size:11px;' +
      'font-family:ui-monospace,monospace;padding:0 10px;' +
      /* z-index: CSS max — see Z_DEBUG comment above */
      'z-index:2147483647;display:flex;align-items:center;gap:8px;' +
      'overflow:hidden;white-space:nowrap;' +
      'border-top:1px solid #1e293b;pointer-events:none';
    bar.innerHTML =
      `<span style="color:#475569;flex-shrink:0;pointer-events:none">${t('debug_bar_label')}</span>` +
      `<span id="fd-db-text" style="flex:1;overflow:hidden;text-overflow:ellipsis">${t('debug_bar_idle')}</span>` +
      `<span id="fd-db-clear" style="pointer-events:auto;cursor:pointer;color:#475569;flex-shrink:0;padding:0 4px" title="${t('debug_clear')}">✕</span>`;
    bar.querySelector('#fd-db-clear').addEventListener('click', () => {
      bar.style.pointerEvents = 'none';
      _history = [];
      _render();
    });
    document.body.appendChild(bar);
    _bar = bar;
    return bar;
  }

  function _render() {
    if (!_bar || !_bar.isConnected) return;
    const txt = _bar.querySelector('#fd-db-text');
    if (!txt) return;
    if (!_history.length) {
      txt.textContent = t('debug_bar_idle');
      txt.style.color = '#64748b';
      return;
    }
    const last  = _history[_history.length - 1];
    const color = last.err ? '#ef4444' : last.status >= 400 ? '#f59e0b' : '#22c55e';
    const stat  = last.err ? '(err)' : last.status ? String(last.status) : '…';
    const el    = last.elapsed != null ? ` | ${last.elapsed}ms` : '';
    txt.textContent = `→ ${last.method} ${last.url}${el}${last.status ? ' | '+stat : ''}`;
    txt.style.color = color;
  }

  function _record(entry) {
    _history.push(entry);
    if (_history.length > MAX_HIST) _history.shift();
    if (_enabled) _render();
  }

  function _patchFetch() {
    if (typeof fetchWithFallback !== 'function') return;
    const _orig = fetchWithFallback;
    window.fetchWithFallback = async function (url, options) {
      const method = (options && options.method) || 'GET';
      let displayUrl = url;
      try { displayUrl = new URL(url).pathname + (new URL(url).search || ''); } catch (_) {}
      const t0 = performance.now();
      if (_enabled) _record({ method, url: displayUrl, status: null, elapsed: null, err: false });
      try {
        const resp    = await _orig(url, options);
        const elapsed = Math.round(performance.now() - t0);
        _record({ method, url: displayUrl, status: resp.status, elapsed, err: false });
        return resp;
      } catch (err) {
        _record({ method, url: displayUrl, status: 0, elapsed: Math.round(performance.now()-t0), err: true });
        throw err;
      }
    };
  }

  window.FDdebug = {
    get enabled() { return _enabled; },
    get history()  { return _history.slice(); },
    enable:  function () { _enabled=true; localStorage.setItem(LS_KEY,'1'); _ensureBar(); _render(); },
    disable: function () { _enabled=false; localStorage.setItem(LS_KEY,'0'); _bar && _bar.remove(); _bar=null; },
    toggle:  function () { FDdebug.enabled ? FDdebug.disable() : FDdebug.enable(); },
  };

  document.addEventListener('DOMContentLoaded', () => {
    _patchFetch();
    if (_enabled) { _ensureBar(); _render(); }
  });
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. SPACE ANALYZER  — file-manager drill-down navigation
 * ═══════════════════════════════════════════════════════════════════════════
 * Each folder click loads GET /api/v1/space_analyze?path=<sub> so the user
 * sees exactly one level at a time (like a file manager).
 * Breadcrumb at the top lets users navigate back.
 */
(function () {
  'use strict';

  function _fmt(b) {
    if (!b) return '0 B';
    if (b >= 1073741824) return (b/1073741824).toFixed(2)+' GB';
    if (b >= 1048576)    return (b/1048576).toFixed(1)   +' MB';
    if (b >= 1024)       return (b/1024).toFixed(0)      +' KB';
    return b+' B';
  }
  const PALETTE = ['#3b82f6','#6366f1','#8b5cf6','#ec4899','#f59e0b',
                   '#10b981','#06b6d4','#84cc16','#f97316','#ef4444'];

  window.openSpaceAnalyzer = async function () {
    document.getElementById('fd-sa-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id    = 'fd-sa-overlay';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-content" style="max-width:720px;width:96vw;padding:0;
           overflow:hidden;border-radius:14px" data-fd-dark="surface">
        <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);
             padding:14px 18px;display:flex;align-items:center;gap:12px" data-fd-dark="header">
          <div style="flex:1">
            <div style="color:white;font-weight:700;font-size:15px">
              📊 ${t('space_analyzer_title')}
            </div>
            <div id="fd-sa-breadcrumb" style="color:rgba(255,255,255,.75);font-size:12px;
                 margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
              /
            </div>
          </div>
          <button id="fd-sa-up" title="Go up" style="background:rgba(255,255,255,.2);
              border:none;color:white;border-radius:8px;padding:5px 10px;cursor:pointer;
              font-size:13px;display:none">↑ Up</button>
          <button id="fd-sa-close" style="background:rgba(255,255,255,.2);border:none;
              color:white;border-radius:50%;width:30px;height:30px;font-size:16px;
              cursor:pointer;display:flex;align-items:center;justify-content:center">✕</button>
        </div>
        <div id="fd-sa-body" style="padding:10px 16px;max-height:72vh;overflow-y:auto">
          <div style="text-align:center;padding:2rem;color:#94a3b8">
            <div style="font-size:2rem;margin-bottom:.5rem">📂</div>
            <div id="fd-sa-spinner">${t('space_analyzer_loading')}</div>
          </div>
        </div>
      </div>`;

    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target===overlay) overlay.remove(); });
    overlay.querySelector('#fd-sa-close').addEventListener('click', () => overlay.remove());

    let _path    = '/';
    let _history = [];

    const $body = overlay.querySelector('#fd-sa-body');
    const $bc   = overlay.querySelector('#fd-sa-breadcrumb');
    const $up   = overlay.querySelector('#fd-sa-up');

    $up.addEventListener('click', () => {
      if (_history.length) {
        _path = _history.pop();
        _load(_path);
      }
    });

    async function _load(path) {
      $body.innerHTML = `<div style="text-align:center;padding:2rem;color:#94a3b8">
        <div style="font-size:2rem;margin-bottom:.5rem">📂</div>${t('space_analyzer_loading')}</div>`;
      $bc.textContent = path || '/';
      $up.style.display = _history.length ? 'block' : 'none';

      try {
        const token = localStorage.getItem('fluxdrop_token') || '';
        const r = await fetch(
          '/api/v1/space_analyze?path=' + encodeURIComponent(path) + '&limit=200',
          { headers: { Authorization: 'Bearer ' + token } }
        );
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const data = await r.json();
        _render(data, path);
      } catch (err) {
        $body.innerHTML = `<p style="color:#ef4444;padding:2rem;text-align:center">
          Failed: ${err.message}</p>`;
      }
    }

    function _render(data, curPath) {
      const items = (data.items || []).slice().sort((a,b) => b.size_bytes - a.size_bytes);
      if (!items.length) {
        $body.innerHTML = `<div style="text-align:center;padding:2rem;color:#94a3b8">
          ${t('space_analyzer_empty')}</div>`;
        return;
      }
      const maxSz = items[0].size_bytes || 1;
      const total = data.total_bytes || 1;

      const header = `<div style="display:flex;justify-content:space-between;
          padding:4px 0 8px;border-bottom:2px solid var(--fd-border,#e2e8f0);
          margin-bottom:6px;font-size:11px;color:var(--fd-muted,#64748b)">
        <span>${items.length} item${items.length!==1?'s':''}</span>
        <span style="font-weight:600;color:var(--fd-text,#1e293b)">${_fmt(data.total_bytes)}</span>
      </div>`;

      const rows = items.map((item, i) => {
        const pct  = (item.size_bytes/maxSz*100).toFixed(1);
        const pctT = (item.size_bytes/total*100).toFixed(1);
        const icon = item.is_dir ? '📁' : '📄';
        const clr  = PALETTE[i % PALETTE.length];
        const drillCursor = item.is_dir ? 'cursor:pointer;' : '';
        return `<div class="fd-sa-bar-wrap" data-fdsa-path="${item.path}"
            data-fdsa-isdir="${item.is_dir?'1':'0'}"
            style="${drillCursor}border-radius:6px;padding:4px 0"
            title="${pctT}% of total · ${_fmt(item.size_bytes)}${item.is_dir?' — click to open':''}">
          <span style="font-size:14px;flex-shrink:0">${icon}</span>
          <span class="fd-sa-name" title="${item.path}">${item.name}</span>
          <div class="fd-sa-bar-track">
            <div class="fd-sa-bar-fill" style="width:${pct}%;background:${clr}"></div>
          </div>
          <span class="fd-sa-size">${_fmt(item.size_bytes)}</span>
          <span class="fd-sa-type" style="color:${clr}">${pctT}%</span>
        </div>`;
      }).join('');

      $body.innerHTML = header + rows;

      // Folder click → drill down
      $body.querySelectorAll('[data-fdsa-isdir="1"]').forEach(row => {
        row.addEventListener('click', () => {
          const subPath = row.dataset.fdsaPath;
          _history.push(curPath);
          _path = subPath;
          $up.style.display = 'block';
          _load(subPath);
        });
        row.addEventListener('mouseenter', () => { row.style.background='var(--fd-surface3,#f1f5f9)'; });
        row.addEventListener('mouseleave', () => { row.style.background=''; });
      });
    }

    _load(_path);
  };
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. UPLOAD: folder drag-drop detection + 409 conflict error display
 * ═══════════════════════════════════════════════════════════════════════════
 * A. When the user drops a folder onto the upload area in file mode,
 *    the browser creates an empty File (size=0). We detect this via
 *    DataTransferItem.webkitGetAsEntry() and auto-switch to folder mode.
 *
 * B. The server now returns HTTP 409 for name conflicts.  We intercept the
 *    409 response in the upload init flow and display a clear error.
 *    (The existing upload code already shows the error string from the
 *     server JSON body — so this fix is mostly about the drag-drop half.)
 */
(function () {
  'use strict';

  // ── A: Drag-drop folder detection ──────────────────────────────────────
  document.addEventListener('dragover', e => {
    e.preventDefault();  // required or drop won't fire
  }, false);

  document.addEventListener('drop', function _fdFolderDrop(e) {
    if (!e.dataTransfer || !e.dataTransfer.items) return;
    const fileInput = document.getElementById('upload-file');
    const folderBtn = document.getElementById('btn-folder-toggle');
    if (!fileInput || !folderBtn) return;

    const entries = Array.from(e.dataTransfer.items)
      .filter(it => it.kind === 'file')
      .map(it => it.webkitGetAsEntry && it.webkitGetAsEntry())
      .filter(Boolean);

    const hasDir = entries.some(ent => ent.isDirectory);
    if (!hasDir) return;

    const isAlreadyFolder = fileInput.hasAttribute('webkitdirectory');
    if (isAlreadyFolder) return;  // already in folder mode — nothing to do

    // Auto-switch to folder mode
    fileInput.setAttribute('webkitdirectory', '');
    fileInput.setAttribute('mozdirectory',    '');
    fileInput.removeAttribute('multiple');
    folderBtn.textContent         = '📄 Files';
    folderBtn.style.background    = '#6366f1';
    folderBtn.title               = (t('auto_mode_folder')) + ' — click to switch back';
    folderBtn.style.boxShadow     = '0 0 0 3px #818cf8';
    setTimeout(() => { folderBtn.style.boxShadow = ''; }, 1400);
  }, false);

  // ── B: Wrap renderFileBrowserView to patch the change listener ──────────
  const _origRender = window.renderFileBrowserView;
  if (typeof _origRender === 'function') {
    window.renderFileBrowserView = function () {
      _origRender.apply(this, arguments);
      const fileInput = document.getElementById('upload-file');
      const folderBtn = document.getElementById('btn-folder-toggle');
      if (!fileInput || !folderBtn) return;

      fileInput.addEventListener('change', function _fdAutoNeg() {
        const files    = Array.from(fileInput.files || []);
        if (!files.length) return;
        const hasPaths = files.some(f => f.webkitRelativePath && f.webkitRelativePath.includes('/'));
        const isFolderMode = fileInput.hasAttribute('webkitdirectory');

        // Detect: dropped files have sub-paths but input is in file mode
        if (hasPaths && !isFolderMode) {
          fileInput.setAttribute('webkitdirectory', '');
          fileInput.setAttribute('mozdirectory',    '');
          fileInput.removeAttribute('multiple');
          folderBtn.textContent      = '📄 Files';
          folderBtn.style.background = '#6366f1';
          folderBtn.style.boxShadow  = '0 0 0 3px #818cf8';
          setTimeout(() => { folderBtn.style.boxShadow = ''; }, 1400);
        }

        // Warn: file with size 0 and no extension is probably a directory
        const pseudoFolders = files.filter(f =>
          f.size === 0 && !f.webkitRelativePath && !f.name.includes('.')
        );
        if (pseudoFolders.length && !isFolderMode) {
          const names = pseudoFolders.map(f => `"${f.name}"`).join(', ');
          const msg   = `${names} appear${pseudoFolders.length===1?'s':''} to be a folder.\n` +
                        `Switch to Folder mode (📁 Folder button) and select it again.`;
          // Use FluxDrop's own modal if available, otherwise alert
          if (typeof showModal === 'function') {
            showModal('Upload hint', msg);
          } else {
            alert(msg);
          }
          fileInput.value = '';
        }
      }, false);
    };
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. TRASH FOLDER BROWSE
 * ═══════════════════════════════════════════════════════════════════════════
 * Intercepts .trash-browse-btn clicks (capturing phase) and renders an
 * inline file-tree from GET /api/v1/trash/<id>/list.
 */
(function () {
  'use strict';

  document.addEventListener('click', async function _fdTrashBrowse(e) {
    const btn = e.target.closest('.trash-browse-btn');
    if (!btn) return;
    const row = btn.closest('.trash-row');
    if (!row) return;

    const existing = row.nextElementSibling;
    if (existing && existing.classList.contains('trash-tree-panel')) {
      existing.remove(); btn.textContent = t('browse'); return;
    }

    const id    = +btn.dataset.id;
    btn.textContent = t('loading');
    btn.disabled    = true;

    const panel = document.createElement('div');
    panel.className  = 'trash-tree-panel';
    panel.style.cssText =
      'background:var(--fd-surface2,#f8fafc);' +
      'border-bottom:1px solid var(--fd-border,#e2e8f0);' +
      'padding:10px 20px 10px 44px;font-size:12px;color:var(--fd-muted,#475569);' +
      'max-height:300px;overflow-y:auto';

    const token = localStorage.getItem('fluxdrop_token') || '';
    try {
      const r = await fetch(`/api/v1/trash/${id}/list`, {
        headers: { Authorization: 'Bearer ' + token }
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data  = await r.json();
      const items = data.items || [];
      panel.innerHTML = items.length ? _treeHtml(items) :
        '<em style="color:#94a3b8">📂 Folder is empty.</em>';
    } catch (err) {
      panel.innerHTML = err.message.includes('404')
        ? `<em style="color:#94a3b8">Folder listing requires the server patch for
           <code>/api/v1/trash/&lt;id&gt;/list</code>.</em>`
        : `<span style="color:#ef4444">Failed: ${err.message}</span>`;
    }

    row.insertAdjacentElement('afterend', panel);
    btn.textContent = 'Close';
    btn.disabled    = false;
  }, true);

  function _treeHtml(items) {
    const sorted = [...items].sort((a,b) =>
      a.is_dir !== b.is_dir ? (a.is_dir ? -1 : 1) : a.name.localeCompare(b.name)
    );
    return sorted.map(item => {
      const icon = item.is_dir ? '📁' : '📄';
      const sz   = item.is_dir ? '' :
        `<span style="margin-left:auto;color:#94a3b8;font-size:11px">${_fmt(item.size_bytes)}</span>`;
      return `<div style="display:flex;align-items:center;gap:5px;padding:2px 0;
          padding-left:${(item.depth||1)*12}px">
        <span>${icon}</span>
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1"
              title="${item.path||item.name}">${item.name}</span>${sz}
      </div>`;
    }).join('');
  }
  function _fmt(b) {
    if (!b) return '0 B';
    if (b>=1073741824) return (b/1073741824).toFixed(2)+' GB';
    if (b>=1048576)    return (b/1048576).toFixed(1)   +' MB';
    if (b>=1024)       return (b/1024).toFixed(0)      +' KB';
    return b+' B';
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 7. TRASH PREVIEW 206 FIX — video/audio native streaming
 * ═══════════════════════════════════════════════════════════════════════════
 * Intercepts .trash-preview-btn clicks for video/audio (capturing phase).
 * Uses direct stream URL + ?token= so browser sends Range requests natively.
 */
(function () {
  'use strict';
  const VID = new Set(['mp4','webm','mkv','mov','avi','m4v','ogv']);
  const AUD = new Set(['mp3','flac','wav','m4a','ogg','opus','aac']);
  const _ext = name => (name.split('.').pop()||'').toLowerCase();

  document.addEventListener('click', async function _fdTrashPreview206(e) {
    const btn = e.target.closest('.trash-preview-btn');
    if (!btn) return;
    const filename = btn.dataset.name || '';
    const ext      = _ext(filename);
    if (!VID.has(ext) && !AUD.has(ext)) return;
    e.stopPropagation();   // prevent original _previewTrashFile from firing

    const id    = +btn.dataset.id;
    const token = localStorage.getItem('fluxdrop_token') || '';
    const url   = `/api/v1/trash/${id}/file` + (token ? `?token=${encodeURIComponent(token)}` : '');

    const modal   = document.getElementById('preview-modal');
    const titleEl = document.getElementById('preview-title');
    const bodyEl  = document.getElementById('preview-body');
    const dlBtn   = document.getElementById('preview-download-btn');
    if (!modal || !bodyEl) return;

    titleEl.textContent = filename;
    dlBtn.style.display = 'none';
    modal.classList.remove('hidden');

    bodyEl.innerHTML = VID.has(ext)
      ? `<video controls autoplay
           style="max-width:100%;max-height:70vh;border-radius:8px;display:block;margin:0 auto;background:#000">
           <source src="${url}">
         </video>`
      : `<div style="padding:2rem 1rem;text-align:center">
           <div style="font-size:4rem;margin-bottom:1rem">🎵</div>
           <div style="color:#94a3b8;margin-bottom:1.5rem;font-size:15px">${filename}</div>
           <audio controls autoplay style="width:100%"><source src="${url}"></audio>
         </div>`;
  }, true);
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 8. LOADING SPINNERS
 * ═══════════════════════════════════════════════════════════════════════════
 */
(function () {
  'use strict';
  function _spinnerHtml(label) {
    return `<span style="display:inline-flex;align-items:center;gap:8px;color:#94a3b8">
      <span style="display:inline-block;width:16px;height:16px;border-radius:50%;
            border:2px solid #334155;border-top-color:#3b82f6;
            animation:fd-spin .7s linear infinite;flex-shrink:0"></span>
      ${label}
    </span>`;
  }
  function _upgrade(root) {
    root.querySelectorAll('*').forEach(el => {
      if (el.childElementCount===0 && el.textContent.trim()==='Loading…' && !el.dataset.fdSpinDone) {
        el.dataset.fdSpinDone = '1';
        el.innerHTML = _spinnerHtml('Loading…');
      }
    });
  }
  const _obs = new MutationObserver(muts => {
    muts.forEach(m => m.addedNodes.forEach(n => {
      if (n.nodeType!==1) return;
      ['pp-quota-card','trash-body'].forEach(id => {
        const el = n.id===id ? n : n.querySelector?.('#'+id);
        if (el) _upgrade(el);
      });
      if (n.id && n.id.endsWith('-body')) _upgrade(n);
    }));
  });
  document.addEventListener('DOMContentLoaded', () => {
    _obs.observe(document.body, { childList: true, subtree: true });
  });
})();

/* ═══════════════════════════════════════════════════════════════════════════
 * 9. SETTINGS PANEL EXTENSIONS
 * ═══════════════════════════════════════════════════════════════════════════
 * Injects dark-mode toggle, language selector, debug toggle, and space
 * analyzer button into the profile panel when it opens.
 */
(function () {
  'use strict';

  function _build() {
    const isDark  = FDtheme.current === 'dark';
    const debugOn = FDdebug.enabled;
    const curLang = FDi18n.lang;
    const opts    = FDi18n.langs.map(c =>
      `<option value="${c}"${c===curLang?' selected':''}>${FDi18n.label(c)}</option>`
    ).join('');

    const el = document.createElement('div');
    el.id    = 'fd-settings-block';
    el.innerHTML = `
      <hr style="border:none;border-top:1px solid var(--fd-border,#e2e8f0);margin:0">
      <div style="font-size:12px;font-weight:700;color:var(--fd-muted,#64748b);
           text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">
        ${t('profile_info_appearance')}
      </div>
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="fd-dark-chk" ${isDark?'checked':''} style="width:16px;height:16px">
        <span style="font-size:13px;font-weight:600">🌙 ${t('dark_mode')}</span>
      </label>
      <label style="display:block;font-size:13px;font-weight:600;margin-bottom:10px">
        🌍 ${t('language')}
        <select id="fd-lang-sel" style="display:block;width:100%;margin-top:4px;
            padding:7px 10px;border:1px solid var(--fd-border,#e2e8f0);border-radius:8px;
            font-size:14px;font-family:Inter,sans-serif;
            background:var(--fd-input-bg,#fff);color:var(--fd-text,#1e293b)">
          ${opts}
        </select>
      </label>
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;margin-bottom:10px">
        <input type="checkbox" id="fd-debug-chk" ${debugOn?'checked':''} style="width:16px;height:16px">
        <span style="font-size:13px;font-weight:600">🔌 ${t('debug_console')}</span>
      </label>
      <button id="fd-sa-btn" style="width:100%;padding:8px 14px;border-radius:8px;
          border:1px solid #3b82f6;background:none;color:#3b82f6;font-size:13px;
          font-weight:600;cursor:pointer;font-family:inherit;transition:background .15s">
        📊 ${t('analyze_space')}
      </button>`;
    return el;
  }

  function _attach(block, overlay) {
    block.querySelector('#fd-dark-chk').addEventListener('change', function() {
      FDtheme.setMode(this.checked ? 'dark' : 'light');
    });
    block.querySelector('#fd-lang-sel').addEventListener('change', async function() {
      await FDi18n.setLang(this.value);
      const fresh = _build();
      block.replaceWith(fresh);
      _attach(fresh, overlay);
    });
    block.querySelector('#fd-debug-chk').addEventListener('change', function() {
      this.checked ? FDdebug.enable() : FDdebug.disable();
    });
    block.querySelector('#fd-sa-btn').addEventListener('click', () => {
      overlay.remove(); openSpaceAnalyzer();
    });
  }

  function _inject(overlay) {
    if (overlay.querySelector('#fd-settings-block')) return;
    const grid = overlay.querySelector('[style*="display:grid"]');
    if (!grid) return;
    const block = _build();
    _attach(block, overlay);
    grid.appendChild(block);
  }

  const _obs = new MutationObserver(muts => {
    muts.forEach(m => m.addedNodes.forEach(n => {
      if (n.nodeType===1 && n.id==='profile-panel-overlay')
        setTimeout(() => _inject(n), 80);
    }));
  });
  document.addEventListener('DOMContentLoaded', () => {
    _obs.observe(document.body, { childList: true });
  });
})();
