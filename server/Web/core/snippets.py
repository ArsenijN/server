import os, re, json, html, logging
from config import _SNIPPETS_DIR, SERVE_DIRECTORY, PUBLIC_BASE_URL

def _load_snippet(filename: str) -> str:
    """Load an HTML snippet from the snippets/ subfolder."""
    with open(os.path.join(_SNIPPETS_DIR, filename), encoding='utf-8') as f:
        return f.read()


# ── Translations for server-rendered pages ──────────────────────────────────
# Share pages work without JavaScript, so they're translated here, from the
# same locale files the app uses (TestWeb/fluxdrop_pp/locale/<lang>.json).
_WEB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOCALE_DIRS = [
    os.path.join(SERVE_DIRECTORY, 'fluxdrop_pp', 'locale'),
    os.path.join(os.path.dirname(_WEB_DIR), 'TestWeb', 'fluxdrop_pp', 'locale'),
    os.path.join(os.path.dirname(_WEB_DIR), 'build', 'src', 'fluxdrop_pp', 'locale'),
]
_locale_cache: dict = {}   # lang -> (path, mtime, dict)


def _locale_path(lang: str):
    """The newest copy of <lang>.json (a stale build next to a fresh source
    would otherwise hide new keys)."""
    found = [p for p in (os.path.join(d, f'{lang}.json') for d in _LOCALE_DIRS)
             if os.path.isfile(p)]
    return max(found, key=os.path.getmtime) if found else None


def load_locale(lang: str) -> dict:
    """The app's catalogue for lang ({} if missing); reloaded when the file changes."""
    p = _locale_path(lang)
    if not p:
        return {}
    try:
        mt = os.path.getmtime(p)
        hit = _locale_cache.get(lang)
        if hit and hit[0] == p and hit[1] == mt:
            return hit[2]
        with open(p, encoding='utf-8') as f:
            data = json.load(f)
        _locale_cache[lang] = (p, mt, data)
        return data
    except Exception:
        logging.exception('load_locale(%s) failed', lang)
        return {}


def pick_lang(handler) -> str:
    """?lang=… , then the fd_lang cookie (set by the app's language
    switch), then Accept-Language; 'en' when nothing matches."""
    from urllib.parse import urlparse, parse_qs

    def ok(code):
        code = (code or '').strip().lower()[:2]
        return code if code.isalpha() and _locale_path(code) else None

    q = parse_qs(urlparse(handler.path).query).get('lang', [None])[0]
    if ok(q):
        return ok(q)
    m = re.search(r'(?:^|;\s*)fd_lang=([A-Za-z-]+)', handler.headers.get('Cookie', '') or '')
    if m and ok(m.group(1)):
        return ok(m.group(1))
    for part in (handler.headers.get('Accept-Language', '') or '').split(','):
        if ok(part.split(';')[0]):
            return ok(part.split(';')[0])
    return 'en'


def tr(lang: str, key: str, **kw) -> str:
    """Translated text (plain, not escaped) with {var} filled in."""
    s = load_locale(lang).get(key) or load_locale('en').get(key) or key
    for k, v in kw.items():
        s = s.replace('{' + k + '}', str(v))
    return s


def _render_snippet(filename: str, lang: str = 'en', **kwargs) -> str:
    """Load a snippet and substitute {PLACEHOLDER} tokens safely.

    Unlike str.format(), this only replaces tokens whose names are explicitly
    passed as keyword arguments, so CSS rules like *{box-sizing:border-box}
    and JS template literals like ${previewUrl} are left completely untouched.

    Translations: {t:key} → HTML-escaped text, {tjs:key} → a JS string
    literal (for the page's scripts), {lang} → the language code,
    {PUBLIC_BASE_URL} → the public origin (absolute og:image URLs).
    """
    template = _load_snippet(filename)
    template = re.sub(r'\{t:([A-Za-z0-9_]+)\}',
                      lambda m: html.escape(tr(lang, m.group(1)), quote=True), template)
    template = re.sub(r'\{tjs:([A-Za-z0-9_]+)\}',
                      lambda m: json.dumps(tr(lang, m.group(1))).replace('<', '\\u003c'), template)
    template = template.replace('{lang}', lang)
    # Before the caller's values, so text inside them is never expanded
    template = template.replace('{PUBLIC_BASE_URL}', PUBLIC_BASE_URL)
    for key, value in kwargs.items():
        template = template.replace('{' + key + '}', str(value))
    return template
