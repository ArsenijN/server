#!/usr/bin/env python3
"""
check_locales.py — FluxDrop locale consistency checker
=======================================================
Run from the project root or any directory:

    python3 check_locales.py                  # uses ./locale/
    python3 check_locales.py path/to/locale/  # custom path

Exit codes:
    0  — all checks passed (warnings may still be printed)
    1  — hard errors: missing keys or broken placeholder syntax

What is checked:
    ❌ HARD  Keys present in en.json but missing from uk.json
    ❌ HARD  Keys present in uk.json but missing from en.json
    ❌ HARD  Placeholder syntax uses ${...} instead of {varname}
    ⚠  SOFT  Values identical between en and uk (possibly untranslated)
    ℹ  INFO  Version mismatch between locale files
"""
import json
import re
import sys
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
# Locale files to compare. Add more pairs here if you add languages.
LOCALE_PAIRS = [('en', 'uk')]
META_KEY = '_meta'

# Keys where identical en/uk values are expected and should not be flagged.
# Add any proper-noun or intentionally-untranslated key here.
SKIP_IDENTICAL_KEYS = {
    META_KEY,
    # Values containing these substrings are OK to be identical across locales
}
IDENTICAL_OK_SUBSTRINGS = {
    'fluxdrop', 'github', 'cdn', 'heic', 'ip beacon', 'hsts', '7-zip',
    'admin', 'ok', 'tos', 'id ', 'http', 'aria',
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load(path: Path) -> dict:
    with open(path, encoding='utf-8') as f:
        return json.load(f)

def _is_identical_ok(key: str, value: str) -> bool:
    """Return True if it's acceptable for en and uk to have the same value."""
    if key in SKIP_IDENTICAL_KEYS:
        return True
    if not isinstance(value, str):
        return True
    v = value.lower()
    if re.fullmatch(r'[\d\s%.:]+', v):
        return True  # pure numbers / punctuation
    if any(sub in v for sub in IDENTICAL_OK_SUBSTRINGS):
        return True
    return False

def _has_bad_placeholder(value: str) -> list[str]:
    """Return list of bad ${...} placeholder matches found in value."""
    return re.findall(r'\$\{[^}]+\}', value)

def _colour(code: str, text: str) -> str:
    """ANSI colour if stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    codes = {'red': '31', 'yellow': '33', 'green': '32', 'cyan': '36', 'bold': '1'}
    return f"\033[{codes.get(code,'0')}m{text}\033[0m"

# ── Main ──────────────────────────────────────────────────────────────────────

def check(locale_dir: Path) -> int:
    """Run all checks; return number of hard errors found."""
    hard_errors = 0
    soft_warnings = 0

    for lang_a, lang_b in LOCALE_PAIRS:
        path_a = locale_dir / f'{lang_a}.json'
        path_b = locale_dir / f'{lang_b}.json'

        for p in (path_a, path_b):
            if not p.exists():
                print(_colour('red', f'❌  File not found: {p}'))
                hard_errors += 1

        if hard_errors:
            continue

        data_a = _load(path_a)
        data_b = _load(path_b)

        keys_a = {k for k in data_a if k != META_KEY}
        keys_b = {k for k in data_b if k != META_KEY}

        # ── Version info ──────────────────────────────────────────────────────
        ver_a = data_a.get(META_KEY, {}).get('version', '?')
        ver_b = data_b.get(META_KEY, {}).get('version', '?')
        if ver_a != ver_b:
            print(_colour('yellow',
                f'ℹ  Version mismatch: {lang_a}.json={ver_a}  {lang_b}.json={ver_b}'))
            soft_warnings += 1
        else:
            print(_colour('cyan', f'ℹ  Version: {ver_a}'))

        # ── Missing in B ──────────────────────────────────────────────────────
        missing_b = sorted(keys_a - keys_b)
        if missing_b:
            print(_colour('red',
                f'\n❌  Missing in {lang_b}.json ({len(missing_b)} key(s)):'))
            for k in missing_b:
                print(f'     {k!r:50s}  →  {data_a[k]!r}')
            hard_errors += len(missing_b)
        
        # ── Extra in B (not in A) ─────────────────────────────────────────────
        extra_b = sorted(keys_b - keys_a)
        if extra_b:
            print(_colour('yellow',
                f'\n⚠   Extra keys in {lang_b}.json (not in {lang_a}.json) '
                f'({len(extra_b)} key(s)):'))
            for k in extra_b:
                print(f'     {k!r}')
            soft_warnings += len(extra_b)

        # ── Broken placeholder syntax ─────────────────────────────────────────
        for fname, data in ((f'{lang_a}.json', data_a), (f'{lang_b}.json', data_b)):
            bad = []
            for k, v in data.items():
                if isinstance(v, str):
                    hits = _has_bad_placeholder(v)
                    if hits:
                        bad.append((k, v, hits))
            if bad:
                print(_colour('red',
                    f'\n❌  Wrong placeholder syntax in {fname} '
                    f'(use {{varname}} not ${{...}}) ({len(bad)} key(s)):'))
                for k, v, hits in bad:
                    print(f'     {k!r}')
                    print(f'       value : {v!r}')
                    print(f'       found : {hits}')
                    print(f'       fix   : replace each ${{...}} with a simple {{name}}')
                hard_errors += len(bad)

        # ── Possibly untranslated (identical values) ──────────────────────────
        shared = keys_a & keys_b
        untranslated = [
            k for k in shared
            if data_a[k] == data_b[k] and not _is_identical_ok(k, data_a[k])
        ]
        if untranslated:
            print(_colour('yellow',
                f'\n⚠   Possibly untranslated in {lang_b}.json '
                f'({len(untranslated)} key(s) identical to {lang_a}):'))
            for k in sorted(untranslated):
                print(f'     {k!r:50s}  =  {data_a[k]!r}')
            soft_warnings += len(untranslated)

        # ── Summary for this pair ─────────────────────────────────────────────
        total_keys = len(keys_a)
        print()
        if hard_errors == 0:
            print(_colour('green',
                f'✅  {lang_a}/{lang_b}: {total_keys} keys, '
                f'0 hard errors, {soft_warnings} warning(s)'))
        else:
            print(_colour('red',
                f'❌  {lang_a}/{lang_b}: {hard_errors} hard error(s), '
                f'{soft_warnings} warning(s)'))

    return hard_errors


def main():
    locale_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / 'locale'
    if not locale_dir.is_dir():
        print(_colour('red', f'❌  Locale directory not found: {locale_dir}'))
        sys.exit(1)

    print(f'Checking locale directory: {locale_dir.resolve()}\n')
    errors = check(locale_dir)
    sys.exit(1 if errors else 0)


if __name__ == '__main__':
    main()
