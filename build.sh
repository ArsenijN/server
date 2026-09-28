#!/bin/bash
# build.sh — build Tailwind CSS, locale bundle, and sync files for FluxDrop
# Run from the repo root (same directory as sync_to_server.sh)
#
# Steps (in order):
#   1. Check locale files for consistency (fails hard on key mismatches / bad syntax)
#   2. Regenerate fd_locale_bundle.js from locale/*.json
#   3. Sync all source files from server/build/src → server/TestWeb (rsync)
#   4. Build / watch Tailwind CSS
#   5. Stamp @@CACHE_VER@@ in sw.js and script.js
#   6. Minify JS/CSS in TestWeb (esbuild, with source maps) — src stays readable
#   7. Pre-compress text assets (.gz, plus .br if a brotli tool is installed)
#      so the web server can send them compressed without per-request CPU

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SRC="./server/build/src/fluxdrop_pp"
OUT="./server/TestWeb/fluxdrop_pp"
CSS_INPUT="$SRC/input.css"
CSS_OUTPUT="$OUT/tailwindcss.css"

# Build tools — kept in server/build/ next to the source they operate on
BUILD_DIR="$SCRIPT_DIR/server/build"
LOCALE_DIR="$SRC/locale"
LOCALE_BUNDLE_OUT="$SRC/fd_locale_bundle.js"
CHECK_LOCALES="$BUILD_DIR/check_locales.py"
BUILD_BUNDLE="$BUILD_DIR/build_locale_bundle.py"

# Parse flags
WATCH=false
SKIP_LOCALE=false
MINIFY=true
for arg in "$@"; do
    case $arg in
        --watch|-w)        WATCH=true ;;
        --skip-locale)     SKIP_LOCALE=true ;;  # escape hatch for CI that manages locales separately
        --no-minify)       MINIFY=false ;;      # keep TestWeb JS/CSS readable (debugging)
        --help|-h)
            echo "Usage: ./build.sh [options]"
            echo "  (no flags)       Check locales, build bundle + CSS, sync src→TestWeb"
            echo "  --watch,-w       Sync once, then watch CSS for changes"
            echo "  --skip-locale    Skip locale check/rebuild (useful if already up to date)"
            echo "  --no-minify      Don't minify JS/CSS in TestWeb (still pre-compresses)"
            exit 0
            ;;
    esac
done

# ── Locale check ──────────────────────────────────────────────────────────────
# Validates that en.json and uk.json have identical key sets and no broken
# ${...} placeholder syntax.  Exits non-zero (and aborts the build) on hard errors.
check_locales() {
    if ! command -v python3 &>/dev/null; then
        echo "⚠  python3 not found — skipping locale check"
        return 0
    fi
    echo "🌍 Checking locale files..."
    if python3 "$CHECK_LOCALES" "$LOCALE_DIR"; then
        echo "✅ Locale check passed"
    else
        echo "❌ Locale check failed — fix errors in locale/*.json before building."
        exit 1
    fi
}

# ── Locale bundle generation ──────────────────────────────────────────────────
# Reads locale/*.json and writes fd_locale_bundle.js so that t() initialises
# synchronously (no async fetch race condition on first paint).
# Must run BEFORE sync_files so the generated bundle is rsync'd to TestWeb.
build_locale_bundle() {
    if ! command -v python3 &>/dev/null; then
        echo "⚠  python3 not found — skipping locale bundle generation"
        return 0
    fi
    echo "📦 Building locale bundle..."
    python3 "$BUILD_BUNDLE" "$LOCALE_DIR" "$LOCALE_BUNDLE_OUT"
}

# ── Cache version stamping ────────────────────────────────────────────────────
stamp_cache_version() {
    local HASH
    HASH=$(find "$SRC" -type f \( -name "*.js" -o -name "*.css" -o -name "*.html" \) \
           ! -name "input.css" \
           | sort | xargs cat 2>/dev/null | sha256sum | cut -c1-8)
    local VER="v-${HASH}"

    echo "🔖 Cache version: fluxdrop-${VER}"

    local SW="$OUT/sw.js"
    local JS="$OUT/script.js"

    if grep -q '@@CACHE_VER@@' "$SW" 2>/dev/null; then
        sed -i "s/@@CACHE_VER@@/${VER}/g" "$SW"
        echo "   ✓ stamped $SW"
    else
        echo "   ⚠ @@CACHE_VER@@ token not found in $SW — skipping stamp"
    fi

    if grep -q '@@CACHE_VER@@' "$JS" 2>/dev/null; then
        sed -i "s/@@CACHE_VER@@/${VER}/g" "$JS"
        echo "   ✓ stamped $JS"
    else
        echo "   ⚠ @@CACHE_VER@@ token not found in $JS — skipping stamp"
    fi
}

sync_files() {
    echo "📁 Syncing files $SRC → $OUT ..."
    rsync -av \
        --exclude="input.css" \
        "$SRC/" "$OUT/"
    echo "✅ Files synced"
}

build_css() {
    echo "🔨 Building Tailwind CSS..."
    npx @tailwindcss/cli -i "$CSS_INPUT" -o "$CSS_OUTPUT" --minify
    echo "✅ Tailwind CSS → $CSS_OUTPUT"
}

# ── Minify (TestWeb copies only) ──────────────────────────────────────────────
# Strips comments/whitespace and shortens local names. Top-level functions keep
# their names (esbuild doesn't rename them when not bundling), so inline
# onclick="showPolicyModal('tos')" handlers keep working. Each file gets a
# source map, so errors in devtools still point at the readable source.
# Runs after stamping so the stamped cache version is what gets minified.
minify_assets() {
    local ESB="$SCRIPT_DIR/node_modules/.bin/esbuild"
    if [ ! -x "$ESB" ]; then
        echo "⚠  esbuild not installed (npm install) — skipping minification"
        return 0
    fi
    echo "🗜  Minifying JS/CSS..."
    local TMPD
    TMPD=$(mktemp -d)
    local f
    for f in "$OUT/script.js" "$OUT/fd_addons.js" "$OUT/fd_locale_bundle.js" "$OUT/sw.js" \
             "$OUT/fd_dark.css" "$OUT/assets/Inter.css"; do
        [ -f "$f" ] || continue
        local base; base=$(basename "$f")
        if "$ESB" "$f" --minify --charset=utf8 --sourcemap --log-level=warning \
               --outfile="$TMPD/$base"; then
            mv -f "$TMPD/$base" "$f"
            mv -f "$TMPD/$base.map" "$f.map"
        else
            echo "   ⚠ minify failed for $f — keeping it unminified"
        fi
    done
    rm -rf "$TMPD"
    echo "✅ Minified"
}

# ── Pre-compress text assets ──────────────────────────────────────────────────
precompress_assets() {
    echo "📦 Pre-compressing text assets..."
    local HAS_BR=false
    command -v brotli &>/dev/null && HAS_BR=true
    # Drop stale compressed copies whose original is gone.
    find "$OUT" -type f \( -name "*.gz" -o -name "*.br" \) | while read -r c; do
        [ -f "${c%.*}" ] || rm -f "$c"
    done
    local n=0
    while IFS= read -r -d '' f; do
        gzip -9 -k -f -n "$f"
        $HAS_BR && brotli -f -q 11 -o "$f.br" "$f"
        n=$((n + 1))
    done < <(find "$OUT" -type f -size +511c \( -name "*.js" -o -name "*.css" -o -name "*.html" \
                -o -name "*.svg" -o -name "*.json" -o -name "*.md" -o -name "*.map" \) -print0)
    echo "✅ Pre-compressed $n files (gzip$($HAS_BR && echo ' + brotli'))"
}

# ── Main build sequence ───────────────────────────────────────────────────────
if ! $SKIP_LOCALE; then
    check_locales      # abort if locale files are broken
    build_locale_bundle  # regenerate fd_locale_bundle.js before rsync
fi

sync_files           # rsync src → TestWeb (includes the freshly generated bundle)

if $WATCH; then
    stamp_cache_version
    echo "👁  Watching for CSS changes (locale changes require a full rebuild)..."
    npx @tailwindcss/cli -i "$CSS_INPUT" -o "$CSS_OUTPUT" --watch
else
    build_css
    stamp_cache_version
    $MINIFY && minify_assets
    precompress_assets
fi
