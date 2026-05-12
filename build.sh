#!/bin/bash
# build.sh — build Tailwind CSS and sync files for FluxDrop
# Run from the repo root (same directory as sync_to_server.sh)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SRC="./server/build/src/fluxdrop_pp"
OUT="./server/TestWeb/fluxdrop_pp"
CSS_INPUT="$SRC/input.css"
CSS_OUTPUT="$OUT/tailwindcss.css"

# Parse flags
WATCH=false
for arg in "$@"; do
    case $arg in
        --watch|-w) WATCH=true ;;
        --help|-h)
            echo "Usage: ./build.sh [--watch]"
            echo "  (no flags)  Build CSS, sync all files from src to output once"
            echo "  --watch,-w  Sync files once, then watch CSS for changes"
            exit 0
            ;;
    esac
done

# ── Cache version stamping ────────────────────────────────────────────────────
# Generates a short hash from the content of all JS/CSS/HTML source files so
# that the SW cache name changes automatically whenever anything is rebuilt.
# Both sw.js and script.js use the token @@CACHE_VER@@ which is replaced here.
stamp_cache_version() {
    # Hash the source tree (JS, CSS, HTML) — exclude input.css (Tailwind source)
    local HASH
    HASH=$(find "$SRC" -type f \( -name "*.js" -o -name "*.css" -o -name "*.html" \) \
           ! -name "input.css" \
           | sort | xargs cat 2>/dev/null | sha256sum | cut -c1-8)
    local VER="v-${HASH}"

    echo "🔖 Cache version: fluxdrop-${VER}"

    # Stamp the token in the OUTPUT copies (after rsync has placed them)
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
    # Copy everything except input.css (Tailwind source, not needed on server)
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

sync_files

if $WATCH; then
    # In watch mode: stamp once after the initial sync, then let Tailwind watch.
    # CSS changes don't need a cache bump (CSS is in PRECACHE_URLS and gets
    # revalidated in the background anyway).
    stamp_cache_version
    echo "👁  Watching for CSS changes..."
    npx @tailwindcss/cli -i "$CSS_INPUT" -o "$CSS_OUTPUT" --watch
else
    build_css
    # Stamp after CSS is built so the hash covers the final output CSS too.
    # Re-hash SRC (the source of truth); CSS output is in OUT and already written.
    stamp_cache_version
fi
