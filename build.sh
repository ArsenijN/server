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
    echo "👁  Watching for CSS changes..."
    npx @tailwindcss/cli -i "$CSS_INPUT" -o "$CSS_OUTPUT" --watch
else
    build_css
fi
