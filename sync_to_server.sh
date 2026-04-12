#!/usr/bin/env bash
# sync_to_server.sh  – unidirectional mirror from local ./server tree to the
# remote host.  Configuration lives in deploy.env (gitignored); copy
# deploy.env.sample to deploy.env and fill in your values before running.
#
# Works on Linux, macOS, and Windows Git Bash (needs rsync in PATH, somewhere 
# in Wiki should be explained already HowTo).
# On Windows, run:  bash sync_to_server.sh
set -euo pipefail

# === load local config ===
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_ENV="$SCRIPT_DIR/deploy.env"

if [ ! -f "$DEPLOY_ENV" ]; then
    echo "ERROR: deploy.env not found."
    echo "Copy deploy.env.sample to deploy.env and fill in your values."
    exit 1
fi

# Source the file — simple KEY=VALUE pairs, no export needed
while IFS='=' read -r key val; do
    # skip comments and blank lines
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${key// }" ]] && continue
    # strip inline comments from value
    val="${val%%#*}"
    # trim whitespace
    key="${key//[[:space:]]/}"
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    # expand $HOME and ~ so paths work on all platforms
    val="${val/\$\{HOME\}/$HOME}"
    # do NOT expand ~ here — remote paths with ~ must expand on the server
    # only set if key is a valid identifier and not already in env
    if [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        export "$key=$val"
    fi
done < "$DEPLOY_ENV"

# === apply defaults for anything not set in deploy.env ===
REMOTE_USER="${REMOTE_USER:-arsen}"
REMOTE_HOST="${REMOTE_HOST:-arseniusgen.uk.to}"
REMOTE_PORT="${REMOTE_PORT:-2847}"
SSH_KEY="${SSH_KEY:-$HOME/DebianServerKey}"
REMOTE_SITE="${REMOTE_SITE:-~/servers/self-host/site}"
LOCAL_BASE="${LOCAL_BASE:-$SCRIPT_DIR/server}"
NO_SUDO_PROMPT="${NO_SUDO_PROMPT:-0}"

# === derived paths ===
BASE_DIR="$LOCAL_BASE"

# On Windows/Git Bash, ControlMaster/ControlPath don't work reliably —
# detect and skip them so rsync still works.
USE_CONTROLMASTER=1
if [[ "${OS:-}" == "Windows_NT" ]] || [[ "$(uname -s 2>/dev/null)" == MINGW* ]] || [[ "$(uname -s 2>/dev/null)" == MSYS* ]]; then
    USE_CONTROLMASTER=0
fi

RSYNC_OPTS=(-avz --exclude='__pycache__' --exclude='.git' --exclude='secrets/')

if [ "$USE_CONTROLMASTER" -eq 1 ]; then
    SSH_CONTROL_PATH="/tmp/ssh_mux_${REMOTE_USER}_${REMOTE_HOST}_${REMOTE_PORT}"
    SSH_OPTS=(-p "$REMOTE_PORT" -i "$SSH_KEY"
              -o ControlMaster=auto
              -o "ControlPath=$SSH_CONTROL_PATH"
              -o ControlPersist=60)
    echo "Opening SSH connection to $REMOTE_HOST..."
    ssh "${SSH_OPTS[@]}" -N -f "$REMOTE_USER@$REMOTE_HOST"
else
    # Git Bash / Windows: no ControlMaster, passphrase asked per-rsync call
    SSH_OPTS=(-p "$REMOTE_PORT" -i "$SSH_KEY" -o BatchMode=no)
    echo "Note: ControlMaster not available on this platform — passphrase may be asked multiple times."
    echo "      Add your key to ssh-agent (ssh-add) to avoid this."
fi

# helper for running rsync
run_rsync() {
    local src="$1" dst="$2"
    echo "-> rsync $src → $dst"
    rsync "${RSYNC_OPTS[@]}" -e "ssh ${SSH_OPTS[*]}" \
          "$src" "$REMOTE_USER@$REMOTE_HOST:$dst"
}

# 1. sync backend code (Web)
run_rsync "$BASE_DIR/Web/" "$REMOTE_SITE/Web/"

# 2. sync public site (TestWeb)
run_rsync "$BASE_DIR/TestWeb/" "$REMOTE_SITE/TestWeb/"

# 3. sync systemd unit files
run_rsync "$BASE_DIR/services/" "$REMOTE_SITE/services/"

# restart services automatically
echo "Restarting services on $REMOTE_HOST..."
if [ "$NO_SUDO_PROMPT" = "1" ] || [ "${NO_SUDO_PROMPT:-0}" = "1" ]; then
    SUDO_CMD="sudo"
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" <<SSH_CMDS
  set -e
  $SUDO_CMD systemctl restart webserver-http.service webserver-https.service webserver-cdn.service
  echo "services restarted"
SSH_CMDS
else
    read -sp "Enter sudo password for $REMOTE_USER@$REMOTE_HOST: " SUDO_PASS
    echo ""
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" <<SSH_CMDS
  set -e
  echo "$SUDO_PASS" | sudo -S systemctl restart webserver-http.service webserver-https.service webserver-cdn.service
  echo "services restarted"
SSH_CMDS
fi

echo "sync complete"
