#!/usr/bin/env bash
# sync_to_server.sh  – unidirectional mirror from local ./server tree to the
# Debian host.  We keep the same layout under ~/servers/self-host/site, placing
# Web code, public files and services in their proper subdirectories.
set -euo pipefail

# === configuration ===
BASE_DIR="$(dirname "$0")/server"            # directory containing Web, TestWeb, services
REMOTE_USER="arsen"
REMOTE_HOST="arseniusgen.uk.to"
REMOTE_PORT="2847"                             # SSH port
SSH_KEY="$HOME/DebianServerKey"

REMOTE_SITE="~/servers/self-host/site"        # base on the server

# shared rsync options as an array so excludes are passed as separate arguments
# (quoting inside a string variable breaks rsync exclude matching)
# secrets/ is excluded: it contains live credentials and DB that must not be
# overwritten by a sync from a dev machine.
RSYNC_OPTS=(-avz --exclude='__pycache__' --exclude='.git' --exclude='secrets/')

# Use SSH ControlMaster so all rsync calls and the final SSH command share a
# single connection — the passphrase is only asked once.
SSH_CONTROL_PATH="/tmp/ssh_mux_${REMOTE_USER}_${REMOTE_HOST}_${REMOTE_PORT}"
SSH_OPTS=(-p "$REMOTE_PORT" -i "$SSH_KEY" -o ControlMaster=auto -o "ControlPath=$SSH_CONTROL_PATH" -o ControlPersist=60)

# Open the master connection up front (this is the only point a passphrase is needed)
echo "Opening SSH connection to $REMOTE_HOST..."
ssh "${SSH_OPTS[@]}" -N -f "$REMOTE_USER@$REMOTE_HOST"

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
# if you prefer not to type a sudo password, set NO_SUDO_PROMPT=1 or
# configure the remote account for passwordless sudo on the systemctl
# commands.
echo "restarting services on remote host"
if [ -z "${NO_SUDO_PROMPT:-}" ]; then
    read -sp "Enter sudo password for $REMOTE_USER@$REMOTE_HOST: " SUDO_PASS
    echo ""
    SUDO_CMD="echo \"$SUDO_PASS\" | sudo -S"
else
    SUDO_CMD="sudo"
fi

ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" <<SSH_CMDS
  set -e
  $SUDO_CMD systemctl restart webserver-http.service webserver-https.service webserver-cdn.service
  echo "services restarted"
SSH_CMDS

echo "sync complete"
