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

# --- make sure the SSH key is loaded into an agent so we only have to
#     type its passphrase once per session.  This is not necessary if you
#     already run an agent manually (e.g. via your shell rc), but harmless
#     otherwise.  If the agent isn't running, ssh-add will start one.
if ! ssh-add -l 2>/dev/null | grep -q "$(ssh-keygen -lf "$SSH_KEY" | awk '{print $2}')"; then
    echo "Adding SSH key to agent (passphrase may be requested)"
    if ! ssh-add "$SSH_KEY"; then
        echo "WARNING: ssh-add failed; you may need to add the key yourself or run the script under an agent" >&2
    fi
fi

REMOTE_SITE="~/servers/self-host/site"        # base on the server
# we will sync the three subtrees individually, avoiding accidental delete

# shared rsync options
RSYNC_OPTS="-avz --exclude='__pycache__' --exclude='.git'"

# helper for running rsync
run_rsync() {
    local src="$1" dst="$2"
    echo "-> rsync $src → $dst"
    rsync $RSYNC_OPTS -e "ssh -p $REMOTE_PORT -i $SSH_KEY" \
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

ssh -p "$REMOTE_PORT" -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" <<SSH_CMDS
  set -e
  $SUDO_CMD systemctl restart webserver-http.service webserver-https.service webserver-cdn.service
  echo "services restarted"
SSH_CMDS

echo "sync complete"