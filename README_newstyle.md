# server `v0.10.1`

Backend for my personal server — anyone can use it.

> **Status:** Almost production-ready. See the [Security Audit](./fluxdrop_audit.md) and [TODO](./TODO.md) for what's left.
> FluxDrop will be indexed by search engines after the remaining security fixes (primarily B2, B7, B8 from audit v4) and UI polish are done.

**Live instance:** https://arseniusgen.uk.to  
**FluxDrop:** https://arseniusgen.uk.to/fluxdrop_pp/  
**Wiki:** https://github.com/ArsenijN/server/wiki

---

## What's in this repo

| Component | Description |
|-----------|-------------|
| `server_cdn.py` | Main server — FluxDrop API, auth, file hosting (HTTP + HTTPS) |
| `server_http.py` / `server_https.py` | Thin redirectors for ports 80/443 |
| `shared.py` | Shared utilities (blacklist, logger, health checks) |
| `config.py` | Centralised path/credential config, loaded from `secrets/` |
| `_helper-*.py` | CLI tools for user and token management |
| `server/Web/` | Frontend: HTML, JS, CSS |
| `services/` | systemd unit files |

---

## Quick start

See the **[Wiki](https://github.com/ArsenijN/server/wiki)** for full instructions. Short version:

### Prerequisites
- Python 3.14+ (build from source — see [Wiki: Prerequisites](https://github.com/ArsenijN/server/wiki/Prerequisites))
- `pip`, `imagemagick`, Node.js + npm (for frontend CSS rebuilds)

### Install

```bash
# 1. Clone (building station)
git clone https://github.com/ArsenijN/server
cd server/server/Web

# 2. Create venv on the server
sudo /usr/local/bin/python3.14 -m venv /opt/venvs/site_web
source /opt/venvs/site_web/bin/activate
pip install -r requirements.txt

# 3. Configure secrets
cp secrets_samples/vars.env.sample secrets/vars.env
# Edit secrets/vars.env — set PUBLIC_DOMAIN, SERVE_ROOT, cert paths, etc.

# 4. Deploy from building station
./sync_to_server.sh

# 5. Enable services
sudo cp ../services/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now webserver-cdn webserver-http webserver-https
```

Full walkthrough: [Wiki: Installation](https://github.com/ArsenijN/server/wiki/Installation)

---

## Secrets & credentials

Sensitive files (DB, SMTP credentials, SSL keys) go in `server/Web/secrets/` — this directory is **git-ignored**.  
Sample files in `secrets_samples/` show the format; copy and rename without the `.sample` suffix.

`config.py` loads `secrets/smtp.env`, `secrets/credentials_local.env`, and `secrets/vars.env` automatically at startup.

See [Wiki: Configuration](https://github.com/ArsenijN/server/wiki/Configuration) for a full variable reference.

---

## Keeping it up to date

```bash
./sync_to_server.sh
```

Mirrors `./server` to the remote host via rsync (secrets are always excluded) and restarts all three services. SSH `ControlMaster` multiplexing means your passphrase is only asked once.

---

## Helper scripts

Run from `Web/` with the venv active. See [Wiki: Admin & Helpers](https://github.com/ArsenijN/server/wiki/Admin-and-Helpers).

| Script | Purpose |
|--------|---------|
| `_helper-check_user_password.py <user> <pass>` | Verify a user's password (bcrypt + legacy SHA-256) |
| `_helper-set_user_password.py <user> <pass>` | Reset a password; invalidates all sessions |
| `_helper-generate_token.py <user> <pass> <path>` | Mint a 1-hour file download token |

---

## Services

Edit the `.service` files to match your username and paths before installing:

```ini
User=your_linux_username
WorkingDirectory=/home/your_linux_username/server/Web
ExecStart=/opt/venvs/site_web/bin/python server_cdn.py
```

---

## Related projects

- [driveguard](https://github.com/ArsenijN/driveguard) — OTA updates and device health monitoring, also hosted on this server
