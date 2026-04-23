# server `v0.12.4`
Just backend code of my server, nothing else, anyone can use it

*Release note: **Fix TOS and PP user agreement version preservation; fix 
display of the document version for TOS and PP in window modal***

Currently, the server is ready for public usage, (see: 
[FluxDrop Audit](./fluxdrop_audit.md), [ToDo](./TODO.md))

The future code updates would cover important issues first, then ToDo entries, 
then user feedback/issue tracker list


Accessible at: https://arseniusgen.uk.to

FluxDrop accessible at: https://arseniusgen.uk.to/fluxdrop_pp/

Wiki page: https://github.com/ArsenijN/server/wiki

New Readme style will be applied or merged with current when FluxDrop will 
reach full production-ready state ([current look](./README_newstyle.md)) and
the version will be bumped to 1.0.0

## FluxDrop relations to this server

This server is a part of my own projects, like FluxDrop (whole CDN 
implementation) and [driveguard](https://github.com/ArsenijN/driveguard) (OTA 
updates, etc.). Since I make my own file hosting thing, I want to make it's 
design "very human". So... there we are

FluxDrop and entire server now operates with proper HTTPS thanks to **Let's 
Encrypt**'s certificates! Test it out at: arseniusgen.uk.to or 
arsenius-gen.uk.to (arsenius_gen.uk.to is also valid, but can't have secure 
HTTPS)

> Q: Why you didn't used Let's Encrypt before?

> A: High usage of domain. Yes, since I technically own a subdomain and not a 
domain, provided by [FreeDNS](https://freedns.afraid.org/subdomain/), I was 
restricted by the thing that other users also uses the subdomains from uk.to, 
and... In 2023 I was not able to do this since Let's Encrypt said that "there's 
a lot of certs already made for this domain", and... Self-signed certs is only 
thing that was made all of this happened. At 2026 usage was lowered (or the 
thing that uk.to now a shealth domain, basically no one can now use it except 
those who used it before?) and I was able to do the certificates successfully 
right and... Now there we are

## Dev info
### Secrets handling

Sensitive information (database, SMTP credentials, SSL keys, etc.) is kept in 
`server/Web/secrets` and is **ignored by git**. Example files are available in 
`server/Web/secrets_samples`; copy the relevant sample and rename it without 
the `.sample` suffix before running the servers.  `config.py` and the request 
handlers automatically load any environment-style `KEY=VALUE` pairs from those 
files.

This makes the repository safe to sync or publish; no actual credentials should 
appear in the tracked files.

### Services

The `.service` files use `User=arsen` and `WorkingDirectory=/home/arsen/...` 
which match the author's server. Before running `systemctl enable`, edit these 
to match your own username and deploy path, or set `REMOTE_SERVICE_USER` in 
`deploy.env` (a future deploy step can patch them automatically).

## Installation

### Prerequisites
- Python 3.14+ (developed and tested on 3.14.3)
- `pip`
- ImageMagick (`sudo apt install imagemagick libmagickwand-dev`) — for email 
icon embedding
- Node.js + npm — for rebuilding Tailwind CSS if you modify the frontend

### 1. Clone and enter the repository on building station
```bash
git clone https://github.com/ArsenijN/server
cd serevr/server/Web
```

### 2. Create and activate a virtual environment on remote server
```bash
python3.14 -m venv /opt/venvs/site_web   # matches the path in the .service files
source /opt/venvs/site_web/bin/activate
```
Or use any path you prefer — just update `ExecStart=` in the `.service` files 
accordingly.

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure secrets
Copy the sample files and fill in your values:
```bash
cp secrets_samples/credentials_local.env.sample secrets/credentials_local.env
cp secrets_samples/smtp.env.sample               secrets/smtp.env
cp secrets_samples/myCA.pem.sample               secrets/myCA.pem   # replace with real cert
cp secrets_samples/myCA.key.sample               secrets/myCA.key   # replace with real key
cp secrets_samples/blklst.txt.sample             secrets/blklst.txt
```

Key environment variables (set in `secrets/vars.env`):
| Variable | Description | Example |
|---|---|---|
| `PUBLIC_DOMAIN` | Your public hostname | `example.com` |
| `SERVE_ROOT` | Root of the CDN/media volume | `/srv/fluxdrop/cdn` |
| `SERVE_DIRECTORY` | Root of the static web files | `/srv/fluxdrop/site/TestWeb` |
| `UPLOAD_TMP_DIR` | Temp dir for chunked uploads (should be on the same volume as `SERVE_ROOT`) | `/srv/fluxdrop/cdn/.upload_sessions` |
| `HTTP_PORT` | HTTP listen port | `63512` |
| `HTTPS_PORT` | HTTPS listen port | `64800` |

### 5. Install and enable systemd services
```bash
# Edit the service files first — update User=, WorkingDirectory=, ExecStart= to match your paths
sudo cp ../services/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now webserver-http webserver-https webserver-cdn
```

### 6. Check logs
```bash
journalctl -u webserver-cdn -f
journalctl -u webserver-https -f
```



## Keeping the server up to date

The `sync_to_server.sh` script performs a one-way mirror from your local
`./server` tree to the Debian host and restarts all three services automatically:
```bash
./sync_to_server.sh
```

It uses SSH `ControlMaster` multiplexing, so your passphrase is only asked once
regardless of how many rsync invocations run.

The `secrets/` directory is **always excluded** from sync — live credentials and
the SQLite database on the server are never overwritten by a deploy.

If you prefer not to be prompted for a sudo password each time, either:
- Configure passwordless sudo on the remote for `systemctl restart` only, or
- Set `NO_SUDO_PROMPT=1` before running (uses `sudo` without `-S`, so you'll
  need an active sudo session on the remote already)

To verify the deployed version after a sync, check the server's log or the
`/status` page:
```
https://<your-domain>/status
```