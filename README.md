# server `v0.21.0.5`
Just backend code of my server, nothing else, anyone can use it

---

*Release notes: ...*

***Mainstream: ...***

***This update ...***

***Additions:***
- ***Important-message modal. An admin can push a notice that everyone sees the
moment they open FluxDrop — signed in or not — for planned maintenance,
incidents, policy changes and the like. Dismissed once per person, except
`CRITICAL` which re-shows on every load so a real outage can't be clicked away
and forgotten***
- ***Notices are translatable. Each notice carries optional per-language
overrides, so a Ukrainian UI shows Ukrainian text instead of the odd mix of a
translated interface with an English announcement on top. Missing translations
fall back to the default text field by field, and switching language while the
modal is open re-renders it immediately***

***Fixes:***
- ***...***

***Backend additions:***
- ***Notice plumbing on top of the existing `message_board` table, rather than
a parallel concept: new `show_modal`, `expires_at` and `i18n` columns (added by
the startup migration, so existing databases upgrade in place). New public
`GET /api/v1/notice` returns the newest non-expired notice — unauthenticated on
purpose, since the whole point is that a visitor reads "down for maintenance"
*before* signing in or starting a 10 GB upload. Posting a new notice supersedes
the previous one without needing to delete it***
- ***New admin `PATCH /api/v1/board/<id>`, which only touches the keys actually
present in the request body, so the status page can flip `show_modal` or extend
an expiry without resending the whole post and clobbering fields it never
rendered***
- ***Status page admin panel gained a 📢 button on every board post: it
promotes that post to a FluxDrop notice in place — no duplicate row, so the
board entry and the notice can never drift apart — with level, duration and
Ukrainian translation editable at the same time. Live notices are badged in the
list, and "Stop showing" clears the modal while leaving the post (and its
translations) on the board***
- ***`PrefetchReader` (`shared.py`), wired into the download, `zip_stream` and 
CDN-proxy copy loops so disk reads overlap socket writes instead of strictly 
alternating. Note: no measurable throughput gain on the current setup — the 
real ceiling turned out to be the router's NAT hairpin and a BIOS-clamped CPU, 
not the server — but it removes a serialisation that does bind on a faster 
link***

***Backend fixes:***
- ***Fix the CDN's HTTPS listener (`:64800`) wedging permanently. The TLS 
handshake ran inside `serve_forever()`'s accept loop with no timeout, so one 
peer that completed the TCP connect and never sent a ClientHello (port scanners 
do this constantly) blocked the loop forever and the port went dead. Uploads 
kept working the whole time because they take the proxy's internal loopback 
port instead, which is exactly why it went unnoticed for two days — the status 
page was reporting it correctly***
- ***Fix TLS 1.3 always negotiating AES-256-GCM instead of ChaCha20. CPython 
exposes no binding for OpenSSL's `SSL_CTX_set_ciphersuites()`, so the existing 
`set_ciphersuites()` call raised `AttributeError` and was silently swallowed on 
every run — the preference had never once applied. Ordering now comes from 
`OPENSSL_CONF` (`services/openssl-tls13-chacha.cnf`, set in the units). On this 
AES-NI-less host that is ~2x the cipher throughput and half the CPU per byte***
- ***Raise the CDN listener's accept backlog from Python's default of 5 to 
128***
- ***Status page now checks HTTPS with a real TLS handshake instead of a bare 
TCP connect (a connect succeeds from the kernel's backlog even when the accept 
loop is dead), and names the affected port in the cause text instead of saying 
"HTTPS server unreachable"***

***About Immich: right now I don't provide the ability for anyone (except 
chosen ones) to use `gallery.arseniusgen.dev` (Immich hosted instance), but you 
can use FluxDrop for your own purposes. Immich may start to be available at 
some point later, but not now***

***Regressions: ...***

*Patch notes: **Changelog:***
- ***Delete old README; fix the CDN's HTTPS port being dead while the proxy's 
internal loopback port kept uploads working and so masked the outage***
- ***...***

---

`server` is ready for public usage according to the data from `September 11, 
2026`. (see: [FluxDrop Audit](./fluxdrop_audit.md), [ToDo](./TODO.md))

The future code updates would cover important code logic/safety issues 
first, then ToDo entries, then user feedback/issue tracker list on GitHub


Main service is accessible at: https://arseniusgen.uk.to, https://arseniusgen.dev

FluxDrop is accessible at: https://fluxdrop.me

Wiki page for `server`: https://github.com/ArsenijN/server/wiki

New `README.md` style will be applied or merged with current after when 
FluxDrop will reach full production-ready state 
([current look](./README_newstyle.md)) and the version will be bumped to 1.0.0

## Large FluxDrop relations to this server

This server repo is a crucial part of my own projects, like FluxDrop (whole CDN 
implementation and most of the changes are made for it there in the repo) and 
[driveguard](https://github.com/ArsenijN/driveguard) (OTA updates, etc.; 
currently stalled). Since I made my own file hosting thing, I want to make it's 
design "very human" and open for anyone. So... there we are

FluxDrop and entire server now operates with proper HTTPS thanks to **Let's 
Encrypt**'s certificates! Test it out at: arseniusgen.uk.to or 
arsenius-gen.uk.to (arsenius_gen.uk.to is also valid, but can't have secure 
HTTPS due to the limitations in the URL/address of having underscores). Also 
now on arseniusgen.dev and fluxdrop.me

A huge thanks to the Afraid FreeDNS for providing the free subdomains for now 
over than 2 years straight. Those subdomains based my interest in making own 
internet projects since 2023

> Q: Why you didn't used Let's Encrypt before?

> A: High usage of domain. Yes, since I technically owned only a subdomain and 
not a domain, provided by [FreeDNS](https://freedns.afraid.org/subdomain/), I 
was restricted by the thing that other users also used the subdomains from 
uk.to, and... In 2023, I was not able to do the certs because following the 
instructions with `certbot` from Let's Encrypt, it said that "there's a lot of 
certs already made for this domain", and... Self-signed certs was only the 
option that made all of this happened. At 2026 usage was lowered (or because 
the uk.to is now a shealth domain, basically no one can now use it except 
those who used it before?), and I was able to do the certificates successfully 
and properly, and... Now there we are

## Dev info
### Server deployment

It's recommended to wipe the `Web` subfolder (preserving the secrets and 
settings) and re-deploy the new server files to remove excess files from older 
updates and commits. Please be cautious with `rm -rf` command since this may 
lead to the total server wipe of credentials and frontend files

Please take a note that server uses `UPLOAD_TMP_DIR` as storage for chunks that 
are uploaded to the server, to then process them and while processing, write 
them to the destination file. It's very recommended to ensure that 
`UPLOAD_TMP_DIR` lives on separate drive (other HDD from main storage of files) 
since that will envolve severe head seeks that will significantly reduce the 
speeds of the file processing

### Posting a notice

Notices live in the `message_board` table, so anything on the status page's
message board can become one. The intended flow is the status page admin panel
(bottom-right *Admin* pill → **Message Board**): post the announcement as usual,
then press 📢 on it, choose level/duration, optionally fill in the Ukrainian
text, and save. Press 📢 again on a live notice to edit it, or **Stop showing**
to pull it while keeping the board post.

Levels are `info`, `ok`, `warning`, `critical`. Only `critical` re-shows after a
user dismisses it; the rest are remembered per notice id in the visitor's
`localStorage`.

The same thing over the API, if you prefer scripting it:

```bash
TOKEN=<admin session token>

# Post, and show it as a notice for the next 6 hours
curl -X POST https://fluxdrop.me/api/v1/board \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"level":"warning","title":"Planned maintenance 02:00-04:00",
       "body":"Uploads are paused while the CDN restarts.",
       "show_modal":true,"expires_in_hours":6,
       "i18n":{"uk":{"title":"Планові роботи 02:00-04:00",
                     "body":"Завантаження призупинено на час перезапуску CDN."}}}'

# Promote an existing board post (id 42) without changing its text
curl -X PATCH https://fluxdrop.me/api/v1/board/42 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"show_modal":true,"expires_in_hours":24}'

# What visitors currently get (no auth)
curl -s https://fluxdrop.me/api/v1/notice

# Stop showing it (the board post stays)
curl -X PATCH https://fluxdrop.me/api/v1/board/42 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"show_modal":false}'
```

Omit both `expires_in_hours` and `expires_at` and the notice stays up until you
stop it. `expires_at` is UTC `YYYY-MM-DD HH:MM[:SS]`, matching how SQLite stores
`CURRENT_TIMESTAMP`. Sending `"expires_at": null` or `"i18n": null` on a PATCH
clears that field.

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
`./server` tree to the Debian host and restarts all three services 
automatically:
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