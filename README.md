# server `v0.19.0.1`
Just backend code of my server, nothing else, anyone can use it

---

*Release notes:*

***Mainstream: More user comfort and abilities with FluxDrop v.19!***

***We are glad to release this new and huge update to the FluxDrop that 
fundamentally changes the user experience with the service! We worked on it for 
the past few months, and we are added a lot of features, such as:***

* ***New domains for the users: `arseniusgen.dev` and `fluxdrop.me`***
* ***Welcome screen for newbies*** — *explaining (almost) everything about how 
FluxDrop works right on your first visit!*
* ***New loading bars and screens, skeleton pages and modals*** — *including 
fresh image placeholders during fetch, dedicated progress bars for blob 
downloads, smooth loading animations for data-heavy stats panels, and a 
gorgeous new gradient placeholder for the acceptance modals.*
* ***Deliberate "Pleasant Loadings"*** — *important actions and state updates 
now hold a smooth loading wheel for at least 1 second so the UI feels 
incredibly stable, deliberate, and satisfying instead of flashing instantly.*
* ***Uploads that are no longer fails if any chunk is missing*** — *network 
errors or timed-out chunks will now immediately trigger a smart retry for 
only the missing/corrupted piece right on the fly, drastically dropping 
internet overhead without needing a full page reload!*
* ***Slow internet is now not a problem for your file uploads!***
* ***Now the FluxDrop support internationalization (i18n) and will be 
translated to more languages, including yours!*** — *and we completely resolved 
the translation drops during UI component state updates (like the Folder First, 
Mixed button, and quota modals). Please note that the localization isn't 
finished yet and may lead to a problems with it*
* ***Trash bin's folder contents are now possible to view and preview*** — 
*plus we fully patched the underlying `206 Partial Content` streaming bugs for 
media file previews inside the trash bin!*
* ***Ability to manage your quota usage with the new visual space analyzer 
util!*** — *Think WizTree or Filelight directly in your browser to see exactly 
what files take up the most space. You can access it via clicking directly on 
the quota usage info panel or in the profile settings.*
* ***Automatic dark mode is new mainstream for those who uses FluxDrop at 
night!*** — *We even re-engineered the theme engine from scratch so the entire 
page load cycle is perfectly synchronized, meaning **no more bright white 
flashes** when loading the page in the dark!*
* ***You can upload the folder or file, without need to specify the upload 
entity type!*** — *The system now automatically negotiates the upload structure 
seamlessly.*
* ***Fixes are also made to the "ZIP Download" for folders to patch the 
problems with speeds of the ZIP streaming downloads***
* ***You can download shared files without JS required!*** — *Access the 
FluxDrop from 2001 PC, an old K-Meleon setup, or a 2010 Samsung Wave running 
bada OS and download your files anywhere, at any time, for anything! (Note: 
Folder downloads as ZIP still require a script-capable browser for now).*
* ***More natural use of the file manager with the right mouse button and 
selections*** — *Enjoy a completely overhauled custom context menu for files 
and folders (streamlined with clean action choices and a vertical "..." 
fallback menu for compact viewports). Plus, we added keyboard-driven file 
selection: use Shift, Ctrl, and Ctrl+Shift exactly like a native desktop file 
explorer!*
* ***Responsive layouts*** — *The entire file manager experience has been 
deeply optimized to scale fluidly across mobile screens, standard 16:9 
monitors, and wide-aspect displays.*
* ***Now you can set the avatar for the profile*** — *complete with smart 
backend optimizations that auto-scale your upload to a crisp 64x64px (actually 
1000x1000px), heavily compressing it via modern AVIF format with JPG fallbacks 
for older devices.*
* ***Action buttons are now redesigned*** — *alongside a gorgeous, intuitive 
redesign for the move, rename, copy, and delete modals.*

***And much, much more! (we gived up in the time of documentation of those 
things)***

***Also, in the time of the server optimizations, we are managed to bump the 
download speeds to the mindblowing 2x times! Right now, our hardware can handle 
up to 40 MB/s download speeds, that's 2x times faster than the older code!***

***Important note: if you want, you can try to use HTTP endpoints of our 
services to reach the theoretical 100 MB/s speeds for uploads. The problem is 
that our hardware is old enough to struggle at encryptions, e.g. `AES-GCM` for 
HTTPS. For even faster speeds, we have made attempts to add the 
`TLS_CHACHA20_POLY1305_SHA256` as secondary main hashing algorithm for HTTPS, 
but it may fallback to `AES-GCM` again and cause slower speeds than expected. 
Future updates should resolve this and other issues that are mentioned before 
or later***

***Security & Infrastructure updates:***

* ***Hardened HTTPS & Asset Delivery*** — *Polished the underlying 
HTTP-to-HTTPS routing layers for the file manager and CDN downloads, preventing 
dead loops and sorting out silent DB hash retrieval timeouts.*
* ***Network Gateway Fixes*** — *Patched API policy request timeouts 
(`NS_ERROR_NET_TIMEOUT`) ensuring secure handshakes finish smoothly on the 
client side.*
* ***Verified Captcha Safeguards*** — *Audited and reinforced the integration 
layers to block automated abuse without hurting user sign-in flows.*

***For developers and testers:***

* ***Fixed the logs duplication*** — *Fully tracking and eliminating redundant 
outputs to keep the host environment clean.*
* ***Network activity bar that shows what FluxDrop does, without need in the 
DevTools to be available*** — *A beautiful, lightweight, one-liner background 
connectivity debug console right at the bottom of the UI settings.*
* ***Locales are now easier to maintain with the helper script, VSCode's 
workflow and GitHub's autocheck script***
* ***Windows's sync script should be fixed for now, without the actual usage I 
can't be sure***

***Regressions: none***

*Patch notes: **Changelog:***
- ***Release as V0.19.0 release, because there's a lot of changes staging***
- ***Fix the version and Readme***

---

`server` is ready for public usage according to the data from `April 28, 2026`. 
(see: [FluxDrop Audit](./fluxdrop_audit.md), [ToDo](./TODO.md))

The future code updates would cover important code logic/safety issues 
first, then ToDo entries, then user feedback/issue tracker list on GitHub


Main service is accessible at: https://arseniusgen.uk.to

FluxDrop is accessible at: https://arseniusgen.uk.to/fluxdrop_pp/

Wiki page for `server`: https://github.com/ArsenijN/server/wiki

New `README.md` style will be applied or merged with current after when 
FluxDrop will reach full production-ready state 
([current look](./README_newstyle.md)) and the version will be bumped to 1.0.0

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
### Server deployment

It's recommended to wipe the `Web` subfolder (preserving the secrets and 
settings) and re-deploy the new server files to remove excess files from older 
updates and commits. Please be cautious with `rm -rf` command since this may 
lead to the total server wipe of credentials and frontend files

Please take a note that server uses `UPLOAD_TMP_DIR` as storage for chunks that 
are uploaded to the server, to then process them and while processing, write 
them to the destination file. It's very recommended to ensure that 
`UPLOAD_TMP_DIR` lives on separate drive since that will envolve severe head 
seeks that will significantly reduce the speeds of the file processing

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