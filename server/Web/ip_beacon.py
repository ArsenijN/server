#!/usr/bin/env python3
"""
ip_beacon.py — FluxDrop IP Beacon Daemon
=========================================
Runs on any device (Linux, macOS, Windows).  Periodically pings your
FluxDrop server so it can record the device's current public IP.

First run
---------
Registering needs a FluxDrop login, because each device belongs to an
account. Either:

  python ip_beacon.py --server https://your-server:8443 --register \
      --label "My Laptop" --fluxdrop-token <your FluxDrop session token>

(the session token is in the browser's localStorage as "fluxdrop_token";
FLUXDROP_TOKEN in the environment works too), or register the device on the
server's /beacon/ui page while signed in and hand the result to the daemon:

  python ip_beacon.py --server https://your-server:8443 --primary-token <token>

Either way the tokens are saved to ~/.config/fluxdrop_beacon/tokens.json
(or --token-file of your choice) and pinging starts automatically.

Subsequent runs
---------------
  python ip_beacon.py --server https://your-server:8443

Tokens are loaded from the saved file.

Flags
-----
  --server      Base URL of your FluxDrop CDN server  (required)
  --register    Register this device (first run; needs --fluxdrop-token)
  --fluxdrop-token  FluxDrop session token used by --register ($FLUXDROP_TOKEN)
  --primary-token   Save a device token from the web page instead of registering
  --label       Human-readable name shown on the lookup page
  --token-file  Where to persist tokens (default: ~/.config/fluxdrop_beacon/tokens.json)
  --interval    Ping interval in seconds (default: 60)
  --insecure    Skip TLS certificate verification (useful for self-signed certs)
  --once        Ping once and exit (useful for cron / systemd timer)
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_TOKEN_FILE = Path.home() / ".config" / "fluxdrop_beacon" / "tokens.json"
DEFAULT_INTERVAL   = 60   # seconds


def _make_ctx(insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def _post(url: str, payload: dict, token: str | None, ctx: ssl.SSLContext) -> dict:
    data    = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return json.loads(r.read())


def _get(url: str, ctx: ssl.SSLContext) -> dict:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return json.loads(r.read())


def _load_tokens(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _save_tokens(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    # Restrict permissions so other users can't read the primary token
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def register(server: str, label: str, token_file: Path, ctx: ssl.SSLContext,
             fluxdrop_token: str) -> dict:
    """Register this device. Needs a FluxDrop session token (the device is
    owned by that account) — copy it from the web UI, or register on the
    IP Beacon page instead and pass the result with --primary-token."""
    url = f"{server.rstrip('/')}/beacon/register"
    try:
        resp = _post(url, {"label": label}, token=fluxdrop_token, ctx=ctx)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("[beacon] Registration needs a FluxDrop login: pass --fluxdrop-token "
                  "(or set FLUXDROP_TOKEN), or register on the IP Beacon page and use "
                  "--primary-token.", file=sys.stderr)
            sys.exit(1)
        raise
    _save_tokens(token_file, resp)
    print(f"[beacon] Registered!")
    print(f"  primary_token : {resp['primary_token']}")
    print(f"  read_token    : {resp['read_token']}")
    print(f"  Saved to      : {token_file}")
    return resp


def ping(server: str, primary_token: str, label: str | None,
         ctx: ssl.SSLContext) -> dict | None:
    url  = f"{server.rstrip('/')}/beacon/ping"
    body = {}
    if label:
        body["label"] = label
    try:
        resp = _post(url, body, token=primary_token, ctx=ctx)
        return resp
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[beacon] Ping HTTP error {e.code}: {body}", file=sys.stderr)
    except Exception as e:
        print(f"[beacon] Ping failed: {e}", file=sys.stderr)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="FluxDrop IP Beacon — keeps your server updated with this device's IP"
    )
    parser.add_argument("--server",     required=True,
                        help="Base URL of your FluxDrop server, e.g. https://arseniusgen.uk.to:64800")
    parser.add_argument("--register",   action="store_true",
                        help="Register this device (first run only)")
    parser.add_argument("--fluxdrop-token", default=os.environ.get("FLUXDROP_TOKEN", ""),
                        help="FluxDrop session token, required with --register "
                             "(default: $FLUXDROP_TOKEN)")
    parser.add_argument("--primary-token", default="",
                        help="Use a device already registered on the IP Beacon web page: "
                             "saves this primary token to the token file and starts pinging")
    parser.add_argument("--label",      default="",
                        help="Human-readable label for this device")
    parser.add_argument("--token-file", default=str(DEFAULT_TOKEN_FILE),
                        help=f"Token storage path (default: {DEFAULT_TOKEN_FILE})")
    parser.add_argument("--interval",   type=int, default=DEFAULT_INTERVAL,
                        help=f"Seconds between pings (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--insecure",   action="store_true",
                        help="Disable TLS verification (self-signed certs)")
    parser.add_argument("--once",       action="store_true",
                        help="Ping once and exit (for cron / systemd timer use)")
    args = parser.parse_args()

    ctx        = _make_ctx(args.insecure)
    token_file = Path(args.token_file)

    # ── Register ──────────────────────────────────────────────────────────
    if args.register:
        if not args.fluxdrop_token:
            print("[beacon] --register needs --fluxdrop-token (or FLUXDROP_TOKEN).", file=sys.stderr)
            sys.exit(2)
        tokens = register(args.server, args.label, token_file, ctx, args.fluxdrop_token)
    elif args.primary_token:
        tokens = {"primary_token": args.primary_token, "label": args.label}
        _save_tokens(token_file, tokens)
        print(f"[beacon] Primary token saved to {token_file}")
    else:
        tokens = _load_tokens(token_file)
        if not tokens.get("primary_token"):
            print(
                "[beacon] No token file found.  Run with --register first.",
                file=sys.stderr,
            )
            sys.exit(1)

    primary_token = tokens["primary_token"]
    label         = args.label or tokens.get("label", "")

    # ── Ping loop ─────────────────────────────────────────────────────────
    if args.once:
        resp = ping(args.server, primary_token, label, ctx)
        if resp:
            print(f"[beacon] Pinged OK — server sees IP: {resp.get('ip')}")
        sys.exit(0 if resp else 1)

    print(f"[beacon] Starting ping loop every {args.interval}s  (Ctrl-C to stop)")
    while True:
        resp = ping(args.server, primary_token, label, ctx)
        if resp:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] Pinged OK — server sees IP: {resp.get('ip')}")
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[beacon] Stopped.")
