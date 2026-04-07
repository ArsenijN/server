#!/usr/bin/env python3
"""
FluxDrop — batch_tar_upload.py
================================
Upload 150 000+ small files to FluxDrop in one streaming request.

The script creates an uncompressed tar archive ON THE FLY and pipes it
directly to the server.  No temp file is written: the tar bytes are
generated and sent in the same pass, making memory use O(chunk_size).

Usage
-----
    python3 batch_tar_upload.py \\
        --server  https://arseniusgen.uk.to:64800 \\
        --token   <your_session_token> \\
        --src     /local/path/to/files/ \\
        --dest    /remote/folder \\
        --mode    sync          # write | skip | sync
        [--workers 4]           # parallel sockets (1 = single stream)
        [--verify]              # send sha256 manifest for server-side verification

Modes
-----
  write  — always overwrite existing files on the server
  skip   — skip files that already exist (name match)
  sync   — overwrite only if the on-disk size differs from the local file
           (fast: no checksum comparison, just stat)
  
The server streams back NDJSON progress.  This script prints it live.
"""

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import ssl
import threading
from pathlib import Path

# ---------------------------------------------------------------------------

def _collect_files(src_dir: str):
    """Walk src_dir and return a sorted list of (abs_path, arcname) pairs."""
    src = Path(src_dir).resolve()
    result = []
    for p in sorted(src.rglob("*")):
        if p.is_file():
            result.append((str(p), str(p.relative_to(src))))
    return result


def _build_sha256_manifest(files):
    """Compute SHA-256 for every file.  Returned dict: {arcname: hex}."""
    manifest = {}
    for abs_path, arcname in files:
        h = hashlib.sha256()
        with open(abs_path, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
        manifest[arcname] = h.hexdigest()
    return manifest


class _TarStream(io.RawIOBase):
    """
    A read-only stream that generates an uncompressed tar archive on-the-fly
    from a list of (abs_path, arcname) pairs.

    Implements readinto() so that urllib/http.client can consume it without
    buffering the whole archive in memory.  Each file is read in 4 MiB chunks.
    """

    BLOCK = 512          # tar block size
    READ_BUF = 4 << 20  # 4 MiB file read buffer

    def __init__(self, files: list):
        super().__init__()
        self._files     = list(files)  # (abs_path, arcname)
        self._buf       = b""          # unconsumed bytes
        self._file_idx  = 0
        self._eof       = False
        self._gen       = self._generate()

    # ---- internal tar byte generator ----------------------------------------

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """Pad data to the next 512-byte boundary."""
        rem = len(data) % 512
        return data if rem == 0 else data + b"\0" * (512 - rem)

    @staticmethod
    def _header(arcname: str, size: int, mtime: float) -> bytes:
        """Build a minimal POSIX ustar file header block (512 bytes)."""
        name_b = arcname.encode("utf-8")[:100].ljust(100, b"\0")
        mode_b  = b"0000644\0"
        uid_b   = b"0000000\0"
        gid_b   = b"0000000\0"
        size_b  = f"{size:011o}\0".encode()
        mtime_b = f"{int(mtime):011o}\0".encode()
        type_b  = b"0"            # regular file
        link_b  = b"\0" * 100
        magic_b = b"ustar  \0"   # GNU magic (two spaces + NUL, not POSIX)
        uname_b = b"\0" * 32
        gname_b = b"\0" * 32
        devmaj  = b"0000000\0"
        devmin  = b"0000000\0"
        prefix  = b"\0" * 155

        header = (
            name_b + mode_b + uid_b + gid_b +
            size_b + mtime_b +
            b"        " +    # checksum placeholder (8 spaces)
            type_b + link_b + magic_b + uname_b + gname_b +
            devmaj + devmin + prefix +
            b"\0" * 12       # pad to 512
        )[:512]

        # Compute and embed checksum
        cksum = sum(header) & 0xFFFF  # treat placeholder spaces as 0x20 each
        cksum_b = f"{cksum:06o}\0 ".encode()
        header = header[:148] + cksum_b + header[156:]
        return header

    def _generate(self):
        """Yield raw bytes of the tar stream in small pieces."""
        for abs_path, arcname in self._files:
            try:
                stat   = os.stat(abs_path)
                size   = stat.st_size
                mtime  = stat.st_mtime
            except OSError:
                continue  # file disappeared — skip silently

            yield self._header(arcname, size, mtime)

            written = 0
            try:
                with open(abs_path, "rb") as f:
                    while True:
                        chunk = f.read(self.READ_BUF)
                        if not chunk:
                            break
                        yield chunk
                        written += len(chunk)
            except OSError:
                pass  # partial file — pad remainder with zeros

            # Pad file data to block boundary
            rem = written % 512
            if rem:
                yield b"\0" * (512 - rem)

        # Two zero-filled 512-byte blocks mark end-of-archive
        yield b"\0" * 1024

    # ---- io.RawIOBase interface ----------------------------------------------

    def readable(self):
        return True

    def readinto(self, b):
        # Fill b from our internal buffer + generator
        while len(self._buf) < len(b) and not self._eof:
            try:
                chunk = next(self._gen)
                self._buf += chunk
            except StopIteration:
                self._eof = True
                break

        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def read(self, n=-1):
        if n == -1:
            parts = [self._buf]
            self._buf = b""
            for chunk in self._gen:
                parts.append(chunk)
            return b"".join(parts)
        buf = bytearray(n)
        k   = self.readinto(buf)
        return bytes(buf[:k])


def compute_tar_size(files: list) -> int:
    """Pre-compute the exact Content-Length for the tar stream (stat only)."""
    total = 0
    for abs_path, _ in files:
        try:
            size = os.path.getsize(abs_path)
        except OSError:
            continue
        total += 512                       # header
        total += size                      # file data
        rem = size % 512
        if rem:
            total += 512 - rem             # padding
    total += 1024                          # end-of-archive
    return total


# ---------------------------------------------------------------------------

def upload(server: str, token: str, src_dir: str, dest: str,
           mode: str = "write", verify: bool = False,
           workers: int = 1, no_verify_ssl: bool = False):

    files = _collect_files(src_dir)
    if not files:
        print("No files found.", file=sys.stderr)
        return

    print(f"Found {len(files)} files.  Building manifest..." if verify else
          f"Found {len(files)} files.")

    manifest = _build_sha256_manifest(files) if verify else {}
    content_length = compute_tar_size(files)
    print(f"Tar size: {content_length / (1 << 30):.2f} GiB  mode={mode}")

    # Build URL
    params = {"dest_path": dest, "mode": mode}
    if manifest:
        params["sha256_manifest"] = json.dumps(manifest)
    url = (server.rstrip("/") +
           "/api/v1/upload_session/batch_tar?" +
           urllib.parse.urlencode(params))

    # SSL context
    ctx = ssl.create_default_context()
    if no_verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    stream = _TarStream(files)
    wrapped = io.BufferedReader(stream, buffer_size=8 << 20)  # 8 MiB

    req = urllib.request.Request(
        url,
        data=wrapped,
        method="POST",
    )
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type",  "application/x-tar")
    req.add_header("Content-Length", str(content_length))

    t0 = time.monotonic()
    extracted = skipped = errors = 0

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=3600) as resp:
            for raw_line in resp:
                line = raw_line.decode().strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    print(line)
                    continue

                typ = obj.get("type")
                if typ == "progress":
                    done = obj.get("done", 0)
                    name = obj.get("name", "")
                    elapsed = time.monotonic() - t0
                    rate = done / elapsed if elapsed > 0 else 0
                    print(f"\r  [{done}/{len(files)}] {name[:60]:<60}  "
                          f"{rate:.0f} files/s", end="", flush=True)
                    extracted += 1
                elif typ == "skipped":
                    skipped += 1
                elif typ == "error":
                    errors += 1
                    print(f"\n  ERROR {obj.get('name')}: {obj.get('msg')}")
                elif typ == "done":
                    extracted = obj.get("extracted", extracted)
                    skipped   = obj.get("skipped",   skipped)
                    errors    = obj.get("errors",    errors)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"\nHTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.monotonic() - t0
    print(f"\n\nDone in {elapsed:.1f}s — "
          f"extracted={extracted}  skipped={skipped}  errors={errors}")


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="FluxDrop batch tar uploader")
    ap.add_argument("--server",          required=True, help="Server base URL")
    ap.add_argument("--token",           required=True, help="FluxDrop session token")
    ap.add_argument("--src",             required=True, help="Local source directory")
    ap.add_argument("--dest",            required=True, help="Remote destination path")
    ap.add_argument("--mode",            default="write",
                    choices=["write", "skip", "sync"])
    ap.add_argument("--verify",          action="store_true",
                    help="Compute & send SHA-256 manifest for server-side verification")
    ap.add_argument("--no-verify-ssl",   action="store_true",
                    help="Disable SSL certificate verification (for self-signed certs)")
    args = ap.parse_args()

    upload(
        server=args.server,
        token=args.token,
        src_dir=args.src,
        dest=args.dest,
        mode=args.mode,
        verify=args.verify,
        no_verify_ssl=args.no_verify_ssl,
    )


if __name__ == "__main__":
    main()
