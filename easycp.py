#!/usr/bin/env python3
"""
easycp - pull files off a remote box with one pasted command.

Run this on YOUR machine (mac / windows / linux). It starts a tiny
authenticated receiver, works out a reachable URL, and shows you a one-line
shell snippet. Paste that snippet into any VPS shell, then run:

    peek /var/www/html                  # list what would go, upload nothing
    send /var/www/html
    send /etc/nginx/nginx.conf notes.txt

...and the files land in your DropZone folder. No SSH keys, no scp syntax.

There are two front ends over the same engine, and no GUI toolkit in either:

    python3 easycp.py                 # control panel in your browser
    python3 easycp.py --headless      # same controls, from this terminal

The control panel is a plain page served on 127.0.0.1 only - the tunnel never
sees it. Type `help` at the headless prompt for the terminal equivalent.

`.git`, `node_modules` and `.env` are skipped by default - edit "Never send"
in the panel, `exclude ...` at the prompt, pass --exclude, or override per
call on the remote box:

    DZ_EXCLUDE=".git" send /var/www/html     # keep .env this time
    DZ_EXCLUDE= send /var/www/html           # send absolutely everything

Want a stable address instead of a random trycloudflare.com one? Point a
domain you own at easycp:

    python3 easycp.py --tunnel domain --hostname drop.example.com
    python3 easycp.py --tunnel token  --hostname drop.example.com \\
                        --tunnel-token eyJhIjoi...
    python3 easycp.py --tunnel off         # LAN / Tailscale only

Both front ends can do the same thing without any flags.
"""

import argparse
import base64
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

TOKEN = secrets.token_urlsafe(9)
DEST = Path.home() / "DropZone"
AUTO_EXTRACT = True
LOG_SINKS = []          # callables(str)
LOG_HISTORY = []        # replayed into the GUI, which attaches its sink late
CONFIG_PATH = Path.home() / ".dropzone.json"
CF_DIR = Path.home() / ".cloudflared"
_tunnel_proc = None
# what the drop page slices large files into; the receiver serves it to the
# page, so a mode change reaches the browser on its next reload
DROP_CHUNK_MB = [0]


def log(msg):
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    LOG_HISTORY.append(line)
    del LOG_HISTORY[:-500]
    for sink in LOG_SINKS:
        try:
            sink(line)
        except Exception:
            pass


def _int(raw, default=0):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


def tilde(path):
    """~/DropZone/foo reads better in a log than /Users/someone/DropZone/foo."""
    try:
        return "~/" + str(Path(path).relative_to(Path.home()))
    except ValueError:
        return str(path)


def in_dest(path):
    """Log paths as the user thinks of them: relative to the DropZone folder."""
    try:
        return str(Path(path).relative_to(DEST))
    except ValueError:
        return tilde(path)


LIST_LIMIT = 20     # per-file log lines before we summarise the rest


def log_landed(path):
    """Name every file that just landed, so the log says what was copied."""
    try:
        if path.is_file():
            log(f"copied  {in_dest(path)}  {human(path.stat().st_size)}")
            return
        files = sorted(p for p in path.rglob("*") if p.is_file())
        total = 0
        for i, p in enumerate(files):
            size = p.stat().st_size
            total += size
            if i < LIST_LIMIT:
                log(f"   + {p.relative_to(path)}  {human(size)}")
        if len(files) > LIST_LIMIT:
            log(f"   + ... and {len(files) - LIST_LIMIT} more files")
        log(f"copied  {in_dest(path)}/  {len(files)} files  {human(total)}")
    except Exception as e:
        log(f"copied  {in_dest(path)}  (could not list contents: {e})")


def safe_name(raw):
    """Strip anything that could escape the destination folder."""
    name = unquote(raw).replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    return name or "upload.bin"


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        log(f"ignoring unreadable {CONFIG_PATH.name}: {e}")
        return {}


def save_config(cfg):
    """Remembers the connection settings. Holds a tunnel token, so 0600."""
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")
        os.chmod(CONFIG_PATH, 0o600)
    except Exception as e:
        log(f"could not save settings: {e}")


def unique_path(base):
    if not base.exists():
        return base
    stem, suffix = base.stem, base.suffix
    if base.name.endswith(".tar.gz"):
        stem, suffix = base.name[:-7], ".tar.gz"
    for i in range(2, 10000):
        cand = base.with_name(f"{stem}-{i}{suffix}")
        if not cand.exists():
            return cand
    return base.with_name(f"{stem}-{secrets.token_hex(3)}{suffix}")


# Windows keeps these reserved at any extension, and the receiving machine
# may well be one - a browser upload is the one path where we do not control
# what the sender's filesystem allowed.
RESERVED = {"con", "prn", "aux", "nul", "clock$"} | {
    f"{p}{i}" for p in ("com", "lpt") for i in range(1, 10)}
MAX_DEPTH = 24


# A denylist, not an allowlist: "café.txt" has to survive intact, so we take
# out only what is dangerous - separators, the characters Windows forbids,
# control codes, and the bidi overrides that let a name print as something
# other than what it is.
UNSAFE = re.compile("[\\x00-\\x1f\\x7f/\\\\:*?\"<>|"
                    "\\u202a-\\u202e\\u2066-\\u2069\\ufeff]")


def safe_segment(seg):
    """One path component, reduced to something safe on every filesystem."""
    # trailing dots and spaces are legal here but not on Windows, and
    # stripping them is also what stops ".." surviving as a name
    seg = UNSAFE.sub("_", seg).strip(" .")
    if seg.split(".")[0].lower() in RESERVED:
        seg = "_" + seg
    return seg[:120]


def safe_rel(raw):
    """A browser-supplied relative path, split into components that cannot
    escape the folder we join them onto.

    Every segment is filtered, and `.`/`..`/drive letters are dropped
    outright rather than sanitised into a name - `..` must not survive as
    `__`, and `C:` must not become a folder.
    """
    parts = []
    for seg in raw.replace("\\", "/").split("/"):
        seg = seg.strip()
        if not seg or seg in (".", "..") or re.fullmatch(r"[A-Za-z]:", seg):
            continue
        seg = safe_segment(seg)
        if seg:
            parts.append(seg)
    return parts[:MAX_DEPTH]


def under(root, *parts):
    """Join and prove the result really is inside root before we open it."""
    target = (root / Path(*parts)).resolve() if parts else root.resolve()
    if target != root.resolve() and not str(target).startswith(
            str(root.resolve()) + os.sep):
        raise ValueError("path escapes the destination")
    return target


# --------------------------------------------------------------------------
# browser drops
#
# One dropped folder is hundreds of separate uploads, so the batch - not the
# request - owns the destination: the folder is reserved once, up front, and
# every file in it lands there even if a same-named folder already existed.
# --------------------------------------------------------------------------

DROPS = {}
DROPS_LOCK = threading.Lock()
DROP_TTL = 6 * 3600


def open_drop(root_name, files, total):
    now = time.time()
    with DROPS_LOCK:
        for key, old in list(DROPS.items()):
            if now - old["seen"] > DROP_TTL:
                DROPS.pop(key, None)
        root = None
        if root_name:
            root = unique_path(DEST / root_name)
            root.mkdir(parents=True, exist_ok=True)
        drop_id = secrets.token_urlsafe(9)
        DROPS[drop_id] = {"root": root, "files": max(int(files or 0), 0),
                          "bytes": max(int(total or 0), 0), "done": 0,
                          "recv": 0, "listed": 0, "mark": 0, "paths": {},
                          "seen": now, "start": now}
    return drop_id, root


def close_drop(drop_id):
    with DROPS_LOCK:
        return DROPS.pop(drop_id, None)


# --------------------------------------------------------------------------
# receiver
# --------------------------------------------------------------------------

class Receiver(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "easycp/1.0"

    def log_message(self, *args):
        pass  # we do our own logging

    def _authed(self):
        return secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def handle_expect_100(self):
        # curl -T sends "Expect: 100-continue"; reject bad tokens before the body
        if not self._authed():
            self.send_error(401, "bad token")
            return False
        self.send_response_only(100)
        self.end_headers()
        return True

    def _reply(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'unsafe-inline'; "
                             "script-src 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._reply(code, json.dumps(obj).encode(), "application/json")

    # -- receiving -------------------------------------------------------
    def _read_chunked(self, out):
        total = 0
        while True:
            line = self.rfile.readline(65536).strip()
            if not line:
                break
            size = int(line.split(b";")[0], 16)
            if size == 0:
                while True:  # trailers
                    t = self.rfile.readline(65536)
                    if t in (b"\r\n", b"\n", b""):
                        break
                break
            left = size
            while left:
                chunk = self.rfile.read(min(262144, left))
                if not chunk:
                    raise IOError("connection closed mid-chunk")
                out.write(chunk)
                left -= len(chunk)
                total += len(chunk)
            self.rfile.readline(8)  # trailing CRLF
        return total

    def _read_sized(self, out, length):
        total = 0
        while total < length:
            chunk = self.rfile.read(min(262144, length - total))
            if not chunk:
                break
            out.write(chunk)
            total += len(chunk)
        return total

    def _recv_into(self, f):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            return self._read_chunked(f)
        return self._read_sized(f, int(self.headers.get("Content-Length", 0)))

    def _recv_body(self, dest_path):
        """Stream the request body to dest_path. Returns bytes written."""
        tmp = dest_path.with_name(dest_path.name + ".part")
        try:
            with open(tmp, "wb") as f:
                n = self._recv_into(f)
            tmp.replace(dest_path)
            return n
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    def do_PUT(self):
        if not self._authed():
            return self._reply(401, b"bad token\n")

        if urlparse(self.path).path == "/drop/put":
            return self._drop_put()

        DEST.mkdir(parents=True, exist_ok=True)
        name = safe_name(urlparse(self.path).path)
        start = time.time()

        # ---- multipart chunk (Cloudflare caps bodies at 100MB) --------
        part = re.match(r"^(.+)\.p(\d{3,})$", name)
        total = self.headers.get("X-Parts")
        if part and total and total.isdigit():
            base, idx, total = part.group(1), part.group(2), int(total)
            pdir = DEST / ".parts" / base
            pdir.mkdir(parents=True, exist_ok=True)
            try:
                n = self._recv_body(pdir / f"p{idx}")
            except Exception as e:
                log(f"FAILED {name}: {e}")
                return self._reply(500, b"failed\n")

            have = sorted(p for p in pdir.iterdir() if p.name.startswith("p")
                          and not p.name.endswith(".part"))
            done = len(have) >= total
            log(f"receiving {base}  part {int(idx) + 1}/{total}  {human(n)}")
            if done:
                self._assemble(pdir, base, have)
                return self._reply(200, f"\nsent  {base}\n".encode())
            # leading \n: curl's progress meter leaves the cursor mid-line
            return self._reply(
                200, f"\nsent  {base} part {int(idx) + 1}/{total}\n".encode())

        # ---- single-shot upload --------------------------------------
        target = unique_path(DEST / name)
        log(f"receiving {target.name} ...")
        try:
            n = self._recv_body(target)
        except Exception as e:
            log(f"FAILED {target.name}: {e}")
            return self._reply(500, b"failed\n")

        secs = max(time.time() - start, 0.001)
        log(f"received {target.name}  {human(n)}  ({human(n / secs)}/s)")

        if AUTO_EXTRACT and target.name.endswith((".tgz", ".tar.gz")):
            self._extract(target)
        else:
            log_landed(target)
        return self._reply(200, f"\nsent  {name}  {human(n)}\n".encode())

    def _assemble(self, pdir, base, parts):
        joined = unique_path(DEST / base)
        try:
            with open(joined, "wb") as out:
                for p in parts:
                    with open(p, "rb") as chunk:
                        shutil.copyfileobj(chunk, out, 1024 * 1024)
            shutil.rmtree(pdir, ignore_errors=True)
            try:
                pdir.parent.rmdir()   # drop .parts/ once empty
            except OSError:
                pass
            log(f"joined {len(parts)} parts -> {joined.name}  {human(joined.stat().st_size)}")
        except Exception as e:
            log(f"FAILED joining {base}: {e}")
            return
        if AUTO_EXTRACT and joined.name.endswith((".tgz", ".tar.gz")):
            self._extract(joined)
        else:
            log_landed(joined)

    def _extract(self, archive):
        label = archive.name.replace(".tar.gz", "").replace(".tgz", "")
        staging = DEST / f".unpack-{secrets.token_hex(4)}"
        try:
            with tarfile.open(archive, "r:gz") as tf:
                try:
                    tf.extractall(staging, filter="data")   # py3.12+
                except TypeError:
                    tf.extractall(staging)

            entries = list(staging.iterdir())
            if len(entries) == 1:
                # archive already carries its own top-level name; don't double-nest
                final = unique_path(DEST / entries[0].name)
                shutil.move(str(entries[0]), str(final))
                staging.rmdir()
            else:
                final = unique_path(DEST / label)
                shutil.move(str(staging), str(final))

            archive.unlink()
            log_landed(final)
        except Exception as e:
            shutil.rmtree(staging, ignore_errors=True)
            log(f"kept archive (extract failed: {e})")
            log_landed(archive)

    # -- browser drops ---------------------------------------------------
    def do_POST(self):
        if not self._authed():
            return self._reply(401, b"bad token\n")
        path = urlparse(self.path).path
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}

        if path == "/drop/begin":
            DEST.mkdir(parents=True, exist_ok=True)
            root_parts = safe_rel(str(body.get("root") or ""))
            root_name = root_parts[0] if root_parts else ""
            count, size = body.get("files"), body.get("bytes")
            try:
                drop_id, root = open_drop(root_name, count, size)
            except Exception as e:
                log(f"FAILED starting a browser drop: {e}")
                return self._reply(500, b"could not start\n")
            what = f"{root.name}/" if root else plural(int(count or 0), "file")
            log(f"browser drop starting: {what}  {human(int(size or 0))}")
            return self._json({"id": drop_id,
                               "root": root.name if root else ""})

        if path == "/drop/end":
            drop = close_drop(str(body.get("id") or ""))
            if not drop:
                return self._json({"ok": True})
            secs = max(time.time() - drop["start"], 0.001)
            root, done = drop["root"], drop["done"]
            extra = done - drop["listed"]
            if extra > 0:
                log(f"   + ... and {extra} more files")
            what = f"{root.name}/  {plural(done, 'file')}" if root \
                else plural(done, "file")
            log(f"copied  {what}  {human(drop['recv'])}  "
                f"({human(drop['recv'] / secs)}/s)")
            return self._json({"ok": True, "files": drop["done"],
                               "bytes": drop["recv"]})

        return self._reply(404, b"not here\n")

    def _drop_put(self):
        """One file, or one slice of one, from the drop page."""
        with DROPS_LOCK:
            drop = DROPS.get(self.headers.get("X-Drop", ""))
            if drop:
                drop["seen"] = time.time()
        if not drop:
            return self._reply(404, b"unknown drop - reload the page\n")

        try:
            raw = base64.urlsafe_b64decode(
                self.headers.get("X-Path", "") + "===").decode("utf-8")
        except Exception:
            return self._reply(400, b"bad path\n")
        parts = safe_rel(raw)
        if not parts:
            return self._reply(400, b"bad path\n")

        idx = _int(self.headers.get("X-Part"), 0)
        total = max(_int(self.headers.get("X-Parts"), 1), 1)
        offset = _int(self.headers.get("X-Offset"), 0)
        key = "/".join(parts)

        if idx == 0:
            try:
                if drop["root"] is not None:
                    # inside a folder we reserved, so the tree is kept verbatim
                    target = under(drop["root"], *parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                else:
                    target = unique_path(under(DEST, parts[-1]))
            except ValueError:
                log(f"REFUSED {raw}: path escapes {tilde(DEST)}")
                return self._reply(400, b"bad path\n")
            # later slices must reuse this exact name: a collision may have
            # renamed it, and recomputing would send them to the wrong file
            with DROPS_LOCK:
                drop["paths"][key] = target
        else:
            with DROPS_LOCK:
                target = drop["paths"].get(key)
            if target is None:
                return self._reply(409, b"start this file again from part 0\n")

        tmp = target.with_name(target.name + ".part")
        if idx == 0:
            tmp.unlink(missing_ok=True)
        have = tmp.stat().st_size if tmp.exists() else 0
        if have != offset:
            # a retried or out-of-order slice would silently corrupt the file
            return self._reply(409, f"expected offset {have}\n".encode())

        want = _int(self.headers.get("Content-Length"), -1)
        try:
            with open(tmp, "ab") as f:
                n = self._recv_into(f)
            # a dropped connection reads short rather than raising, and on the
            # last slice that would rename a truncated file into place
            if want >= 0 and n != want:
                raise IOError(f"got {n} of {want} bytes")
        except Exception as e:
            tmp.unlink(missing_ok=True)
            log(f"FAILED {key}: {e}")
            return self._reply(500, b"failed\n")

        with DROPS_LOCK:
            drop["recv"] += n
        if idx + 1 < total:
            return self._json({"ok": True, "offset": have + n})

        tmp.replace(target)
        size = target.stat().st_size
        with DROPS_LOCK:
            drop["done"] += 1
            done, listed = drop["done"], drop["listed"]
            # name the first few, then fall back to a percentage so a
            # thousand-file folder does not bury the log
            if listed < LIST_LIMIT:
                drop["listed"] += 1
                # name it as it landed - a collision may have renamed it
                shown = "/".join(parts[:-1] + [target.name])
                line = f"   + {shown}  {human(size)}"
            elif drop["bytes"] and drop["recv"] * 4 // max(drop["bytes"], 1) > drop["mark"]:
                drop["mark"] = drop["recv"] * 4 // max(drop["bytes"], 1)
                line = (f"receiving ... {done}/{drop['files']} files  "
                        f"{human(drop['recv'])} of {human(drop['bytes'])}")
            else:
                line = ""
        if line:
            log(line)
        return self._json({"ok": True, "offset": size, "name": target.name})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/drop", "/drop/"):
            key = parse_qs(parsed.query).get("k", [""])[0]
            if not secrets.compare_digest(key, TOKEN):
                return self._reply(403, b"bad or missing key\n")
            return self._reply(200, DROP_PAGE.encode(), "text/html; charset=utf-8")
        if parsed.path == "/drop/config":
            if not self._authed():
                return self._reply(401, b"bad token\n")
            return self._json({"chunkMb": DROP_CHUNK_MB[0],
                               "dest": DEST.name})
        self._reply(200, b"easycp is listening.\n")


# --------------------------------------------------------------------------
# reachability
# --------------------------------------------------------------------------

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


INSTALL_HINT = {
    "darwin": "brew install cloudflared",
    "win32": "winget install --id Cloudflare.cloudflared",
}.get(sys.platform, "see https://developers.cloudflare.com/cloudflare-one/"
                    "connections/connect-networks/downloads/")


class TunnelError(Exception):
    """cloudflared could not give us a working public address."""


def cloudflared():
    return shutil.which("cloudflared")


def cf_logged_in():
    return (CF_DIR / "cert.pem").exists()


def clean_host(raw):
    """'https://drop.example.com/' -> 'drop.example.com'"""
    host = (raw or "").strip()
    host = re.sub(r"^[a-z]+://", "", host, flags=re.I).strip("/")
    return host.split("/")[0].strip()


def _run_cf(args, timeout=90):
    """One-shot cloudflared command. Returns (ok, output)."""
    exe = cloudflared()
    if not exe:
        return False, "cloudflared is not installed"
    try:
        p = subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"`cloudflared {args[0]}` timed out"
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode == 0, out.strip()


def _spawn(args):
    """Start a long-lived cloudflared process and pump its output onto a queue."""
    global _tunnel_proc
    _tunnel_proc = subprocess.Popen(
        [cloudflared(), *args],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    q = queue.Queue()
    threading.Thread(target=_pump, args=(_tunnel_proc, q), daemon=True).start()
    return _tunnel_proc, q


def _pump(proc, q):
    for line in proc.stdout:
        q.put(line)
    q.put(None)


def _await(proc, q, pattern, timeout):
    """Wait for a line matching pattern. Returns the match, or None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            line = q.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None:
                return None
            continue
        if line is None:
            return None
        m = pattern.search(line)
        if m:
            threading.Thread(target=_drain, args=(q,), daemon=True).start()
            return m
    return None


def _drain(q):
    while q.get() is not None:
        pass


def start_quick_tunnel(port, timeout=25):
    """Free quick tunnel -> random trycloudflare.com https URL. No account."""
    if not cloudflared():
        raise TunnelError(f"cloudflared is not installed  ({INSTALL_HINT})")
    log("opening cloudflare quick tunnel ...")
    proc, q = _spawn(["tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"])
    m = _await(proc, q, re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com"), timeout)
    if not m:
        stop_tunnel()
        raise TunnelError("quick tunnel did not come up")
    return m.group(0)


def start_named_tunnel(port, hostname, name="dropzone", timeout=30):
    """Named tunnel on a domain in your Cloudflare account. Needs `tunnel login`."""
    if not cloudflared():
        raise TunnelError(f"cloudflared is not installed  ({INSTALL_HINT})")
    hostname = clean_host(hostname)
    if "." not in hostname:
        raise TunnelError("enter a full hostname, e.g. drop.example.com")
    if not cf_logged_in():
        raise TunnelError("not authorised yet - click 'Log in to Cloudflare' first")
    name = (name or "dropzone").strip()

    ok, out = _run_cf(["tunnel", "list", "--output", "json"])
    if not ok:
        raise TunnelError(f"could not list tunnels: {out.splitlines()[-1] if out else '?'}")
    try:
        existing = {t.get("name") for t in json.loads(out or "[]")}
    except Exception:
        existing = set()

    if name not in existing:
        log(f"creating tunnel '{name}' ...")
        ok, out = _run_cf(["tunnel", "create", name])
        if not ok:
            raise TunnelError(f"could not create tunnel: {_last(out)}")

    log(f"routing {hostname} -> {name} ...")
    ok, out = _run_cf(["tunnel", "route", "dns", "--overwrite-dns", name, hostname])
    if not ok:
        raise TunnelError(f"could not add DNS record: {_last(out)}")

    log(f"starting tunnel '{name}' ...")
    proc, q = _spawn(["tunnel", "--no-autoupdate", "run",
                      "--url", f"http://127.0.0.1:{port}", name])
    if not _await(proc, q, _READY, timeout):
        stop_tunnel()
        raise TunnelError(f"tunnel '{name}' did not connect")
    return f"https://{hostname}"


def start_token_tunnel(port, hostname, token, timeout=30):
    """Run a tunnel from a Zero Trust dashboard token. Routing lives in the dashboard."""
    if not cloudflared():
        raise TunnelError(f"cloudflared is not installed  ({INSTALL_HINT})")
    hostname = clean_host(hostname)
    if "." not in hostname:
        raise TunnelError("enter the public hostname you set in the dashboard")
    if not (token or "").strip():
        raise TunnelError("paste the tunnel token from the Cloudflare dashboard")

    log("starting tunnel from token ...")
    proc, q = _spawn(["tunnel", "--no-autoupdate", "run",
                      "--url", f"http://127.0.0.1:{port}", "--token", token.strip()])
    if not _await(proc, q, _READY, timeout):
        stop_tunnel()
        raise TunnelError("token tunnel did not connect (is the token current?)")
    return f"https://{hostname}"


_READY = re.compile(r"Registered tunnel connection|Connection [0-9a-fA-F-]+ registered",
                    re.I)


def _last(out):
    lines = [l for l in (out or "").splitlines() if l.strip()]
    return lines[-1] if lines else "unknown error"


def cf_login(on_done):
    """`cloudflared tunnel login` opens a browser; the user picks the zone there."""
    def work():
        if not cloudflared():
            return on_done(False, f"cloudflared is not installed  ({INSTALL_HINT})")
        log("opening browser for Cloudflare authorisation ...")
        ok, out = _run_cf(["tunnel", "login"], timeout=300)
        if ok and cf_logged_in():
            log("cloudflare authorised")
            on_done(True, "authorised - now pick a hostname and hit Apply")
        else:
            on_done(False, _last(out) if out else "login failed")
    threading.Thread(target=work, daemon=True).start()


def bring_up(port, mode, hostname="", name="dropzone", token="", url=""):
    """Bring up whatever the chosen mode needs and return the public base URL."""
    stop_tunnel()
    if mode == "quick":
        return start_quick_tunnel(port)
    if mode == "domain":
        return start_named_tunnel(port, hostname, name)
    if mode == "token":
        return start_token_tunnel(port, hostname, token)
    if mode == "url":
        base = (url or "").strip().rstrip("/")
        if not base:
            raise TunnelError("enter the base URL that reaches this machine")
        if not re.match(r"^https?://", base):
            base = "https://" + base
        return base
    return f"http://{lan_ip()}:{port}"   # direct / LAN


def stop_tunnel():
    global _tunnel_proc
    if _tunnel_proc and _tunnel_proc.poll() is None:
        _tunnel_proc.terminate()
        try:
            _tunnel_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _tunnel_proc.kill()
    _tunnel_proc = None


DEFAULT_EXCLUDE = ".git node_modules .env"


def snippet(base_url, chunk_mb=0, excludes=DEFAULT_EXCLUDE):
    """Defines `peek` (dry run) and `send` (upload) in the remote shell.

    chunk_mb > 0 splits the stream so each request stays under proxy limits.
    excludes is a space-separated pattern list; the remote shell can override
    it per-call with DZ_EXCLUDE='...' send /path.
    """
    excludes = " ".join((excludes or "").split())

    # $(_dzx) is deliberately unquoted so each pattern becomes its own word.
    # The inner $(printf ...) is what forces that split under zsh too, which
    # does not split a bare $VAR - there the excludes would silently do nothing.
    prelude = (
        f'DZ_EXCLUDE="${{DZ_EXCLUDE-{excludes}}}"; '
        '_dzx() { for x in $(printf "%s\\n" "$DZ_EXCLUDE"); do '
        'printf " --exclude=%s" "$x"; done; }; '
    )

    peek = (
        'peek() { for p in "$@"; do b=$(basename "$p"); d=$(dirname "$p"); '
        't=$(mktemp); tar -C "$d" $(_dzx) -czf "$t" "$b"; echo "== $p"; '
        'tar -tzf "$t" | sed "s/^/   /" | head -30; '
        'echo "   ---- $(tar -tzf "$t" | wc -l | tr -d " ") entries, '
        '$(wc -c < "$t" | awk \'{printf "%.2f MB", $1/1048576}\') gzipped"; '
        'rm -f "$t"; done; }; '
    )

    if not chunk_mb:
        send = (
            'send() { for p in "$@"; do b=$(basename "$p"); '
            'tar -C "$(dirname "$p")" $(_dzx) -czf - "$b" | '
            f'curl -f#T - -H "X-Token: {TOKEN}" "{base_url}/u/$b.tgz"; done; }}'
        )
    else:
        send = (
            'send() { for p in "$@"; do b=$(basename "$p"); d=$(mktemp -d); '
            f'tar -C "$(dirname "$p")" $(_dzx) -czf - "$b" | '
            f'split -b {chunk_mb}m -d -a 3 - "$d/p"; '
            'n=$(ls "$d" | wc -l); i=0; for f in "$d"/p*; do '
            f'curl -f#T "$f" -H "X-Token: {TOKEN}" -H "X-Parts: $n" '
            f'"{base_url}/u/$b.tgz.p$(printf %03d $i)" || break; i=$((i+1)); done; '
            'rm -rf "$d"; done; }'
        )
    return prelude + peek + send


def chunk_for(mode, base, override="auto"):
    """Everything through the Cloudflare proxy hits a 100MB body cap."""
    if override != "auto":
        return int(override)
    if mode in ("quick", "domain", "token"):
        return 90
    return 90 if "trycloudflare.com" in (base or "") else 0


# --------------------------------------------------------------------------
# modes
# --------------------------------------------------------------------------

MODES = [
    {"id": "quick", "name": "Cloudflare quick tunnel",
     "note": "random URL, no account", "fields": [],
     "hint": "A throwaway https URL from Cloudflare. Changes every run."},
    {"id": "domain", "name": "My domain via Cloudflare",
     "note": "needs a Cloudflare account", "fields": ["hostname", "tunnel_name"],
     "hint": "Uses a domain already on your Cloudflare account. Log in once, "
             "then easycp creates the tunnel and the DNS record for you."},
    {"id": "token", "name": "Cloudflare tunnel token",
     "note": "from the Zero Trust dashboard", "fields": ["hostname", "tunnel_token"],
     "hint": "Create the tunnel at one.dash.cloudflare.com (Networks > Tunnels), "
             "point its public hostname at http://127.0.0.1:{port}, then paste "
             "the token here."},
    {"id": "direct", "name": "Direct / LAN",
     "note": "no tunnel", "fields": [],
     "hint": "Reachable only from this network - LAN, Tailscale, or your own "
             "port-forward. No 100MB request cap."},
    {"id": "url", "name": "Custom URL",
     "note": "your own proxy or port-forward", "fields": ["url"],
     "hint": "Already have easycp reachable somewhere? Enter that base URL and "
             "easycp will just print the matching command."},
]
MODE_IDS = [m["id"] for m in MODES]
FIELD_LABELS = {"hostname": "Hostname", "tunnel_name": "Tunnel name",
                "tunnel_token": "Tunnel token", "url": "Base URL"}


def mode_info(mode_id):
    for m in MODES:
        if m["id"] == mode_id:
            return m
    return MODES[0]


def log_class(msg):
    """Which colour a log line gets, in the browser and in the terminal."""
    low = msg.lower()
    if msg.startswith("   +"):
        return "dim"
    if "failed" in low or low.startswith("could not"):
        return "bad"
    if low.startswith(("copied", "sent", "joined", "unpacked", "listening")):
        return "ok"
    if low.startswith(("receiving", "connecting", "switching", "opening",
                       "starting", "waiting", "creating", "routing")):
        return "warn"
    return "msg"


# --------------------------------------------------------------------------
# event bus - one log line goes to every open browser tab
# --------------------------------------------------------------------------

class Bus:
    def __init__(self):
        self.clients = []
        self.lock = threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=2000)
        with self.lock:
            self.clients.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.clients:
                self.clients.remove(q)

    def publish(self, kind, data):
        msg = json.dumps({"kind": kind, "data": data})
        with self.lock:
            clients = list(self.clients)
        for q in clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass        # a tab that cannot keep up loses lines, not the app


BUS = Bus()


# --------------------------------------------------------------------------
# app state - both front ends drive this one object
# --------------------------------------------------------------------------

class App:
    def __init__(self, port, cfg, chunk_override="auto"):
        self.port = port
        self.chunk_override = chunk_override
        self.mode = cfg.get("mode", "quick")
        self.hostname = cfg.get("hostname", "")
        self.tunnel_name = cfg.get("tunnel_name", "dropzone") or "dropzone"
        self.tunnel_token = cfg.get("tunnel_token", "")
        self.url = cfg.get("url", "")
        self.exclude = cfg.get("exclude", DEFAULT_EXCLUDE)
        self.base = f"http://{lan_ip()}:{port}"
        self.chunk = 0
        self.health = "idle"            # idle | busy | live | error
        self.status = "starting"
        self.busy = False

    # -- settings --------------------------------------------------------
    def settings(self):
        return dict(mode=self.mode, hostname=self.hostname,
                    tunnel_name=self.tunnel_name, tunnel_token=self.tunnel_token,
                    url=self.url, exclude=self.exclude)

    def update(self, **kw):
        for key in ("mode", "hostname", "tunnel_name", "tunnel_token", "url",
                    "exclude"):
            if key in kw and kw[key] is not None:
                setattr(self, key, str(kw[key]).strip())
        if self.mode not in MODE_IDS:
            self.mode = "quick"
        self.hostname = clean_host(self.hostname)
        self.tunnel_name = self.tunnel_name or "dropzone"

    def save(self):
        save_config(self.settings())

    def snippet(self):
        return snippet(self.base, self.chunk, self.exclude)

    def drop_url(self):
        """The link you hand to whoever is sending - it carries the key, so
        anyone holding it can upload until easycp restarts."""
        return f"{self.base}/drop?k={TOKEN}"

    def as_dict(self):
        return {
            "dropUrl": self.drop_url(),
            "modes": MODES, "fieldLabels": FIELD_LABELS, "mode": self.mode,
            "hostname": self.hostname, "tunnel_name": self.tunnel_name,
            "tunnel_token": self.tunnel_token, "url": self.url,
            "exclude": self.exclude, "base": self.base, "chunk": self.chunk,
            "snippet": self.snippet(), "dest": tilde(DEST), "port": self.port,
            "health": self.health, "status": self.status, "busy": self.busy,
            "cloudflared": bool(cloudflared()), "cfLoggedIn": cf_logged_in(),
            "installHint": INSTALL_HINT,
            "hint": mode_info(self.mode)["hint"].replace("{port}", str(self.port)),
        }

    def push(self):
        BUS.publish("state", self.as_dict())

    # -- actions ---------------------------------------------------------
    def set_exclude(self, patterns):
        self.exclude = " ".join((patterns or "").split())
        self.save()
        self.push()

    def apply(self, **kw):
        """Bring the chosen mode up. Blocking; returns (ok, message)."""
        self.update(**kw)
        self.busy, self.health = True, "busy"
        self.status = "connecting ..."
        self.push()
        log(f"switching to {mode_info(self.mode)['name']} ...")
        try:
            self.base = bring_up(self.port, self.mode, self.hostname,
                                 self.tunnel_name, self.tunnel_token, self.url)
            self.chunk = chunk_for(self.mode, self.base, self.chunk_override)
            self.health, self.status = "live", f"listening on {self.base}"
            self.save()
            log(f"listening on {self.base}")
            result = (True, self.status)
        except TunnelError as e:
            # bring_up() already tore the old tunnel down, so the previous URL
            # is dead - fall back to the address that actually still works.
            self.base = f"http://{lan_ip()}:{self.port}"
            self.chunk = chunk_for("direct", self.base, self.chunk_override)
            self.health = "error"
            self.status = f"{e} - showing this machine's local address"
            log(f"connect failed: {e}")
            log(f"local address only: {self.base}")
            result = (False, str(e))
        except Exception as e:                  # never get stuck on "connecting"
            self.health = "error"
            self.status = f"{type(e).__name__}: {e}"
            log(f"connect failed: {self.status}")
            result = (False, self.status)
        finally:
            self.busy = False
            DROP_CHUNK_MB[0] = self.chunk    # the drop page slices to match
            self.push()
        return result

    def apply_async(self, **kw):
        threading.Thread(target=lambda: self.apply(**kw), daemon=True).start()

    def login_async(self):
        self.busy, self.health = True, "busy"
        self.status = "waiting for the browser ..."
        self.push()

        def done(ok, msg):
            self.busy = False
            self.health = "live" if ok else "error"
            self.status = msg
            self.push()

        cf_login(done)


# --------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>easycp</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%232563eb'/><path d='M16 6v13m0 0l-5-5m5 5l5-5M8 25h16' stroke='white' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>">
<style>
:root{
  --bg:#f4f6fb; --card:#fff; --line:#e3e8f0; --ink:#0f172a; --mute:#5b6577;
  --faint:#94a0b3; --accent:#2563eb; --accent-ink:#fff; --accent-soft:#e8eefc;
  --good:#059669; --bad:#dc2626; --warn:#b45309;
  --panel:#0f172a; --panel-ink:#e2e8f0; --panel-line:#1e2b45;
  --radius:12px; --shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0a0f1d; --card:#121a2c; --line:#22304a; --ink:#e8edf7; --mute:#9aa8bf;
    --faint:#6b7a93; --accent:#4f83f1; --accent-soft:#1a2743; --good:#34d399;
    --bad:#f87171; --warn:#fbbf24; --panel:#070d19; --panel-line:#1c2842;
    --shadow:none;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:960px;margin:0 auto;padding:28px 22px 40px}
header{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;
  margin-bottom:20px;flex-wrap:wrap}
h1{margin:0;font-size:26px;letter-spacing:-.02em}
/* the wordmark is art, so the real heading is left for screen readers only */
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);
  white-space:nowrap}
pre.mark{margin:0;color:var(--accent);font-family:ui-monospace,SFMono-Regular,
  Menlo,Consolas,monospace;font-size:clamp(5px,1.55vw,11px);line-height:1.12;
  font-weight:600}
.tag{color:var(--mute);font-size:13px;margin-top:6px}
.right{display:flex;align-items:center;gap:10px}
.dest{color:var(--mute);font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace}

.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);padding:18px 20px;margin-bottom:14px}
.chead{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.chead h2{margin:0;font-size:15px;font-weight:600}
.chead .sub{color:var(--mute);font-size:12.5px}
.step{background:var(--accent-soft);color:var(--accent);font-size:11px;font-weight:700;
  border-radius:6px;padding:2px 7px}
.pill{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--mute);
  font-size:12.5px;max-width:60%;text-align:right}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);flex:none}
.dot.live{background:var(--good)} .dot.error{background:var(--bad)}
.dot.busy{background:var(--accent);animation:blink 1s infinite}
@keyframes blink{50%{opacity:.25}}

.modes{display:grid;gap:8px}
.mode{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:9px;
  border:1px solid transparent;cursor:pointer;user-select:none}
.mode:hover{background:var(--accent-soft)}
.mode .mark{width:15px;height:15px;border-radius:50%;border:2px solid var(--faint);flex:none}
.mode[aria-checked=true]{background:var(--accent-soft);border-color:var(--accent)}
.mode[aria-checked=true] .mark{border-color:var(--accent);box-shadow:inset 0 0 0 3px var(--card);
  background:var(--accent)}
.mode .name{font-weight:550}
.mode[aria-checked=true] .name{color:var(--accent)}
.mode .note{color:var(--faint);font-size:12.5px}

.fields{margin:14px 0 0;display:grid;gap:10px}
.row{display:grid;grid-template-columns:120px 1fr;align-items:center;gap:12px}
.row label{color:var(--mute);font-size:12.5px}
input[type=text],input[type=password]{width:100%;padding:8px 11px;border-radius:8px;
  border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit;
  font-size:13.5px}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.hint{color:var(--faint);font-size:12.5px;margin-top:12px;min-height:34px}
.actions{display:flex;align-items:center;gap:9px;margin-top:12px;flex-wrap:wrap}

.btn{border:1px solid transparent;border-radius:9px;padding:8px 16px;font:inherit;
  font-size:13.5px;font-weight:550;cursor:pointer;background:var(--accent);
  color:var(--accent-ink);transition:background .12s,transform .04s}
.btn:hover{filter:brightness(1.07)} .btn:active{transform:translateY(1px)}
.btn.ghost{background:var(--card);color:var(--ink);border-color:var(--line)}
.btn.ghost:hover{background:var(--accent-soft)}
.btn.ok{background:var(--good);color:#fff;border-color:transparent}
.btn[disabled]{opacity:.45;cursor:not-allowed;filter:none}

.skip{display:flex;align-items:center;gap:11px;margin-bottom:12px;flex-wrap:wrap}
.skip label{color:var(--mute);font-size:12.5px;white-space:nowrap}
.skip input{flex:1;min-width:200px}
.skip .tip{color:var(--faint);font-size:12px}

pre.code,#log{background:var(--panel);border:1px solid var(--panel-line);border-radius:10px;
  color:var(--panel-ink);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:12.5px;margin:0;padding:13px 15px}
pre.code{white-space:pre-wrap;word-break:break-all;max-height:190px;overflow:auto}
#log{height:280px;overflow:auto;line-height:1.55}
#log div{white-space:pre-wrap;word-break:break-word}
#log .t{color:#64748b}
#log .ok{color:#34d399} #log .warn{color:#fbbf24} #log .bad{color:#f87171}
#log .dim{color:#8b9ab1} #log .msg{color:var(--panel-ink)}
.foot{display:flex;align-items:center;gap:10px;margin-top:12px;flex-wrap:wrap}
.meta{color:var(--mute);font-size:12.5px}
code.k{background:var(--accent-soft);color:var(--accent);border-radius:5px;padding:1px 6px;
  font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.err{background:var(--bad);color:#fff;padding:10px 14px;border-radius:9px;margin-bottom:14px}

.wm{display:flex;align-items:center;gap:10px;justify-content:center;
  margin-top:22px;padding-top:16px;border-top:1px solid var(--line);
  font-size:12px;color:var(--faint)}
.wm-mark{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:700;
  letter-spacing:.04em;color:var(--mute)}
.wm a{color:var(--faint);text-decoration:none}
.wm a:hover{color:var(--accent);text-decoration:underline}
</style></head><body>
<div class="wrap">
  <header>
    <div>
      <h1 class="sr">easycp</h1>
      <pre class="mark" aria-hidden="true">  ___   __ _  ___   _   _   ___  _ __
 / _ \ / _` |/ __| | | | | / __|| '_ \
|  __/| (_| |\__ \ | |_| || (__ | |_) |
 \___| \__,_||___/  \__, | \___|| .__/
                    |___/       |_|</pre>
      <div class="tag">one-paste file transfer off a remote box</div>
    </div>
    <div class="right">
      <span class="dest" id="dest"></span>
      <button class="btn ghost" id="open">Open folder</button>
      <button class="btn ghost" id="quit">Quit</button>
    </div>
  </header>

  <div id="offline" class="err" hidden>Lost the connection to easycp. Is it still running?</div>

  <section class="card">
    <div class="chead">
      <h2>Connection</h2>
      <span class="pill"><i class="dot" id="dot"></i><span id="status"></span></span>
    </div>
    <div class="modes" id="modes" role="radiogroup"></div>
    <div class="fields" id="fields"></div>
    <div class="hint" id="hint"></div>
    <div class="actions">
      <button class="btn" id="apply">Apply</button>
      <button class="btn ghost" id="login">Log in to Cloudflare</button>
      <span class="meta" id="cfnote"></span>
    </div>
  </section>

  <section class="card">
    <div class="chead"><span class="step">1</span><h2>Paste this into your VPS shell</h2></div>
    <div class="skip">
      <label for="excl">Never send</label>
      <input type="text" id="excl" spellcheck="false" autocomplete="off">
      <span class="tip">space-separated patterns</span>
    </div>
    <pre class="code" id="snippet"></pre>
    <div class="foot">
      <button class="btn" id="copy">Copy command</button>
      <span class="meta" id="listening"></span>
    </div>
  </section>

  <section class="card">
    <div class="chead"><h2>EasyDrop &mdash; send from a browser</h2>
      <span class="sub">for a Windows box, a phone, or anyone without a shell</span>
    </div>
    <pre class="code" id="dropurl"></pre>
    <div class="foot">
      <button class="btn ghost" id="copylink">Copy link</button>
      <span class="meta">Anyone with this link can upload here until easycp
        restarts, which issues a new key.</span>
    </div>
  </section>

  <section class="card">
    <div class="chead"><span class="step">2</span><h2>Activity</h2>
      <span class="sub"><code class="k">peek /path</code> previews &middot;
        <code class="k">send /path</code> copies it here</span>
    </div>
    <div id="log"></div>
  </section>

  <footer class="wm">
    <span class="wm-mark">easycp</span>
    <a href="https://github.com/roninimous/easycp" target="_blank"
       rel="noopener noreferrer">github.com/roninimous/easycp</a>
  </footer>
</div>
<script>
const K = new URLSearchParams(location.search).get('k') || sessionStorage.getItem('dzk') || '';
if (K) sessionStorage.setItem('dzk', K);
const $ = s => document.querySelector(s);
let S = null;

async function api(path, body){
  const opt = {headers:{'X-UI-Token':K}};
  if (body){ opt.method='POST'; opt.headers['Content-Type']='application/json';
             opt.body=JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function modeCards(){
  $('#modes').innerHTML = S.modes.map(m =>
    `<div class="mode" role="radio" data-id="${m.id}" aria-checked="false" tabindex="0">
       <span class="mark"></span><span class="name">${m.name}</span>
       <span class="note">${m.note}</span></div>`).join('');
  document.querySelectorAll('.mode').forEach(el => {
    const pick = () => { S.mode = el.dataset.id; render(); };
    el.onclick = pick;
    el.onkeydown = e => { if (e.key === ' ' || e.key === 'Enter'){ e.preventDefault(); pick(); } };
  });
}

function fields(){
  const need = S.modes.find(m => m.id === S.mode).fields;
  const box = $('#fields');
  const focused = document.activeElement && document.activeElement.dataset
                  ? document.activeElement.dataset.key : null;
  if (box.dataset.for !== S.mode){
    box.dataset.for = S.mode;
    box.innerHTML = need.map(f =>
      `<div class="row"><label for="f-${f}">${S.fieldLabels[f]}</label>
       <input id="f-${f}" data-key="${f}" spellcheck="false" autocomplete="off"
        type="${f === 'tunnel_token' ? 'password' : 'text'}"></div>`).join('');
    box.querySelectorAll('input').forEach(i => {
      i.value = S[i.dataset.key] || '';
      i.oninput = () => { S[i.dataset.key] = i.value; };
      i.onkeydown = e => { if (e.key === 'Enter') $('#apply').click(); };
    });
  } else {
    box.querySelectorAll('input').forEach(i => {
      if (i.dataset.key !== focused) i.value = S[i.dataset.key] || '';
    });
  }
}

function render(){
  document.querySelectorAll('.mode').forEach(el =>
    el.setAttribute('aria-checked', el.dataset.id === S.mode));
  fields();
  $('#hint').textContent = S.modes.find(m => m.id === S.mode).hint
                            .replace('{port}', S.port);
  $('#dot').className = 'dot ' + S.health;
  $('#status').textContent = S.status;
  $('#dest').textContent = S.dest;
  $('#snippet').textContent = S.snippet;
  $('#dropurl').textContent = S.dropUrl;
  $('#listening').textContent = 'listening on ' + S.base +
    (S.chunk ? '   ·   split into ' + S.chunk + 'MB requests' : '');
  if (document.activeElement !== $('#excl')) $('#excl').value = S.exclude;
  $('#apply').disabled = S.busy;
  $('#apply').textContent = S.busy ? 'Connecting…' : 'Apply';
  $('#login').disabled = S.busy || S.mode !== 'domain';
  $('#cfnote').textContent = S.cloudflared
    ? (S.mode === 'domain' && !S.cfLoggedIn ? 'log in once to use your own domain' : '')
    : 'cloudflared not found — ' + S.installHint;
}

function addLog(entry){
  const line = entry.line, cls = entry.cls;
  const box = $('#log');
  const stuck = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  const i = line.indexOf('] ');
  const div = document.createElement('div');
  const t = document.createElement('span');
  t.className = 't'; t.textContent = i > 0 ? line.slice(0, i + 2) : '';
  const m = document.createElement('span');
  m.className = cls; m.textContent = i > 0 ? line.slice(i + 2) : line;
  div.append(t, m); box.append(div);
  while (box.childElementCount > 800) box.firstChild.remove();
  if (stuck) box.scrollTop = box.scrollHeight;
}

$('#apply').onclick = () => {
  const body = {mode:S.mode, hostname:S.hostname, tunnel_name:S.tunnel_name,
                tunnel_token:S.tunnel_token, url:S.url};
  S.busy = true; render();
  api('/api/connect', body).catch(e => alert(e.message));
};
$('#login').onclick = () => api('/api/login', {}).catch(e => alert(e.message));
$('#open').onclick = () => api('/api/open', {}).catch(e => alert(e.message));
$('#quit').onclick = () => {
  if (confirm('Stop easycp? Transfers in progress will be cut off.'))
    api('/api/quit', {}).catch(() => {});
};

let exclTimer = null;
$('#excl').oninput = () => {
  clearTimeout(exclTimer);
  const v = $('#excl').value;
  exclTimer = setTimeout(() => api('/api/exclude', {exclude:v}).catch(()=>{}), 350);
};

async function copyBtn(btn, text, label){
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.append(ta); ta.select();
    try { document.execCommand('copy'); } finally { ta.remove(); }
  }
  btn.textContent = '✓  Copied!'; btn.classList.add('ok');
  clearTimeout(btn._t);
  btn._t = setTimeout(() => { btn.textContent = label;
                              btn.classList.remove('ok'); }, 1600);
}

$('#copy').onclick = () =>
  copyBtn($('#copy'), S ? S.snippet : '', 'Copy command');
$('#copylink').onclick = () =>
  copyBtn($('#copylink'), S ? S.dropUrl : '', 'Copy link');

function listen(){
  const es = new EventSource('/api/events?k=' + encodeURIComponent(K));
  es.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.kind === 'log') addLog(msg.data);
    else if (msg.kind === 'state'){
      const focused = document.activeElement;
      const keep = focused && focused.dataset && focused.dataset.key;
      const mine = {};
      if (keep) mine[keep] = focused.value;
      S = Object.assign(msg.data, mine);
      render();
    } else if (msg.kind === 'bye') { es.close(); $('#offline').hidden = false; }
  };
  es.onopen = () => { $('#offline').hidden = true; };
  es.onerror = () => { $('#offline').hidden = false; };
}

(async function start(){
  try { S = await api('/api/state'); }
  catch (e) {
    document.body.innerHTML = '<div class="wrap"><div class="err">This page needs the '
      + 'link printed in the terminal (it carries a one-time key).</div></div>';
    return;
  }
  modeCards(); render();
  (S.log || []).forEach(addLog);
  listen();
})();
</script></body></html>
"""


# --------------------------------------------------------------------------
# the drop page - served over the tunnel, this is what the sender sees
# --------------------------------------------------------------------------

DROP_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EasyDrop</title>
<meta name="referrer" content="no-referrer">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%232563eb'/><path d='M16 6v13m0 0l-5-5m5 5l5-5M8 25h16' stroke='white' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>">
<style>
:root{
  --bg:#f4f6fb; --card:#fff; --line:#e3e8f0; --ink:#0f172a; --mute:#5b6577;
  --faint:#94a0b3; --accent:#2563eb; --accent-ink:#fff; --accent-soft:#e8eefc;
  --good:#059669; --bad:#dc2626; --track:#e8ecf4;
  --radius:12px; --shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0a0f1d; --card:#121a2c; --line:#22304a; --ink:#e8edf7; --mute:#9aa8bf;
    --faint:#6b7a93; --accent:#4f83f1; --accent-soft:#1a2743; --good:#34d399;
    --bad:#f87171; --track:#1b2740; --shadow:none;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:720px;margin:0 auto;padding:34px 22px 48px}
/* the wordmark is art, so the real heading is left for screen readers only */
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);
  white-space:nowrap}
pre.mark{margin:0;color:var(--accent);font-family:ui-monospace,SFMono-Regular,
  Menlo,Consolas,monospace;font-size:clamp(4px,1.35vw,10px);line-height:1.12;
  font-weight:600}
.tag{color:var(--mute);font-size:13px;margin-top:8px}
header{margin-bottom:20px}
/* inline-block so the parent centres the art as one unit - centring a <pre>
   line by line would stagger it */
pre.target{display:inline-block;text-align:left;margin:0 0 14px;
  color:var(--accent);line-height:1.18;font-weight:600;opacity:.85;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:12px;transition:opacity .12s,transform .12s}
#zone.over pre.target{opacity:1;transform:translateY(2px)}

.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);padding:18px 20px;margin-bottom:14px}

#zone{border:2px dashed var(--line);border-radius:var(--radius);background:var(--card);
  padding:38px 22px;text-align:center;transition:border-color .12s,background .12s;
  margin-bottom:14px}
#zone.over{border-color:var(--accent);background:var(--accent-soft)}
#zone .big{font-size:17px;font-weight:600;margin-bottom:4px}
#zone .sub{color:var(--mute);font-size:13px}
#zone svg{color:var(--accent);margin-bottom:10px}
.picks{display:flex;gap:9px;justify-content:center;margin-top:16px;flex-wrap:wrap}

.btn{border:1px solid transparent;border-radius:9px;padding:8px 16px;font:inherit;
  font-size:13.5px;font-weight:550;cursor:pointer;background:var(--accent);
  color:var(--accent-ink);transition:background .12s,transform .04s}
.btn:hover{filter:brightness(1.07)} .btn:active{transform:translateY(1px)}
.btn.ghost{background:var(--card);color:var(--ink);border-color:var(--line)}
.btn.ghost:hover{background:var(--accent-soft)}
.btn[disabled]{opacity:.45;cursor:not-allowed;filter:none}
input[type=file]{display:none}

.head{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.head h2{margin:0;font-size:15px;font-weight:600}
.head .sub{color:var(--mute);font-size:12.5px;margin-left:auto}

#rows{max-height:320px;overflow:auto;margin:0 -6px}
.row{display:grid;grid-template-columns:1fr auto;gap:3px 12px;padding:7px 6px;
  border-radius:8px;align-items:center}
.row .nm{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-family:ui-monospace,Menlo,Consolas,monospace}
.row .sz{color:var(--faint);font-size:12px;font-variant-numeric:tabular-nums;
  white-space:nowrap}
.row .bar{grid-column:1/-1;height:4px;border-radius:3px;background:var(--track);
  overflow:hidden}
.row .bar i{display:block;height:100%;width:0;background:var(--accent);
  transition:width .15s linear}
.row.done .bar i{background:var(--good)}
.row.bad .sz{color:var(--bad)} .row.bad .bar i{background:var(--bad)}

.total{display:flex;align-items:center;gap:12px;margin-top:14px;flex-wrap:wrap}
.total .bar{flex:1;min-width:160px;height:7px;border-radius:4px;background:var(--track);
  overflow:hidden}
.total .bar i{display:block;height:100%;width:0;background:var(--accent);
  transition:width .15s linear}
.total .txt{color:var(--mute);font-size:12.5px;font-variant-numeric:tabular-nums}
.note{color:var(--faint);font-size:12.5px;margin-top:14px}
.done-msg{background:var(--good);color:#fff;padding:11px 15px;border-radius:9px;
  margin-bottom:14px;font-weight:550}
.err{background:var(--bad);color:#fff;padding:11px 15px;border-radius:9px;
  margin-bottom:14px}

.wm{display:flex;align-items:center;gap:10px;justify-content:center;
  margin-top:26px;padding-top:16px;border-top:1px solid var(--line);
  font-size:12px;color:var(--faint)}
.wm-mark{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:700;
  letter-spacing:.04em;color:var(--mute)}
.wm a{color:var(--faint);text-decoration:none}
.wm a:hover{color:var(--accent);text-decoration:underline}
[hidden]{display:none !important}
</style></head><body>
<div class="wrap">
  <header>
    <h1 class="sr">EasyDrop</h1>
    <pre class="mark" aria-hidden="true"> _____                      ____
| ____|  __ _  ___   _   _ |  _ \  _ __   ___   _ __
|  _|   / _` |/ __| | | | || | | || '__| / _ \ | '_ \
| |___ | (_| |\__ \ | |_| || |_| || |   | (_) || |_) |
|_____| \__,_||___/  \__, ||____/ |_|    \___/ | .__/
                     |___/                     |_|</pre>
    <div class="tag">drop files here and they land on the other machine</div>
  </header>

  <div id="fail" class="err" hidden></div>
  <div id="ok" class="done-msg" hidden></div>

  <div id="zone">
    <pre class="target" aria-hidden="true">       ___
      |   |
      |   |
   ___|   |___
   \         /
    \       /
     \     /
      \___/

|             |
|             |
|_____________|</pre>
    <div class="big">Drop files or folders here</div>
    <div class="sub">or pick them below &mdash; folders keep their structure</div>
    <div class="picks">
      <button class="btn" id="pickFiles">Choose files</button>
      <button class="btn ghost" id="pickDir">Choose a folder</button>
    </div>
    <input type="file" id="fileIn" multiple>
    <input type="file" id="dirIn" webkitdirectory directory multiple>
  </div>

  <section class="card" id="list" hidden>
    <div class="head">
      <h2 id="listTitle">Queue</h2>
      <span class="sub" id="listSub"></span>
    </div>
    <div id="rows"></div>
    <div class="total">
      <div class="bar"><i id="allBar"></i></div>
      <span class="txt" id="allTxt"></span>
      <button class="btn ghost" id="cancel" hidden>Cancel</button>
    </div>
  </section>

  <div class="note" id="note"></div>

  <footer class="wm">
    <span class="wm-mark">easycp</span>
    <a href="https://github.com/roninimous/easycp" target="_blank"
       rel="noopener noreferrer">github.com/roninimous/easycp</a>
  </footer>
</div>
<script>
const KEY = new URLSearchParams(location.search).get('k') || '';
const $ = s => document.querySelector(s);
const MB = 1024 * 1024;
let CHUNK = 0;          // MB per request, 0 = send whole files
let items = [], busy = false, cancelled = false, live = null;

const human = n => {
  const u = ['B','KB','MB','GB']; let i = 0;
  while (n >= 1024 && i < 3) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : Math.round(n)) + u[i];
};
const b64 = s => btoa(String.fromCharCode.apply(null, new TextEncoder().encode(s)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

fetch('/drop/config', {headers: {'X-Token': KEY}})
  .then(r => r.ok ? r.json() : null)
  .then(c => {
    if (!c) return;
    CHUNK = c.chunkMb || 0;
    $('#note').textContent = 'Uploads land in the ' + c.dest +
      ' folder on the receiving machine.' +
      (CHUNK ? ' Large files are sent in ' + CHUNK + 'MB pieces.' : '');
  })
  .catch(() => {});

/* ---- collecting ------------------------------------------------------- */
// A dropped folder arrives as a tree of entries that has to be walked; the
// items list must be read synchronously in the drop handler, before any await.
async function walk(entry, prefix, out) {
  if (entry.isFile) {
    const f = await new Promise((res, rej) => entry.file(res, rej));
    out.push({file: f, path: prefix + entry.name});
  } else if (entry.isDirectory) {
    const rd = entry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => rd.readEntries(res, rej));
      if (!batch.length) break;                 // readEntries caps at ~100
      for (const e of batch) await walk(e, prefix + entry.name + '/', out);
    }
  }
}

const zone = $('#zone');
['dragenter', 'dragover'].forEach(ev => zone.addEventListener(ev, e => {
  e.preventDefault(); zone.classList.add('over');
}));
['dragleave', 'drop'].forEach(ev => zone.addEventListener(ev, e => {
  e.preventDefault();
  if (ev === 'drop' || e.target === zone) zone.classList.remove('over');
}));
zone.addEventListener('drop', async e => {
  const entries = [];
  for (const it of e.dataTransfer.items || []) {
    const en = it.webkitGetAsEntry && it.webkitGetAsEntry();
    if (en) entries.push(en);
  }
  const out = [];
  if (entries.length) {
    for (const en of entries) await walk(en, '', out);
  } else {
    for (const f of e.dataTransfer.files || []) out.push({file: f, path: f.name});
  }
  add(out);
});

$('#pickFiles').onclick = () => $('#fileIn').click();
$('#pickDir').onclick = () => $('#dirIn').click();
$('#fileIn').onchange = e => add([...e.target.files].map(f => ({file: f, path: f.name})));
$('#dirIn').onchange = e => add([...e.target.files].map(
  f => ({file: f, path: f.webkitRelativePath || f.name})));

/* ---- queue + rendering ------------------------------------------------ */
function add(found) {
  if (!found.length || busy) return;
  $('#ok').hidden = true; $('#fail').hidden = true;
  items = found.map(f => ({file: f.file, path: f.path, sent: 0, state: ''}));
  $('#rows').textContent = '';
  for (const it of items) {
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = '<div class="nm"></div><div class="sz"></div>' +
                    '<div class="bar"><i></i></div>';
    row.querySelector('.nm').textContent = it.path;
    row.querySelector('.sz').textContent = human(it.file.size);
    it.row = row; it.fill = row.querySelector('.bar i');
    it.note = row.querySelector('.sz');
    $('#rows').append(row);
  }
  const bytes = items.reduce((n, i) => n + i.file.size, 0);
  $('#list').hidden = false;
  $('#listTitle').textContent = items.length + (items.length === 1 ? ' file' : ' files');
  $('#listSub').textContent = human(bytes);
  send();
}

let frame = null;
function paint() {
  if (frame) return;
  frame = requestAnimationFrame(() => {
    frame = null;
    let sent = 0, total = 0;
    for (const it of items) {
      sent += it.sent; total += it.file.size;
      const pct = it.file.size ? (it.sent / it.file.size) * 100 : (it.state ? 100 : 0);
      it.fill.style.width = (it.state === 'done' ? 100 : pct) + '%';
    }
    $('#allBar').style.width = (total ? (sent / total) * 100 : 0) + '%';
    const secs = (Date.now() - start) / 1000;
    $('#allTxt').textContent = human(sent) + ' of ' + human(total) +
      (busy && secs > 0.6 ? '  ·  ' + human(sent / secs) + '/s' : '');
  });
}

/* ---- uploading -------------------------------------------------------- */
let start = Date.now();

function api(path, body) {
  return fetch(path, {
    method: 'POST',
    headers: {'X-Token': KEY, 'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(r => {
    if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
    return r.json();
  });
}

function put(id, it, blob, part, parts, offset) {
  return new Promise((res, rej) => {
    const x = new XMLHttpRequest();
    live = x;
    x.open('PUT', '/drop/put');
    x.setRequestHeader('X-Token', KEY);
    x.setRequestHeader('X-Drop', id);
    x.setRequestHeader('X-Path', b64(it.rel));
    x.setRequestHeader('X-Part', part);
    x.setRequestHeader('X-Parts', parts);
    x.setRequestHeader('X-Offset', offset);
    x.upload.onprogress = e => { it.sent = offset + e.loaded; paint(); };
    x.onload = () => x.status === 200
      ? res()
      : rej(new Error(x.status + ' ' + (x.responseText || '').trim()));
    x.onerror = () => rej(new Error('the connection dropped'));
    x.onabort = () => rej(new Error('cancelled'));
    x.send(blob);
  });
}

async function putFile(id, it) {
  const size = it.file.size, cut = CHUNK * MB;
  const parts = (cut && size > cut) ? Math.ceil(size / cut) : 1;
  for (let attempt = 0; ; attempt++) {
    try {
      let off = 0;
      for (let i = 0; i < parts; i++) {
        if (cancelled) throw new Error('cancelled');
        const blob = parts === 1 ? it.file : it.file.slice(off, Math.min(off + cut, size));
        await put(id, it, blob, i, parts, off);
        off += blob.size;
        it.sent = off; paint();
      }
      return;
    } catch (e) {
      // a failed slice leaves a half-written part, so retry the whole file:
      // part 0 is what tells the receiver to start the file over
      if (cancelled || attempt >= 2) throw e;
      it.sent = 0; it.note.textContent = 'retrying ...'; paint();
      await new Promise(r => setTimeout(r, 700 * (attempt + 1)));
    }
  }
}

// Each top-level folder is its own batch, so the receiver can reserve one
// destination for it up front; everything loose goes in a batch together.
function batches() {
  const byRoot = new Map(), loose = [];
  for (const it of items) {
    const cut = it.path.indexOf('/');
    if (cut > 0) {
      const root = it.path.slice(0, cut);
      it.rel = it.path.slice(cut + 1);
      if (!byRoot.has(root)) byRoot.set(root, []);
      byRoot.get(root).push(it);
    } else {
      it.rel = it.path;
      loose.push(it);
    }
  }
  const out = [...byRoot].map(([root, list]) => ({root, list}));
  if (loose.length) out.push({root: '', list: loose});
  return out;
}

async function send() {
  busy = true; cancelled = false; start = Date.now();
  $('#cancel').hidden = false;
  let files = 0, bytes = 0;
  try {
    for (const b of batches()) {
      const size = b.list.reduce((n, i) => n + i.file.size, 0);
      const {id} = await api('/drop/begin',
                             {root: b.root, files: b.list.length, bytes: size});
      try {
        for (const it of b.list) {
          await putFile(id, it);
          it.state = 'done'; it.row.classList.add('done');
          it.note.textContent = human(it.file.size);
          files++; bytes += it.file.size;
          paint();
        }
      } finally {
        await api('/drop/end', {id}).catch(() => {});
      }
    }
    $('#ok').hidden = false;
    $('#ok').textContent = 'Sent ' + files + (files === 1 ? ' file' : ' files') +
                           '  ·  ' + human(bytes);
  } catch (e) {
    const it = items.find(i => i.state !== 'done');
    if (it) { it.row.classList.add('bad'); it.note.textContent = 'failed'; }
    $('#fail').hidden = false;
    $('#fail').textContent = cancelled
      ? 'Cancelled. ' + files + ' of ' + items.length + ' files had already been sent.'
      : 'Upload stopped: ' + e.message + ' — ' + files + ' of ' + items.length +
        ' files got through. Try the rest again.';
  } finally {
    busy = false; live = null;
    $('#cancel').hidden = true;
    paint();
  }
}

$('#cancel').onclick = () => {
  cancelled = true;
  if (live) live.abort();
};
window.addEventListener('beforeunload', e => {
  if (busy) { e.preventDefault(); e.returnValue = ''; }
});
</script></body></html>
"""


# --------------------------------------------------------------------------
# control server - local only, this is what the browser talks to
# --------------------------------------------------------------------------

UI_TOKEN = secrets.token_urlsafe(12)
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class Control(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "easycp-UI/1.0"
    app = None                      # set once, before the server starts

    def log_message(self, *args):
        pass

    # -- guards ----------------------------------------------------------
    def _local(self):
        """Only this machine, and no cross-origin page driving the API."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in LOCAL_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin:
            try:
                if urlparse(origin).hostname not in LOCAL_HOSTS:
                    return False
            except Exception:
                return False
        return True

    def _authed(self):
        given = self.headers.get("X-UI-Token", "")
        if not given:
            given = parse_qs(urlparse(self.path).query).get("k", [""])[0]
        return secrets.compare_digest(given, UI_TOKEN)

    # -- replies ---------------------------------------------------------
    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode(), "application/json")

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if not self._local():
            return self._send(403, b"local requests only\n")
        path = urlparse(self.path).path
        if path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if not self._authed():
            return self._send(403, b"bad or missing key\n")
        if path == "/api/state":
            state = self.app.as_dict()
            state["log"] = [{"line": l, "cls": log_class(l.partition("] ")[2])}
                            for l in LOG_HISTORY[-300:]]
            return self._json(state)
        if path == "/api/events":
            return self._stream()
        self._send(404, b"not here\n")

    def do_POST(self):
        if not self._local():
            return self._send(403, b"local requests only\n")
        if not self._authed():
            return self._send(403, b"bad or missing key\n")
        path = urlparse(self.path).path
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        app = self.app

        if path == "/api/connect":
            app.apply_async(**{k: body.get(k) for k in
                               ("mode", "hostname", "tunnel_name",
                                "tunnel_token", "url")})
            return self._json({"ok": True})
        if path == "/api/exclude":
            app.set_exclude(body.get("exclude", ""))
            return self._json({"ok": True})
        if path == "/api/login":
            app.login_async()
            return self._json({"ok": True})
        if path == "/api/open":
            open_folder(DEST)
            log(f"opened {tilde(DEST)}")
            return self._json({"ok": True})
        if path == "/api/quit":
            self._json({"ok": True})
            threading.Thread(target=shutdown, daemon=True).start()
            return
        self._send(404, b"not here\n")

    # -- live log --------------------------------------------------------
    def _stream(self):
        q = BUS.subscribe()
        self.close_connection = True        # SSE runs until the tab goes away
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b": open\n\n")
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15)
                    self.wfile.write(b"data: " + msg.encode() + b"\n\n")
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")     # keep the tab attached
                self.wfile.flush()
        except Exception:
            pass                                        # tab closed - that's all
        finally:
            BUS.unsubscribe(q)


def shutdown():
    BUS.publish("bye", {})
    time.sleep(0.2)
    log("shutting down")
    stop_tunnel()
    os._exit(0)


def start_control(app, ui_port):
    """Bind the browser UI to loopback only - the tunnel must never see it."""
    Control.app = app
    srv = ThreadingHTTPServer(("127.0.0.1", ui_port), Control)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def open_folder(path):
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif os.name == "nt":
        os.startfile(str(path))  # noqa
    else:
        subprocess.Popen(["xdg-open", str(path)])


# --------------------------------------------------------------------------
# terminal mode
# --------------------------------------------------------------------------

ANSI = {"ok": "\033[32m", "warn": "\033[33m", "bad": "\033[31m",
        "dim": "\033[90m", "msg": ""}
DIM, BOLD, OFF = "\033[90m", "\033[1m", "\033[0m"
TTY = sys.stdout.isatty()


def paint(text, code):
    return f"{code}{text}{OFF}" if TTY and code else text


def term_sink(line):
    stamp, _, msg = line.partition("] ")
    if not msg:
        print(line)
        return
    print(paint(stamp + "]", DIM) + " " + paint(msg, ANSI[log_class(msg)]))


def copy_to_clipboard(text):
    if sys.platform == "darwin":
        tries = [["pbcopy"]]
    elif os.name == "nt":
        tries = [["clip"]]
    else:
        tries = [["wl-copy"], ["xclip", "-selection", "clipboard"],
                 ["xsel", "--clipboard", "--input"]]
    # clip.exe decodes stdin with the console code page unless it sees a
    # UTF-16LE BOM, which would mangle a non-ASCII exclude pattern. The
    # utf-16 codec writes that BOM for us; Windows is always little-endian.
    data = text.encode("utf-16" if os.name == "nt" else "utf-8")
    for cmd in tries:
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(cmd, input=data, check=True)
            return True
        except Exception:
            pass
    return False


HELP = """
  commands

    show                  print the paste-me command again
    copy                  copy it to the clipboard
    link                  print the browser upload link (no shell needed)
    copylink              copy that link instead
    status                where files land, what is listening, what is skipped
    log [n]               replay the last n log lines (default 20)

    mode <name>           %s
    hostname <host>       domain for `mode domain` / `mode token`
    name <name>           cloudflared tunnel name (default dropzone)
    token <token>         tunnel token for `mode token`
    url <base-url>        base URL for `mode url`
    exclude <patterns>    what `send` never uploads ('exclude -' clears it)
    apply                 bring the chosen mode up and reprint the command
    login                 authorise cloudflared for `mode domain`

    dest [path]           show or change where files land
    open                  open that folder in the file manager
    quit                  stop easycp
""" % " | ".join(MODE_IDS)


REPO = "github.com/roninimous/easycp"

LOGO = r"""
    ___   __ _  ___   _   _   ___  _ __
   / _ \ / _` |/ __| | | | | / __|| '_ \
  |  __/| (_| |\__ \ | |_| || (__ | |_) |
   \___| \__,_||___/  \__, | \___|| .__/
                      |___/       |_|
"""


def banner(app):
    out = [paint(LOGO, BOLD)]
    out.append(f"  saving to   {tilde(DEST)}")
    out.append(f"  listening   {app.base}")
    if app.chunk:
        out.append(f"  splitting   {app.chunk}MB per request (proxy body limit)")
    out.append(f"  skipping    {app.exclude or '(nothing)'}")
    out.append("")
    out.append("  1. paste this into your VPS shell:")
    out.append("")
    out.append("     " + app.snippet())
    out.append("")
    out.append("  2. then:  " + paint("peek /path", BOLD) + "  to preview,  "
               + paint("send /path", BOLD) + "  to copy it here")
    out.append("")
    out.append("  no shell on the other end? send them this link instead:")
    out.append("")
    out.append("     " + app.drop_url())
    out.append("")
    out.append(paint("  type `help` for commands, `quit` to stop", DIM))
    out.append(paint(f"  {REPO}", DIM))
    out.append("")
    return "\n".join(out)


def repl(app):
    """--headless: everything the browser UI does, driven from the prompt."""
    print(banner(app))
    prompt = paint("dz>", BOLD) + " "
    while True:
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not raw:
            continue
        cmd, _, rest = raw.partition(" ")
        cmd, rest = cmd.lower(), rest.strip()

        if cmd in ("help", "h", "?"):
            print(HELP)
        elif cmd in ("quit", "exit", "q"):
            break
        elif cmd == "show":
            print("\n     " + app.snippet() + "\n")
        elif cmd in ("copy", "c"):
            if copy_to_clipboard(app.snippet()):
                print("  copied to the clipboard")
            else:
                print("  no clipboard tool found - here it is:\n")
                print("     " + app.snippet() + "\n")
        elif cmd == "link":
            print("\n     " + app.drop_url() + "\n")
        elif cmd == "copylink":
            if copy_to_clipboard(app.drop_url()):
                print("  copied to the clipboard")
            else:
                print("  no clipboard tool found - here it is:\n")
                print("     " + app.drop_url() + "\n")
        elif cmd in ("status", "st"):
            print(f"  mode        {mode_info(app.mode)['name']}")
            print(f"  listening   {app.base}   ({app.status})")
            print(f"  drop page   {app.drop_url()}")
            print(f"  saving to   {tilde(DEST)}")
            print(f"  splitting   {str(app.chunk) + 'MB per request' if app.chunk else 'off'}")
            print(f"  skipping    {app.exclude or '(nothing)'}")
        elif cmd == "log":
            n = int(rest) if rest.isdigit() else 20
            for line in LOG_HISTORY[-n:]:
                term_sink(line)
        elif cmd == "mode":
            if rest in MODE_IDS:
                app.update(mode=rest)
                need = mode_info(rest)["fields"]
                print(f"  mode set to {mode_info(rest)['name']}")
                print(f"  {mode_info(rest)['hint'].replace('{port}', str(app.port))}")
                if need:
                    print("  needs: " + ", ".join(FIELD_LABELS[f].lower() for f in need))
                print("  run `apply` to bring it up")
            else:
                print("  pick one of: " + " | ".join(MODE_IDS))
        elif cmd in ("hostname", "host"):
            app.update(hostname=rest)
            print(f"  hostname = {app.hostname or '(none)'}")
        elif cmd == "name":
            app.update(tunnel_name=rest)
            print(f"  tunnel name = {app.tunnel_name}")
        elif cmd == "token":
            app.update(tunnel_token=rest)
            print(f"  tunnel token = {'set' if app.tunnel_token else '(none)'}")
        elif cmd == "url":
            app.update(url=rest)
            print(f"  base url = {app.url or '(none)'}")
        elif cmd in ("exclude", "skip"):
            app.set_exclude("" if rest == "-" else rest)
            print(f"  skipping {app.exclude or '(nothing)'}")
            print("\n     " + app.snippet() + "\n")
        elif cmd in ("apply", "go", "connect"):
            ok, msg = app.apply()
            print(("  " + msg) if ok else paint("  " + msg, ANSI["bad"]))
            print("\n     " + app.snippet() + "\n")
        elif cmd == "login":
            done = threading.Event()

            def finished(ok, msg):
                print(("  " + msg) if ok else paint("  " + msg, ANSI["bad"]))
                done.set()
            cf_login(finished)
            print("  a browser window should open - waiting ...")
            done.wait()
        elif cmd == "dest":
            if rest:
                set_dest(Path(rest).expanduser())
                app.push()
            print(f"  saving to {tilde(DEST)}")
        elif cmd == "open":
            open_folder(DEST)
            print(f"  opened {tilde(DEST)}")
        else:
            print(f"  no such command: {cmd}   (try `help`)")

    print("  stopping ...")
    stop_tunnel()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def set_dest(path):
    global DEST
    DEST = path
    DEST.mkdir(parents=True, exist_ok=True)
    log(f"saving to {tilde(DEST)}")


def main():
    global DEST, AUTO_EXTRACT

    ap = argparse.ArgumentParser(description="Receive files from a remote box.")
    cfg = load_config()

    ap.add_argument("--port", type=int, default=8765, help="upload listen port")
    ap.add_argument("--dest", default=str(DEST), help="where received files land")
    ap.add_argument("--tunnel", choices=["auto", "quick", "domain", "token", "off"],
                    default="auto",
                    help="auto = saved setting, else a quick tunnel")
    ap.add_argument("--hostname", default=cfg.get("hostname", ""),
                    help="your domain, e.g. drop.example.com (domain/token modes)")
    ap.add_argument("--tunnel-name", default=cfg.get("tunnel_name", "dropzone"),
                    help="cloudflared tunnel name for --tunnel domain")
    ap.add_argument("--tunnel-token", default=cfg.get("tunnel_token", ""),
                    help="tunnel token from the Cloudflare Zero Trust dashboard")
    ap.add_argument("--url", help="override the public base URL shown in the snippet")
    ap.add_argument("--chunk-mb", default="auto",
                    help="split uploads into N-MB requests; 'auto' = 90 behind "
                         "Cloudflare (100MB proxy cap), 0 = never split")
    ap.add_argument("--exclude", default=cfg.get("exclude", DEFAULT_EXCLUDE),
                    help="space-separated patterns `send` never uploads "
                         f"(default: {DEFAULT_EXCLUDE!r}; '' sends everything)")
    ap.add_argument("--no-extract", action="store_true", help="keep .tgz archives as-is")
    ap.add_argument("--headless", action="store_true",
                    help="drive everything from this terminal, no browser UI")
    ap.add_argument("--ui-port", type=int, default=0,
                    help="port for the local browser UI (default: pick a free one)")
    ap.add_argument("--no-browser", action="store_true",
                    help="start the browser UI but do not open a window")
    args = ap.parse_args()

    DEST = Path(args.dest).expanduser()
    AUTO_EXTRACT = not args.no_extract
    DEST.mkdir(parents=True, exist_ok=True)

    LOG_SINKS.append(term_sink)
    LOG_SINKS.append(lambda line: BUS.publish(
        "log", {"line": line, "cls": log_class(line.partition("] ")[2])}))

    try:
        srv = ThreadingHTTPServer(("0.0.0.0", args.port), Receiver)
    except OSError as e:
        sys.exit(f"cannot listen on port {args.port}: {e}\n"
                 f"another easycp may already be running - try --port {args.port + 1}")
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    if args.url:
        mode = "url"
    elif args.tunnel == "auto":
        mode = cfg.get("mode", "quick")
    elif args.tunnel == "off":
        mode = "direct"
    else:
        mode = args.tunnel

    app = App(args.port, {**cfg, "mode": mode, "hostname": args.hostname,
                          "tunnel_name": args.tunnel_name,
                          "tunnel_token": args.tunnel_token,
                          "url": args.url or "", "exclude": args.exclude},
              args.chunk_mb)

    log(f"saving to {tilde(DEST)}")
    app.apply()

    if args.headless:
        if sys.stdin.isatty():
            repl(app)
        else:
            # piped or nohup'd: there is nobody to prompt, so just keep running
            print(banner(app))
            print("  no terminal attached - running until stopped\n")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                stop_tunnel()
        return

    ui_port = start_control(app, args.ui_port)
    ui_url = f"http://127.0.0.1:{ui_port}/?k={UI_TOKEN}"
    print()
    print(paint(LOGO, BOLD))
    print(f"  control panel at {ui_url}")
    print(paint(f"  {REPO}", DIM))
    print(f"  saving to   {tilde(DEST)}")
    print(f"  listening   {app.base}")
    print(f"  drop page   {app.drop_url()}")
    print(paint("  ctrl-c here, or Quit in the browser, to stop", DIM))
    print()
    if not args.no_browser:
        try:
            webbrowser.open(ui_url)
        except Exception as e:
            log(f"could not open a browser ({e}) - use the link above")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        stop_tunnel()


if __name__ == "__main__":
    main()
