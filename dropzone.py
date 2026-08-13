#!/usr/bin/env python3
"""
DropZone - pull files off a remote box with one pasted command.

Run this on YOUR machine (mac / windows / linux). It starts a tiny
authenticated receiver, works out a reachable URL, and shows you a one-line
shell snippet. Paste that snippet into any VPS shell, then run:

    peek /var/www/html                  # list what would go, upload nothing
    send /var/www/html
    send /etc/nginx/nginx.conf notes.txt

...and the files land in your DropZone folder. No SSH keys, no scp syntax.

`.git`, `node_modules` and `.env` are skipped by default - edit "Never send"
in the GUI, pass --exclude, or override per call on the remote box:

    DZ_EXCLUDE=".git" send /var/www/html     # keep .env this time
    DZ_EXCLUDE= send /var/www/html           # send absolutely everything

    python3 dropzone.py                 # GUI
    python3 dropzone.py --headless      # terminal only
    python3 dropzone.py --tunnel off    # LAN / Tailscale / port-forward only

Want a stable address instead of a random trycloudflare.com one? Point a
domain you own at DropZone:

    python3 dropzone.py --tunnel domain --hostname drop.example.com
    python3 dropzone.py --tunnel token  --hostname drop.example.com \\
                        --tunnel-token eyJhIjoi...

The GUI has a Connection panel that does the same thing without flags.
"""

import argparse
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
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

# Tk on macOS is the deprecated system build; the warning is noise to our users.
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

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


def log(msg):
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    LOG_HISTORY.append(line)
    del LOG_HISTORY[:-500]
    for sink in LOG_SINKS:
        try:
            sink(line)
        except Exception:
            pass


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


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


# --------------------------------------------------------------------------
# receiver
# --------------------------------------------------------------------------

class Receiver(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DropZone/1.0"

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

    def _reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

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

    def _recv_body(self, dest_path):
        """Stream the request body to dest_path. Returns bytes written."""
        tmp = dest_path.with_name(dest_path.name + ".part")
        try:
            with open(tmp, "wb") as f:
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    n = self._read_chunked(f)
                else:
                    n = self._read_sized(f, int(self.headers.get("Content-Length", 0)))
            tmp.replace(dest_path)
            return n
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    def do_PUT(self):
        if not self._authed():
            return self._reply(401, b"bad token\n")

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
            log(f"got {base} part {int(idx) + 1}/{total}  {human(n)}")
            if len(have) >= total:
                self._assemble(pdir, base, have)
            return self._reply(200, b"ok\n")

        # ---- single-shot upload --------------------------------------
        target = unique_path(DEST / name)
        log(f"receiving {target.name} ...")
        try:
            n = self._recv_body(target)
        except Exception as e:
            log(f"FAILED {target.name}: {e}")
            return self._reply(500, b"failed\n")

        secs = max(time.time() - start, 0.001)
        log(f"got {target.name}  {human(n)}  ({human(n / secs)}/s)")

        if AUTO_EXTRACT and target.name.endswith((".tgz", ".tar.gz")):
            self._extract(target)
        return self._reply(200, b"ok\n")

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
            suffix = "/" if final.is_dir() else ""
            log(f"unpacked -> {final.name}{suffix}")
        except Exception as e:
            shutil.rmtree(staging, ignore_errors=True)
            log(f"kept archive (extract failed: {e})")

    def do_GET(self):
        self._reply(200, b"DropZone is listening.\n")


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


def connect(port, mode, hostname="", name="dropzone", token="", url=""):
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
# gui
# --------------------------------------------------------------------------

MODES = [
    ("quick",  "Cloudflare quick tunnel  (random URL, no account)"),
    ("domain", "My domain via Cloudflare  (needs a Cloudflare account)"),
    ("token",  "Cloudflare tunnel token  (from the Zero Trust dashboard)"),
    ("direct", "Direct / LAN  (no tunnel)"),
    ("url",    "Custom URL  (your own proxy or port-forward)"),
]
MODE_LABELS = [label for _, label in MODES]
LABEL_TO_MODE = {label: mode for mode, label in MODES}
MODE_TO_LABEL = dict(MODES)


def run_gui(base_url, chunk_mb, port, cfg, chunk_override="auto", note=""):
    # Classic tk widgets only: Apple's deprecated system Tk 8.5 draws ttk
    # widgets as an empty window on current macOS.
    import tkinter as tk
    from tkinter import scrolledtext

    root = tk.Tk()
    root.title("DropZone")
    root.geometry("760x680")
    root.minsize(660, 560)

    state = {"base": base_url, "chunk": chunk_mb, "cmd": snippet(base_url, chunk_mb)}

    # -- 1. connection ---------------------------------------------------
    conn = tk.LabelFrame(root, text=" Connection ", padx=4, pady=4)
    conn.pack(fill="x", padx=14, pady=(12, 0))
    conn.columnconfigure(1, weight=1)

    mode_var = tk.StringVar(value=MODE_TO_LABEL.get(cfg.get("mode", "quick"),
                                                    MODE_TO_LABEL["quick"]))
    host_var = tk.StringVar(value=cfg.get("hostname", ""))
    name_var = tk.StringVar(value=cfg.get("tunnel_name", "dropzone"))
    token_var = tk.StringVar(value=cfg.get("tunnel_token", ""))
    url_var = tk.StringVar(value=cfg.get("url", ""))
    conn_status = tk.StringVar()

    tk.Label(conn, text="Mode").grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))
    picker = tk.OptionMenu(conn, mode_var, *MODE_LABELS)
    picker.configure(anchor="w", highlightthickness=0)
    picker.grid(row=0, column=1, sticky="ew", padx=10, pady=(8, 4))

    def field(row, text, var, show=None):
        lab = tk.Label(conn, text=text)
        ent = tk.Entry(conn, textvariable=var, show=show,
                       relief="solid", bd=1, highlightthickness=0)
        lab.grid(row=row, column=0, sticky="w", padx=10, pady=3)
        ent.grid(row=row, column=1, sticky="ew", padx=10, pady=3, ipady=3)
        return lab, ent

    host_row = field(1, "Hostname", host_var)
    name_row = field(2, "Tunnel name", name_var)
    token_row = field(3, "Tunnel token", token_var, show="*")
    url_row = field(4, "Base URL", url_var)

    hint = tk.Label(conn, text="", fg="#666", wraplength=690,
                    justify="left", anchor="w")
    hint.grid(row=5, column=0, columnspan=2, sticky="ew", padx=10, pady=(6, 0))

    btns = tk.Frame(conn)
    btns.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10, pady=(8, 6))
    apply_btn = tk.Button(btns, text="Apply", width=10)
    apply_btn.pack(side="left")
    login_btn = tk.Button(btns, text="Log in to Cloudflare", width=18)
    login_btn.pack(side="left", padx=8)
    tk.Label(btns, textvariable=conn_status, fg="#666", anchor="w").pack(side="left", padx=6)

    HINTS = {
        "quick": "A throwaway https URL from Cloudflare. Changes every run.",
        "domain": "Uses a domain already on your Cloudflare account. Log in once, "
                  "then DropZone creates the tunnel and the DNS record for you.",
        "token": "Create the tunnel at one.dash.cloudflare.com (Networks > Tunnels), "
                 "point its public hostname at http://127.0.0.1:%d, then paste the "
                 "token here." % port,
        "direct": "Reachable only from this network - LAN, Tailscale, or your own "
                  "port-forward. No 100MB request cap.",
        "url": "Already have DropZone reachable somewhere? Enter that base URL and "
               "DropZone will just print the matching command.",
    }

    def current_mode():
        return LABEL_TO_MODE.get(mode_var.get(), "quick")

    def refresh_fields(*_):
        mode = current_mode()
        for rows, modes in ((host_row, {"domain", "token"}),
                            (name_row, {"domain"}),
                            (token_row, {"token"}),
                            (url_row, {"url"})):
            for w in rows:
                w.grid() if mode in modes else w.grid_remove()
        hint.configure(text=HINTS[mode])
        login_btn.configure(state="normal" if mode == "domain" else "disabled")

    mode_var.trace_add("write", refresh_fields)
    refresh_fields()

    # -- 2. the snippet ---------------------------------------------------
    tk.Label(root, text="1.  Paste this into your VPS shell",
             font=("TkDefaultFont", 11, "bold"), anchor="w"
             ).pack(fill="x", padx=14, pady=(12, 0))

    skip = tk.Frame(root)
    skip.pack(fill="x", padx=14, pady=(4, 0))
    tk.Label(skip, text="Never send").pack(side="left")
    excl_var = tk.StringVar(value=cfg.get("exclude", DEFAULT_EXCLUDE))
    tk.Entry(skip, textvariable=excl_var, relief="solid", bd=1,
             highlightthickness=0).pack(side="left", fill="x", expand=True,
                                        padx=8, ipady=2)
    tk.Label(skip, text="space-separated, e.g.  .git node_modules .env",
             fg="#666").pack(side="left")

    box = tk.Text(root, height=6, wrap="word", font=("Courier", 10),
                  relief="solid", bd=1)
    box.insert("1.0", state["cmd"])
    box.configure(state="disabled")
    box.pack(fill="x", padx=14, pady=(4, 0))

    bar = tk.Frame(root)
    bar.pack(fill="x", padx=14, pady=8)
    status = tk.StringVar()

    def copy():
        root.clipboard_clear()
        root.clipboard_append(state["cmd"])
        status.set("copied to clipboard")

    tk.Button(bar, text="Copy command", command=copy, width=14).pack(side="left")
    tk.Button(bar, text="Open folder",
              command=lambda: open_folder(DEST), width=12).pack(side="left", padx=8)
    tk.Label(bar, textvariable=status, fg="#666").pack(side="left", padx=6)

    tk.Label(root, text="2.  Then:   peek /path   to list what would go, "
                        "then   send /path",
             font=("TkDefaultFont", 11, "bold"), anchor="w").pack(fill="x", padx=14)

    out = scrolledtext.ScrolledText(root, height=12, font=("Courier", 9),
                                    state="disabled", relief="solid", bd=1)
    out.pack(fill="both", expand=True, padx=14, pady=(6, 12))

    def sink(line):
        def append():
            out.configure(state="normal")
            out.insert("end", line + "\n")
            out.see("end")
            out.configure(state="disabled")
        root.after(0, append)

    # -- wiring -----------------------------------------------------------
    def show_snippet(base=None, chunk=None):
        base = state["base"] if base is None else base
        chunk = state["chunk"] if chunk is None else chunk
        state.update(base=base, chunk=chunk,
                     cmd=snippet(base, chunk, excl_var.get()))
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", state["cmd"])
        box.configure(state="disabled")
        note = f"  ·  split into {chunk}MB requests" if chunk else ""
        status.set(f"listening on {base}{note}")

    excl_var.trace_add("write", lambda *_: show_snippet())

    def apply():
        mode = current_mode()
        settings = dict(mode=mode, hostname=clean_host(host_var.get()),
                        tunnel_name=name_var.get().strip() or "dropzone",
                        tunnel_token=token_var.get().strip(),
                        url=url_var.get().strip(),
                        exclude=excl_var.get().strip())
        apply_btn.configure(state="disabled")
        conn_status.set("connecting ...")

        def work():
            try:
                base = connect(port, mode, settings["hostname"],
                               settings["tunnel_name"], settings["tunnel_token"],
                               settings["url"])
                chunk = chunk_for(mode, base, chunk_override)
                save_config(settings)
                root.after(0, lambda: (conn_status.set("connected"),
                                       host_var.set(settings["hostname"]),
                                       show_snippet(base, chunk),
                                       log(f"listening on {base}")))
            except TunnelError as e:
                # connect() already tore the old tunnel down, so the previous
                # URL is dead - show the address that actually still works.
                msg, fallback = str(e), f"http://{lan_ip()}:{port}"
                root.after(0, lambda: (
                    conn_status.set(f"{msg} - showing local address"),
                    log(f"connect failed: {msg}"),
                    show_snippet(fallback, chunk_for("direct", fallback, chunk_override))))
            finally:
                root.after(0, lambda: apply_btn.configure(state="normal"))

        threading.Thread(target=work, daemon=True).start()

    def login():
        login_btn.configure(state="disabled")
        conn_status.set("waiting for the browser ...")

        def done(ok, msg):
            root.after(0, lambda: (conn_status.set(msg),
                                   login_btn.configure(state="normal")))
        cf_login(done)

    apply_btn.configure(command=apply)
    login_btn.configure(command=login)

    for past in LOG_HISTORY:        # startup happens before this sink exists
        sink(past)
    LOG_SINKS.append(sink)
    show_snippet(base_url, chunk_mb)
    log(f"saving to {DEST}")
    log(f"listening on {base_url}")
    if note:
        conn_status.set(note)
    elif not cloudflared():
        conn_status.set(f"cloudflared not found - {INSTALL_HINT}")

    def quit_app():
        save_config({**cfg, "exclude": excl_var.get().strip()})
        stop_tunnel()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", quit_app)
    if sys.platform == "darwin":
        # system Tk 8.5 can paint an empty window until a relayout happens
        root.after(80, lambda: (root.geometry("761x681"), root.geometry("760x680"),
                                root.lift()))
    root.mainloop()


def open_folder(path):
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif os.name == "nt":
        os.startfile(str(path))  # noqa
    else:
        subprocess.Popen(["xdg-open", str(path)])


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    global DEST, AUTO_EXTRACT

    ap = argparse.ArgumentParser(description="Receive files from a remote box.")
    cfg = load_config()

    ap.add_argument("--port", type=int, default=8765)
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
    ap.add_argument("--headless", action="store_true", help="no GUI")
    args = ap.parse_args()

    DEST = Path(args.dest).expanduser()
    AUTO_EXTRACT = not args.no_extract
    DEST.mkdir(parents=True, exist_ok=True)

    if args.headless:
        LOG_SINKS.append(print)

    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Receiver)
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

    note = ""
    try:
        base = connect(args.port, mode, args.hostname, args.tunnel_name,
                       args.tunnel_token, args.url)
    except TunnelError as e:
        note = f"no tunnel ({e}) - showing this machine's local address instead"
        log(note)
        log("that address only works from this network; fix the above for a public URL")
        mode, base = "direct", f"http://{lan_ip()}:{args.port}"

    chunk = chunk_for(mode, base, args.chunk_mb)

    if args.headless or not gui_available():
        if not args.headless:
            LOG_SINKS.append(print)
        print(f"\n  saving to  {DEST}")
        print(f"  listening  {base}")
        if chunk:
            print(f"  splitting  {chunk}MB per request (proxy body limit)")
        if args.exclude.strip():
            print(f"  skipping   {args.exclude.strip()}")
        print()
        print("  1. paste into the VPS shell:\n")
        print("     " + snippet(base, chunk, args.exclude) + "\n")
        print("  2. preview:  peek /path/to/file-or-folder")
        print("     send it:  send /path/to/file-or-folder\n")
        print("  ctrl-c to stop\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_tunnel()
    else:
        run_gui(base, chunk, args.port, {**cfg, "mode": mode,
                                         "hostname": args.hostname,
                                         "tunnel_name": args.tunnel_name,
                                         "tunnel_token": args.tunnel_token,
                                         "exclude": args.exclude},
                args.chunk_mb, note)


def gui_available():
    try:
        import tkinter  # noqa
        if os.name != "nt" and sys.platform != "darwin" and not os.environ.get("DISPLAY"):
            return False
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
