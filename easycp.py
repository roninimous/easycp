#!/usr/bin/env python3
"""
easycp - pull files off a remote box with one pasted command.

Run this on YOUR machine (mac / windows / linux). It starts a tiny
authenticated receiver, works out a reachable URL, and shows you a one-line
shell snippet. Paste that snippet into any VPS shell, then run:

    peek /var/www/html                  # list what would go, upload nothing
    send /var/www/html
    send /etc/nginx/nginx.conf notes.txt

...and the files land in your EasyDrop folder. No SSH keys, no scp syntax.

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
import atexit
import base64
import json
import mimetypes
import os
import queue
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
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
DEST = Path.home() / "EasyDrop"
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
    """~/EasyDrop/foo reads better in a log than /Users/someone/EasyDrop/foo."""
    try:
        return "~/" + str(Path(path).relative_to(Path.home()))
    except ValueError:
        return str(path)


def unescape_path(raw):
    """Undo shell-style backslash escapes from a pasted path.

    Finder's "Copy as Pathname" (and drag-and-drop into some terminals) escapes
    spaces and other punctuation as a shell would - `/AI\\ Assistant.png` - but
    the headless prompt reads the line raw, with no shell to unescape it.
    """
    try:
        parts = shlex.split(raw)
    except ValueError:
        return raw
    return parts[0] if len(parts) == 1 else raw


def in_dest(path):
    """Log paths as the user thinks of them: relative to the EasyDrop folder."""
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


# --------------------------------------------------------------------------
# QR codes
#
# A QR encoder small enough to live in a stdlib-only script: byte mode, error
# level M, versions 1-10, which covers any URL we would ever put on screen.
# Everything here is straight out of ISO/IEC 18004. Verified against Apple's
# CIQRCodeGenerator (identical matrices) and its decoder.
# --------------------------------------------------------------------------

# total codewords (data + error correction) per version
QR_TOTAL = {1: 26, 2: 44, 3: 70, 4: 100, 5: 134,
            6: 172, 7: 196, 8: 242, 9: 292, 10: 346}

# level M: (ec codewords per block, blocks1, data per block1, blocks2, data per block2)
QR_BLOCKS = {
    1: (10, 1, 16, 0, 0), 2: (16, 1, 28, 0, 0), 3: (26, 1, 44, 0, 0),
    4: (18, 2, 32, 0, 0), 5: (24, 2, 43, 0, 0), 6: (16, 4, 27, 0, 0),
    7: (18, 4, 31, 0, 0), 8: (22, 2, 38, 2, 39), 9: (22, 3, 36, 2, 37),
    10: (26, 4, 43, 1, 44),
}

# alignment pattern centres
QR_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
            6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46],
            10: [6, 28, 50]}

# GF(256), primitive polynomial 0x11d
GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def _rs_gen(n):
    """Generator polynomial for n error-correction codewords."""
    g = [1]
    for i in range(n):
        g = [0] + g
        for j in range(len(g) - 1):
            g[j] ^= _gf_mul(g[j + 1], GF_EXP[i])
    return g[::-1]      # division below wants the leading coefficient first


def _rs_ec(data, n):
    g = _rs_gen(n)
    rem = list(data) + [0] * n
    for i in range(len(data)):
        c = rem[i]
        if c:
            for j in range(len(g)):
                rem[i + j] ^= _gf_mul(g[j], c)
    return rem[len(data):]


def _bits(data_bits, version):
    """Data bit string -> interleaved codewords, ready for placement."""
    ec_n, b1, d1, b2, d2 = QR_BLOCKS[version]
    total_data = b1 * d1 + b2 * d2

    # terminator, byte alignment, then the standard alternating padding
    bits = data_bits + "0" * min(4, total_data * 8 - len(data_bits))
    bits += "0" * (-len(bits) % 8)
    pad = ("11101100", "00010001")
    i = 0
    while len(bits) < total_data * 8:
        bits += pad[i % 2]
        i += 1
    cws = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]

    blocks, ecs, at = [], [], 0
    for count, size in ((b1, d1), (b2, d2)):
        for _ in range(count):
            blocks.append(cws[at:at + size])
            ecs.append(_rs_ec(blocks[-1], ec_n))
            at += size

    out = []
    for i in range(max(d1, d2)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec_n):
        for e in ecs:
            out.append(e[i])
    return out


def _template(version):
    """Function patterns, plus a map of which modules they occupy."""
    size = version * 4 + 17
    m = [[0] * size for _ in range(size)]
    used = [[False] * size for _ in range(size)]

    def put(r, c, v):
        m[r][c], used[r][c] = v, True

    for (br, bc) in ((0, 0), (0, size - 7), (size - 7, 0)):
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = br + r, bc + c
                if 0 <= rr < size and 0 <= cc < size:
                    edge = r in (0, 6) and 0 <= c <= 6
                    side = c in (0, 6) and 0 <= r <= 6
                    core = 2 <= r <= 4 and 2 <= c <= 4
                    put(rr, cc, 1 if (edge or side or core) else 0)

    for i in range(8, size - 8):          # timing
        put(6, i, 1 - i % 2)
        put(i, 6, 1 - i % 2)

    centres = QR_ALIGN[version]
    for r in centres:
        for c in centres:
            if (r < 8 and c < 8) or (r < 8 and c > size - 9) \
                    or (r > size - 9 and c < 8):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    put(r + dr, c + dc,
                        1 if max(abs(dr), abs(dc)) != 1 else 0)

    put(size - 8, 8, 1)                   # the always-dark module
    for i in range(9):                    # format info areas
        if not used[8][i]:
            put(8, i, 0)
        if not used[i][8]:
            put(i, 8, 0)
    for i in range(8):
        put(8, size - 1 - i, 0)
        put(size - 1 - i, 8, 0)
    if version >= 7:                      # version info areas
        for i in range(6):
            for j in range(3):
                put(size - 11 + j, i, 0)
                put(i, size - 11 + j, 0)
    return m, used


def _place(m, used, codewords):
    size = len(m)
    bits = "".join(f"{c:08b}" for c in codewords)
    i, up = 0, True
    col = size - 1
    while col > 0:
        if col == 6:                      # skip the vertical timing line
            col -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for row in rows:
            for c in (col, col - 1):
                if not used[row][c]:
                    m[row][c] = int(bits[i]) if i < len(bits) else 0
                    i += 1
        up = not up
        col -= 2


MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _format_bits(mask):
    """15-bit BCH format string for level M (01... no: M is 00)."""
    fmt = (0b00 << 3) | mask          # level M = 00
    v = fmt << 10
    for i in range(4, -1, -1):
        if v & (1 << (i + 10)):
            v ^= 0b10100110111 << i
    return ((fmt << 10) | v) ^ 0b101010000010010


def _version_bits(version):
    v = version << 12
    for i in range(5, -1, -1):
        if v & (1 << (i + 12)):
            v ^= 0b1111100100101 << i
    return (version << 12) | v


def _apply(m, used, mask):
    size = len(m)
    out = [row[:] for row in m]
    for r in range(size):
        for c in range(size):
            if not used[r][c] and MASKS[mask](r, c):
                out[r][c] ^= 1

    fmt = _format_bits(mask)
    for i in range(15):
        bit = (fmt >> i) & 1
        # copy one: down column 8, then left along row 8
        if i < 6:
            out[i][8] = bit
        elif i == 6:
            out[7][8] = bit
        elif i == 7:
            out[8][8] = bit
        elif i == 8:
            out[8][7] = bit
        else:
            out[8][14 - i] = bit
        # copy two: right along row 8, then up column 8
        if i < 8:
            out[8][size - 1 - i] = bit
        else:
            out[size - 15 + i][8] = bit
    out[size - 8][8] = 1

    if size >= 45:                        # version 7+
        vb = _version_bits((size - 17) // 4)
        for i in range(18):
            bit = (vb >> i) & 1
            out[i // 3][size - 11 + i % 3] = bit
            out[size - 11 + i % 3][i // 3] = bit
    return out


def _penalty(m):
    size = len(m)
    score = 0
    for line in [m[r] for r in range(size)] + \
                [[m[r][c] for r in range(size)] for c in range(size)]:
        run, prev = 0, -1
        for v in line:
            if v == prev:
                run += 1
                if run == 5:
                    score += 3
                elif run > 5:
                    score += 1
            else:
                prev, run = v, 1
        # finder-like patterns, with the required light run on either side
        s = "".join(str(v) for v in line)
        for pat in ("1011101" + "0000", "0000" + "1011101"):
            start = 0
            while True:
                at = s.find(pat, start)
                if at < 0:
                    break
                score += 40
                start = at + 1
    for r in range(size - 1):
        for c in range(size - 1):
            block = m[r][c] + m[r][c + 1] + m[r + 1][c] + m[r + 1][c + 1]
            if block in (0, 4):
                score += 3
    dark = sum(sum(row) for row in m)
    score += 10 * (abs(dark * 100 // (size * size) - 50) // 5)
    return score


_QR_CACHE = {}


def qr_rows(text):
    """The matrix as a list of '0101' strings, cached - the URL rarely moves
    but as_dict() is called on every state push."""
    if text not in _QR_CACHE:
        _QR_CACHE.clear()               # only ever one URL at a time
        try:
            _QR_CACHE[text] = ["".join(str(v) for v in row) for row in qr(text)]
        except Exception as e:
            log(f"could not build a QR code: {e}")
            _QR_CACHE[text] = []
    return _QR_CACHE[text]


# Palette indices 16 and 231 are the fixed black and white of the 256-colour
# cube. The named colours (30/40/97/107) are whatever the user's theme decided
# they are, which for a QR is the difference between scanning and not.
QR_BLACK_BG, QR_WHITE_BG = "\033[48;5;16m", "\033[48;5;231m"
QR_BLACK_FG, QR_WHITE_FG = "\033[38;5;16m", "\033[38;5;231m"
QR_OFF = "\033[0m"


def _qr_grid(matrix, quiet):
    n = len(matrix[0])
    width = n + quiet * 2
    grid = [[0] * width for _ in range(quiet)]
    for row in matrix:
        grid.append([0] * quiet + [1 if str(v) == "1" else 0
                                   for v in row] + [0] * quiet)
    grid += [[0] * width for _ in range(quiet)]
    return grid, width


def qr_ansi(matrix, quiet=2, style=""):
    """A QR a phone can actually scan off a terminal.

    Scanners want dark on light, so this paints its own black and white
    rather than trusting the terminal's theme.

    A terminal cell is about twice as tall as it is wide, so a module has to
    be either two cells wide or half a cell tall to come out square. Both
    shapes are here; neither is stretched:

      default  two spaces per module - 74 columns, and a space is the one
               character every terminal renders in exactly one cell
      tiny     one half block per two module rows - a quarter of the area,
               but it needs a font with that glyph and a terminal that both
               draws it as a clean half cell and does not treat it as
               double-width. Where the terminal leaves any of the cell
               unpainted the dark rows come out striped, which no amount of
               care on this side can fix; `low` puts the ink at the bottom of
               the cell instead of the top, which dodges it on some terminals
    """
    if not matrix:
        return ""
    grid, width = _qr_grid(matrix, quiet)

    if style in ("tiny", "low"):
        if len(grid) % 2:
            grid.append([0] * width)      # the block needs pairs of rows
        FG = {0: QR_WHITE_FG, 1: QR_BLACK_FG}
        BG = {0: QR_WHITE_BG, 1: QR_BLACK_BG}
        # upper block: ink is the top module, background the bottom one.
        # lower block swaps both, so the same picture comes out with the
        # glyph at the other end of the cell.
        glyph = "▄" if style == "low" else "▀"
        out = []
        for y in range(0, len(grid), 2):
            line, seen = "", None
            for x in range(width):
                top, bot = grid[y][x], grid[y + 1][x]
                pair = (bot, top) if style == "low" else (top, bot)
                if pair != seen:
                    line += FG[pair[0]] + BG[pair[1]]
                    seen = pair
                line += glyph
            out.append(line + QR_OFF)
        return "\n".join(out)

    cell = "  "                           # two cells wide = one square module
    out = []
    for row in grid:
        line, seen = "", None
        for v in row:
            want = QR_BLACK_BG if v else QR_WHITE_BG
            if want != seen:
                line += want
                seen = want
            line += cell
        out.append(line + QR_OFF)
    return "\n".join(out)


def qr(text):
    """Returns the module matrix as a list of rows of 0/1."""
    data = text.encode("utf-8")
    for version in range(1, 11):
        ec_n, b1, d1, b2, d2 = QR_BLOCKS[version]
        cap_bits = (b1 * d1 + b2 * d2) * 8
        count_bits = 8 if version < 10 else 16
        if 4 + count_bits + len(data) * 8 <= cap_bits:
            break
    else:
        raise ValueError("too long for a version 10 QR code")

    bits = "0100" + format(len(data), f"0{count_bits}b")
    bits += "".join(f"{b:08b}" for b in data)
    cws = _bits(bits, version)

    base, used = _template(version)
    _place(base, used, cws)
    best, best_score = None, None
    for mask in range(8):
        cand = _apply(base, used, mask)
        s = _penalty(cand)
        if best_score is None or s < best_score:
            best, best_score = cand, s
    return best

# --------------------------------------------------------------------------
# the logo - optional branding shown in the panel and on the drop page
# --------------------------------------------------------------------------

LOGO_PATH = Path.home() / ".easycp-logo"
LOGO_MAX = 2 * 1024 * 1024
LOGO = {"data": b"", "type": "", "v": 0}


def sniff_image(data):
    """Trust the bytes, not the Content-Type the browser claimed.

    SVG is deliberately not accepted: it is markup, it would be served from
    the same origin as the drop page, and nothing here needs it.
    """
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return ""


def load_logo():
    try:
        data = LOGO_PATH.read_bytes()
    except OSError:
        return
    kind = sniff_image(data)
    if kind:
        LOGO.update(data=data, type=kind, v=int(LOGO_PATH.stat().st_mtime))
    else:
        log(f"ignoring {tilde(LOGO_PATH)}: not a PNG, JPEG, GIF or WebP")


def set_logo(data):
    """Returns (ok, message). Raises nothing - the caller replies with it."""
    if not data:
        return False, "empty upload"
    if len(data) > LOGO_MAX:
        return False, f"too big - keep it under {human(LOGO_MAX)}"
    kind = sniff_image(data)
    if not kind:
        return False, "needs to be a PNG, JPEG, GIF or WebP"
    try:
        LOGO_PATH.write_bytes(data)
        os.chmod(LOGO_PATH, 0o600)
    except OSError as e:
        return False, f"could not save it: {e}"
    LOGO.update(data=data, type=kind, v=int(time.time()))
    log(f"logo set  {kind}  {human(len(data))}")
    return True, "logo updated"


def clear_logo():
    LOGO_PATH.unlink(missing_ok=True)
    LOGO.update(data=b"", type="", v=int(time.time()))
    log("logo removed")


# --------------------------------------------------------------------------
# sharing - hand out a one-time link to a single file (a folder goes out as
# a .tar.gz, same as `peek -r`/`send -r` package one for the VPS snippet)
# --------------------------------------------------------------------------

SHARE_DIR = Path(tempfile.mkdtemp(prefix="easycp-share-"))
atexit.register(shutil.rmtree, SHARE_DIR, ignore_errors=True)

SHARES_LOCK = threading.Lock()
SHARES = {}              # id -> {path, name, ctype, token, cleanup}
SHARE_BATCHES_LOCK = threading.Lock()
SHARE_BATCHES = {}       # id -> {dir, root}  (a folder mid-upload from the panel)


def make_share(path, cleanup):
    """Register path for one download. Returns (id, token) for the link."""
    sid = secrets.token_hex(8)
    token = secrets.token_urlsafe(16)
    ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    with SHARES_LOCK:
        SHARES[sid] = {"path": path, "name": path.name, "ctype": ctype,
                       "token": token, "cleanup": cleanup}
    return sid, token


def take_share(sid, key):
    """Redeem a link: valid once, then gone even if the download fails."""
    with SHARES_LOCK:
        share = SHARES.get(sid)
        if not share or not secrets.compare_digest(key, share["token"]):
            return None
        share = SHARES.pop(sid)
    BUS.publish("share", {"id": sid, "alive": False})
    return share


def regen_share(sid):
    """Rotate a still-live share onto a new id/token. The old link dies the
    instant this runs; the file underneath, and its name, do not change.

    Returns (new_id, share) for the fresh link, or None if `sid` was already
    downloaded, revoked, or never existed - regenerating only makes sense
    for a link nobody has used yet.
    """
    with SHARES_LOCK:
        share = SHARES.pop(sid, None)
        if not share:
            return None
        new_sid = secrets.token_hex(8)
        share["token"] = secrets.token_urlsafe(16)
        SHARES[new_sid] = share
    BUS.publish("share", {"id": sid, "alive": False})
    return new_sid, share


def tar_folder(path):
    archive = SHARE_DIR / f"{safe_segment(path.name) or 'folder'}-{secrets.token_hex(4)}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(path, arcname=path.name or "folder")
    return archive


def stage_share(path):
    """A plain file shares as itself; a folder is tarred into SHARE_DIR first.

    Returns (serveable_path, cleanup) - cleanup marks a path that is our own
    copy, safe to delete once the link is used or the process exits.
    """
    if path.is_dir():
        return tar_folder(path), True
    return path, False


def open_share_batch(root_name):
    bid = secrets.token_hex(8)
    bdir = SHARE_DIR / f".batch-{bid}"
    root = bdir / (safe_segment(root_name or "") or "folder")
    root.mkdir(parents=True, exist_ok=True)
    with SHARE_BATCHES_LOCK:
        SHARE_BATCHES[bid] = {"dir": bdir, "root": root}
    return bid, root


def close_share_batch(bid):
    with SHARE_BATCHES_LOCK:
        return SHARE_BATCHES.pop(bid, None)


# headless only: the most recent live share id for each path, so `share
# <path>` a second time rotates that link instead of stacking another one
LAST_SHARE = {}


def share_command(app, path_arg):
    """Implements the `share <path>` prompt command. Returns lines to print."""
    p = Path(path_arg).expanduser()
    if not p.exists():
        return [f"  no such file or folder: {p}"]
    key = str(p.resolve())
    prev = LAST_SHARE.get(key)
    regen = regen_share(prev) if prev else None
    if regen:
        sid, share = regen
        token, name = share["token"], share["name"]
        log(f"share re-linked: {name} - the old link is dead")
        tail = "the previous link for this is now dead"
    else:
        try:
            served, cleanup = stage_share(p)
        except Exception as e:
            return [f"  could not prepare that: {e}"]
        sid, token = make_share(served, cleanup)
        name = served.name
        what = "folder, tarred" if p.is_dir() else human(served.stat().st_size)
        log(f"share ready: {name}  ({what})")
        tail = "one download and it's gone"
    LAST_SHARE[key] = sid
    url = f"{app.base}/s/{sid}?k={token}"
    return [f"\n     {url}\n", f"     {tail}\n"]


OLD_DEST = Path.home() / "DropZone"


def adopt_old_dest(dest):
    """~/DropZone was the default before the rename, so carry it across rather
    than silently starting an empty folder next to the user's files."""
    if dest != Path.home() / "EasyDrop" or not OLD_DEST.is_dir():
        return dest            # a custom --dest, or nothing to carry over
    if dest.exists():
        if any(OLD_DEST.iterdir()):
            log(f"note: {tilde(OLD_DEST)} still holds files - "
                f"now saving to {tilde(dest)}")
        return dest
    try:
        OLD_DEST.rename(dest)
        log(f"moved {tilde(OLD_DEST)} -> {tilde(dest)}")
    except OSError as e:
        log(f"could not move {tilde(OLD_DEST)} ({e}) - saving to {tilde(dest)}")
    return dest


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

    def _image(self, data, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        # user-supplied bytes: never let a browser guess a different type
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(data)

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
        if parsed.path == "/drop/logo":
            # an <img> cannot send a header, so this one takes the key in the
            # query like the page itself does
            key = parse_qs(parsed.query).get("k", [""])[0]
            if not secrets.compare_digest(key, TOKEN):
                return self._reply(403, b"bad or missing key\n")
            if not LOGO["data"]:
                return self._reply(404, b"no logo\n")
            return self._image(LOGO["data"], LOGO["type"])
        if parsed.path == "/drop/config":
            if not self._authed():
                return self._reply(401, b"bad token\n")
            return self._json({"chunkMb": DROP_CHUNK_MB[0],
                               "dest": DEST.name,
                               "logo": bool(LOGO["data"]), "logoV": LOGO["v"]})
        if parsed.path.startswith("/s/"):
            # a share link carries its own one-time token - not the drop key
            sid = parsed.path[len("/s/"):].strip("/")
            key = parse_qs(parsed.query).get("k", [""])[0]
            share = take_share(sid, key)
            if not share:
                return self._reply(404, b"this link is used up, or never existed\n")
            return self._serve_share(share)
        self._reply(200, b"easycp is listening.\n")

    def _serve_share(self, share):
        path, name, cleanup = share["path"], share["name"], share["cleanup"]
        try:
            size = path.stat().st_size
        except OSError:
            log(f"share failed: {name} is gone from disk")
            return self._reply(404, b"that file is gone\n")
        self.send_response(200)
        self.send_header("Content-Type", share["ctype"])
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition",
                         f'attachment; filename="{name.replace(chr(34), chr(39))}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        sent = 0
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(262144)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
            log(f"share downloaded: {name}  {human(sent)} - link is now dead")
        except Exception as e:
            log(f"share interrupted: {name}  ({human(sent)} sent, {e}) - link is now dead")
        finally:
            if cleanup:
                path.unlink(missing_ok=True)


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
}.get(sys.platform,
      # everything else is some Linux/BSD: the apt/yum repo covers most of it,
      # and the static binary covers the rest
      "apt/yum repo at https://pkg.cloudflare.com, or a binary from "
      "https://github.com/cloudflare/cloudflared/releases")


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
    # _dzr resolves a path to an absolute one, so that `.` and `..` arrive
    # with a real name: basename "." is "." and would have travelled as an
    # archive called ".tgz". It also answers "does this exist" in one step.
    #
    # _dzls lists the top-level entries of a directory by kind, hidden ones
    # included - which is the whole point of -af/-ad over a bare *, since the
    # shell expands * before we ever see it and * never matches a dotfile.
    #
    # _dzm expands a wildcard argument if the user's shell left it literal
    # (for example under noglob). Normal shell expansion still wins first.
    #
    # _dzrp builds a recursive file list for `send -r PATTERN [ROOT]`, keeping
    # paths relative to ROOT so extraction recreates just the matching tree.
    prelude = (
        f'DZ_EXCLUDE="${{DZ_EXCLUDE-{excludes}}}"; '
        '_dzx() { for x in $(printf "%s\\n" "$DZ_EXCLUDE"); do '
        'printf " --exclude=%s" "$x"; done; }; '
        '_dzr() { if [ -d "$1" ]; then (cd "$1" && pwd); '
        'elif [ -e "$1" ]; then printf "%s/%s" '
        '"$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"; fi; }; '
        '_dzm() { case "$1" in *\\**|*\\?*|*\\[*) '
        'd=$(dirname "$1"); b=$(basename "$1"); '
        '[ "$b" = "*" ] && return 0; '
        '( cd "$d" 2>/dev/null || exit 1; '
        'if [ -n "$ZSH_VERSION" ]; then setopt null_glob; fi; '
        'for e in * .*; do case "$e" in .|..) continue;; esac; '
        '[ -e "$e" ] || continue; '
        'case "$b:$e" in .*:*) ;; *:.*) continue;; esac; '
        'if [ -n "$ZSH_VERSION" ]; then [[ "$e" = ${~b} ]] || continue; '
        'else case "$e" in $b) ;; *) continue;; esac; fi; '
        'printf "%s/%s\\n" "$(pwd)" "$e"; done ); '
        ';; *) _dzr "$1";; esac; }; '
        '_dzls() { k=$1; ( cd "$2" || exit 1; '
        'if [ -n "$ZSH_VERSION" ]; then setopt null_glob; fi; '
        'for e in * .*; do case "$e" in .|..) continue;; esac; '
        '[ -e "$e" ] || continue; '
        'case "$k" in f) [ -f "$e" ] || continue;; d) [ -d "$e" ] || continue;; '
        'esac; printf "%s\\n" "$e"; done ); }; '
        '_dzrp() { [ -n "$2" ] || { echo "missing pattern for $1"; return 1; }; '
        'p=$2; q=$(_dzr "${3:-.}"); '
        'if [ -z "$q" ]; then echo "no such path: ${3:-.}"; return 1; fi; '
        'if [ "$q" = / ]; then echo "refusing to take the whole filesystem"; '
        'return 1; fi; b=$(basename "$q"); l=$(mktemp); '
        '( cd "$q" || exit 1; find . -type f -name "$p" -print ) | '
        'sed "s#^./##" > "$l"; '
        'if [ ! -s "$l" ]; then rm -f "$l"; '
        'echo "nothing matching $p in $q"; return 1; fi; }; '
        # every flag resolves to a kind, so peek and send parse them the same way
        '_dzk() { case "$1" in -a|-all) echo all;; -af|-allfiles) echo f;; '
        '-ad|-alldirs|-alldirectories) echo d;; esac; }; '
        # peek's listing, from a tar that is compressed only when $sz=1 -
        # gzipping everything just to print names is the slow part -s skips
        '_dzshow() { tar -tf "$1" | sed "s/^/   /" | head -30; '
        'n=$(tar -tf "$1" | wc -l | tr -d " "); '
        'if [ "$sz" = 1 ]; then echo "   ---- $n entries, '
        '$(wc -c < "$1" | awk \'{printf "%.2f MB", $1/1048576}\') gzipped"; '
        'else echo "   ---- $n entries  (add -s for the gzipped size)"; fi; }; '
    )

    # "${@:-.}" makes a bare `peek` or `send` mean "this directory", which is
    # what you want after cd-ing somewhere.
    guard = (
        'q=$(_dzr "$p"); '
        'if [ -z "$q" ]; then echo "no such path: $p"; continue; fi; '
        'if [ "$q" = / ]; then echo "refusing to take the whole filesystem"; '
        'continue; fi; b=$(basename "$q"); d=$(dirname "$q"); '
    )

    # the flag forms pack once, from a list, instead of once per argument
    flag_pack = (
        'p=${2:-.}; q=$(_dzr "$p"); '
        'if [ -z "$q" ]; then echo "no such path: $p"; return 1; fi; '
        'b=$(basename "$q"); l=$(mktemp); _dzls "$k" "$q" > "$l"; '
        'if [ ! -s "$l" ]; then rm -f "$l"; '
        'echo "nothing matching in $q"; return 1; fi; '
    )
    flag_tar = (
        'COPYFILE_DISABLE=1 tar -C "$q" $(_dzx) -czf %s -T "$l"'
    )

    # send always gzips - it's the actual upload, so the compression pays for
    # itself. peek only does when $sz=1 (-s/-size); by default it builds a
    # plain tar, which skips the compression that makes a big peek slow.
    peek_tar = (
        'tf=""; [ "$sz" = 1 ] && tf=z; '
        'COPYFILE_DISABLE=1 tar -C "$q" $(_dzx) -c${tf}f %s -T "$l"'
    )
    peek_tar_path = (
        'tf=""; [ "$sz" = 1 ] && tf=z; '
        'COPYFILE_DISABLE=1 tar -C "$d" $(_dzx) -c${tf}f %s "$b"'
    )

    # kept as one string so it reads top-to-bottom in the source even though
    # it lands in the middle of peek()'s one-liner
    peek_help = (
        'echo "peek - preview what send would upload, without sending it"; echo; '
        'echo "  peek [path...]         list one path (a file or a whole folder)"; '
        'echo "  peek                   (no args) lists the current directory"; '
        'echo "  peek -a  [path]        top-level files and folders, loose (-all)"; '
        'echo "  peek -af [path]        top-level files only (-allfiles)"; '
        'echo "  peek -ad [path]        top-level folders only (-alldirectories)"; '
        'echo "  peek -r PATTERN [dir]  files matching PATTERN anywhere under dir (-recursive)"; '
        'echo; '
        'echo "  peek -s ...            also gzip everything to show the upload size (-size)"; '
        'echo "                         slower, since that means actually compressing it"; '
        'echo "  send takes the same flags (minus -s) and actually uploads"; '
    )

    peek = (
        'peek() { sz=0; case "$1" in -s|-size) sz=1; shift;; esac; '
        'case "$1" in -h|-help|--help) ' + peek_help + 'return;; '
        '-r|-recursive) _dzrp "$@" || return 1; '
        't=$(mktemp); ' + (peek_tar % '"$t"') + '; '
        'echo "== $q"; _dzshow "$t"; rm -f "$t" "$l"; return; esac; '
        'k=$(_dzk "$1"); if [ -n "$k" ]; then ' + flag_pack +
        't=$(mktemp); ' + (peek_tar % '"$t"') + '; '
        'echo "== $q"; _dzshow "$t"; rm -f "$t" "$l"; return; fi; '
        'for p in "${@:-.}"; do m=$(_dzm "$p"); '
        'if [ -z "$m" ]; then echo "no such path: $p"; continue; fi; '
        'printf "%s\\n" "$m" | while IFS= read -r p; do ' + guard +
        't=$(mktemp); ' + (peek_tar_path % '"$t"') + '; echo "== $q"; '
        '_dzshow "$t"; rm -f "$t"; done; done; }; '
    )

    if not chunk_mb:
        up = (f'_dzup() {{ curl -f#T - -H "X-Token: {TOKEN}" '
              f'"{base_url}/u/$1.tgz"; }}; ')
    else:
        up = ('_dzup() { w=$(mktemp -d); '
              f'split -b {chunk_mb}m -d -a 3 - "$w/p"; '
              'n=$(ls "$w" | wc -l); i=0; for f in "$w"/p*; do '
              f'curl -f#T "$f" -H "X-Token: {TOKEN}" -H "X-Parts: $n" '
              f'"{base_url}/u/$1.tgz.p$(printf %03d $i)" || break; '
              'i=$((i+1)); done; rm -rf "$w"; }; ')

    # kept as one string so it reads top-to-bottom in the source even though
    # it lands in the middle of send()'s one-liner
    send_help = (
        'echo "send - copy files to this machine over the tunnel"; echo; '
        'echo "  send [path...]         one archive per path (a file or a whole folder)"; '
        'echo "  send                   (no args) sends the current directory"; '
        'echo "  send -a  [path]        top-level files and folders, loose (-all)"; '
        'echo "  send -af [path]        top-level files only (-allfiles)"; '
        'echo "  send -ad [path]        top-level folders only (-alldirectories)"; '
        'echo "  send -r PATTERN [dir]  files matching PATTERN anywhere under dir (-recursive)"; '
        'echo; '
        'echo "  send *.png             wildcards work; for \'everything\' use -a, not send *"; '
        'echo "  DZ_EXCLUDE=\'\' send ...     ignore the default skip list for this call only"; '
        'echo "  peek takes the same flags and previews instead of uploading"; '
    )

    send = (
        'send() { case "$1" in -h|-help|--help) ' + send_help + 'return;; '
        '-r|-recursive) _dzrp "$@" || return 1; '
        + (flag_tar % "-") + ' | _dzup "$b"; rm -f "$l"; return; esac; '
        'k=$(_dzk "$1"); if [ -n "$k" ]; then ' + flag_pack +
        (flag_tar % "-") + ' | _dzup "$b"; rm -f "$l"; return; fi; '
        'for p in "${@:-.}"; do m=$(_dzm "$p"); '
        'if [ -z "$m" ]; then echo "no such path: $p"; continue; fi; '
        'printf "%s\\n" "$m" | while IFS= read -r p; do ' + guard +
        'COPYFILE_DISABLE=1 tar -C "$d" $(_dzx) -czf - "$b" | _dzup "$b"; '
        'done; done; }'
    )

    # the wordmark reuses WORDMARK verbatim (single-quoted per line, via
    # printf rather than echo, since it's full of backslashes and one
    # backtick that a plain echo cannot be trusted to pass through as-is)
    banner_sh = "printf '%s\\n' " + " ".join(
        "'" + line.replace("'", "'\\''") + "'"
        for line in WORDMARK.strip("\n").split("\n")
    ) + " ''; "

    # both functions are gone the moment this shell closes - say so, and wipe
    # the pasted one-liner off the screen rather than leave it sitting there
    footer = (
        '; clear; ' + banner_sh +
        'echo "peek and send are set up in this shell - '
        'they will go away once it closes"'
    )
    return prelude + up + peek + send + footer


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
    if low.startswith(("share downloaded", "share interrupted")):
        return "bad"
    if low.startswith(("copied", "sent", "joined", "unpacked", "listening",
                       "share ready", "share re-linked")):
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
            "dropUrl": self.drop_url(), "qr": qr_rows(self.drop_url()),
            "logo": bool(LOGO["data"]), "logoV": LOGO["v"],
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

    def new_url(self):
        """Throw the current quick tunnel away and take whatever URL comes
        back. Cloudflare picks the name, so this is a re-roll, not a rename -
        and the old link dies the moment the old tunnel does."""
        if self.mode != "quick":
            msg = "only Cloudflare quick tunnels get a random URL"
            log(f"not re-rolling: {msg}")
            return False, msg
        old = self.base
        log("asking Cloudflare for a new quick tunnel URL ...")
        ok, msg = self.apply()
        if ok and old:
            log(f"the old link is dead now: {old}")
        return ok, msg

    def new_url_async(self):
        threading.Thread(target=self.new_url, daemon=True).start()

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

.qrrow{display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap}
.qrrow pre.code{flex:1;min-width:220px;margin:0}
.qrcol{display:flex;flex-direction:column;align-items:center;gap:6px;flex:none}
/* a QR wants a light quiet zone whatever the page theme is doing */
.qrbox{background:#fff;padding:8px;border-radius:8px;line-height:0}
.qrbox svg{display:block;width:132px;height:132px;shape-rendering:crispEdges}
.qrcap{color:var(--faint);font-size:11.5px}

.brandlogo{max-height:34px;max-width:150px;object-fit:contain}
.brandlogo.big{max-height:46px;max-width:170px}
.brandrow{display:flex;align-items:center;gap:14px;margin-top:16px;
  padding-top:15px;border-top:1px solid var(--line);flex-wrap:wrap}
.brandtext{flex:1;min-width:170px}
.brandtitle{font-weight:600;font-size:13.5px}
.brandbtns{display:flex;gap:8px;flex-wrap:wrap}
input[type=file]{display:none}

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
      <img class="brandlogo" id="logo" alt="" hidden>
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
      <button class="btn ghost" id="newurl" hidden>New URL</button>
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
    <div class="qrrow">
      <div class="qrcol">
        <div class="qrbox" id="qr"></div>
        <div class="qrcap">Scan with a phone</div>
      </div>
      <pre class="code" id="dropurl"></pre>
    </div>
    <div class="foot">
      <button class="btn ghost" id="copylink">Copy link</button>
      <span class="meta">Anyone with this link can upload here until easycp
        restarts, which issues a new key.</span>
    </div>

    <div class="brandrow">
      <img class="brandlogo big" id="logoPrev" alt="" hidden>
      <div class="brandtext">
        <div class="brandtitle">Your logo</div>
        <div class="meta" id="logoNote"></div>
      </div>
      <div class="brandbtns">
        <button class="btn ghost" id="logoPick">Choose image</button>
        <button class="btn ghost" id="logoDrop" hidden>Remove</button>
      </div>
      <input type="file" id="logoIn" accept="image/png,image/jpeg,image/gif,image/webp">
    </div>
  </section>

  <section class="card">
    <div class="chead"><h2>Share a file or folder</h2>
      <span class="sub">a one-time link &mdash; it dies the moment it's opened</span>
    </div>
    <div class="brandbtns">
      <button class="btn ghost" id="sharePick">Choose file</button>
      <button class="btn ghost" id="shareFolderPick">Choose folder</button>
    </div>
    <input type="file" id="shareIn">
    <input type="file" id="shareFolderIn" webkitdirectory multiple>
    <div class="meta" id="shareNote"></div>
    <pre class="code" id="shareLink" hidden></pre>
    <div class="foot" id="shareFoot" hidden>
      <button class="btn ghost" id="shareCopy">Copy link</button>
      <button class="btn ghost" id="shareRegen">Regenerate link</button>
      <span class="pill"><i class="dot" id="shareDot"></i><span id="shareStatus"></span></span>
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
  drawQr();
  logo();
  $('#listening').textContent = 'listening on ' + S.base +
    (S.chunk ? '   ·   split into ' + S.chunk + 'MB requests' : '');
  if (document.activeElement !== $('#excl')) $('#excl').value = S.exclude;
  $('#apply').disabled = S.busy;
  $('#apply').textContent = S.busy ? 'Connecting…' : 'Apply';
  // only quick tunnels have a URL worth re-rolling
  $('#newurl').hidden = S.mode !== 'quick';
  $('#newurl').disabled = S.busy;
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
$('#newurl').onclick = () => {
  if (!confirm('Get a different quick tunnel URL?\n\n' +
               'Cloudflare picks the name, so you cannot choose it. The ' +
               'command and the EasyDrop link both change, and anyone still ' +
               'holding the old link will find it dead.')) return;
  S.busy = true; render();
  api('/api/newurl', {}).catch(e => alert(e.message));
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

let qrDrawn = '';
function drawQr(){
  const rows = S.qr || [];
  if (!rows.length){ $('#qr').parentElement.hidden = true; return; }
  $('#qr').parentElement.hidden = false;
  const key = rows.join('');
  if (key === qrDrawn) return;              // same URL, same code
  qrDrawn = key;
  const n = rows.length, q = 2, side = n + q * 2;
  let d = '';
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++)
      if (rows[r][c] === '1') d += `M${c + q} ${r + q}h1v1h-1z`;
  $('#qr').innerHTML =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${side} ${side}">` +
    `<rect width="${side}" height="${side}" fill="#fff"/>` +
    `<path d="${d}" fill="#000"/></svg>`;
}

function logo(){
  // ?v= busts the cache: same URL, new bytes after an upload
  const src = '/api/logo?k=' + encodeURIComponent(K) + '&v=' + S.logoV;
  for (const el of [$('#logo'), $('#logoPrev')]){
    el.hidden = !S.logo;
    if (S.logo && el.getAttribute('src') !== src) el.src = src;
  }
  $('#logoDrop').hidden = !S.logo;
  $('#logoPick').textContent = S.logo ? 'Replace' : 'Choose image';
  $('#logoNote').textContent = S.logo
    ? 'Shown here and on the EasyDrop page you share.'
    : 'PNG, JPEG, GIF or WebP. Shown here and on the EasyDrop page you share.';
}

$('#logoPick').onclick = () => $('#logoIn').click();
$('#logoIn').onchange = async e => {
  const f = e.target.files[0];
  e.target.value = '';                 // so the same file can be picked again
  if (!f) return;
  $('#logoNote').textContent = 'Uploading ...';
  try {
    const r = await fetch('/api/logo', {method:'POST',
      headers:{'X-UI-Token':K, 'Content-Type': f.type || 'application/octet-stream'},
      body:f});
    const out = await r.json().catch(() => ({}));
    if (!r.ok || !out.ok) throw new Error(out.error || r.statusText);
  } catch (err) {
    $('#logoNote').textContent = 'Could not use that image — ' + err.message;
  }
};
$('#logoDrop').onclick = () =>
  api('/api/logo/clear', {}).catch(e => alert(e.message));

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

function shareNote(msg){ $('#shareNote').textContent = msg; }

let shareId = null;
function shareDot(alive){
  $('#shareDot').className = 'dot ' + (alive ? 'live' : 'error');
  $('#shareStatus').textContent = alive ? 'live — one download and it\'s gone' : 'used — link is dead';
}
function showShareLink(url, name, id, note){
  shareId = id;
  $('#shareLink').textContent = url;
  $('#shareLink').hidden = false;
  $('#shareFoot').hidden = false;
  shareDot(true);
  shareNote(note || (name + ' — ready to share'));
}

$('#sharePick').onclick = () => $('#shareIn').click();
$('#shareIn').onchange = async e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (!f) return;
  $('#shareFoot').hidden = true; $('#shareLink').hidden = true;
  shareNote('Uploading ...');
  try {
    const r = await fetch('/api/share', {method:'POST',
      headers:{'X-UI-Token':K, 'Content-Type': f.type || 'application/octet-stream',
               'X-Share-Name': encodeURIComponent(f.name)},
      body: f});
    const out = await r.json().catch(() => ({}));
    if (!r.ok || !out.ok) throw new Error(out.error || r.statusText);
    showShareLink(out.url, out.name, out.id);
  } catch (err) { shareNote('Could not share that — ' + err.message); }
};

$('#shareFolderPick').onclick = () => $('#shareFolderIn').click();
$('#shareFolderIn').onchange = async e => {
  const files = Array.from(e.target.files);
  e.target.value = '';
  if (!files.length) return;
  $('#shareFoot').hidden = true; $('#shareLink').hidden = true;
  const root = (files[0].webkitRelativePath || files[0].name).split('/')[0];
  shareNote(`Uploading ${files.length} file${files.length === 1 ? '' : 's'} ...`);
  try {
    const begin = await api('/api/share/begin', {root});
    for (const f of files){
      const rel = f.webkitRelativePath || f.name;
      const r = await fetch('/api/share/file', {method:'POST',
        headers:{'X-UI-Token':K, 'Content-Type':'application/octet-stream',
                 'X-Batch':begin.id, 'X-Path':encodeURIComponent(rel)},
        body: f});
      const out = await r.json().catch(() => ({}));
      if (!r.ok || !out.ok) throw new Error(out.error || r.statusText);
    }
    const done = await api('/api/share/end', {id: begin.id});
    showShareLink(done.url, done.name, done.id);
  } catch (err) { shareNote('Could not share that folder — ' + err.message); }
};

$('#shareCopy').onclick = () =>
  copyBtn($('#shareCopy'), $('#shareLink').textContent, 'Copy link');
$('#shareRegen').onclick = async () => {
  if (!shareId) return;
  shareNote('Regenerating ...');
  try {
    const out = await api('/api/share/regen', {id: shareId});
    showShareLink(out.url, out.name, out.id, out.name + ' — new link, the old one is dead');
  } catch (err) { shareNote('Could not regenerate — ' + err.message); }
};

function listen(){
  const es = new EventSource('/api/events?k=' + encodeURIComponent(K));
  es.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.kind === 'log') addLog(msg.data);
    else if (msg.kind === 'share'){
      if (msg.data.id === shareId && !msg.data.alive) shareDot(false);
    }
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
header{margin-bottom:20px;display:flex;align-items:center;gap:18px;
  justify-content:space-between;flex-wrap:wrap}
.hgroup{min-width:0}
/* whoever is sending sees who they are sending to */
.brandlogo{max-height:60px;max-width:190px;object-fit:contain;flex:none}
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

/* the transfer really is a terminal job, so it may as well look like one -
   and an ASCII bar needs no colour to be readable */
.term{background:#0b1020;border:1px solid #202a44;border-radius:var(--radius);
  overflow:hidden;margin-bottom:14px}
.termhead{display:flex;align-items:center;gap:8px;padding:9px 13px;
  background:#151c30;border-bottom:1px solid #202a44}
.termhead .d{width:10px;height:10px;border-radius:50%;flex:none}
.termhead .r{background:#ff5f57} .termhead .y{background:#febc2e}
.termhead .g{background:#28c840}
.termhead .tt{margin-left:6px;color:#8b9ab1;font-size:12px;
  font-family:ui-monospace,Menlo,Consolas,monospace}
.xbtn{margin-left:auto;background:none;border:1px solid #2c3a5a;color:#9aa8bf;
  border-radius:6px;padding:3px 10px;font:inherit;font-size:12px;
  font-family:ui-monospace,Menlo,Consolas,monospace;cursor:pointer}
.xbtn:hover{border-color:#f87171;color:#f87171}

.termbody{padding:12px 13px 13px;overflow-x:auto;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:12.5px;line-height:1.65;color:#e2e8f0}
#rows{max-height:300px;overflow-y:auto}
.ln{display:grid;grid-template-columns:1fr auto auto auto;gap:0 12px;
  align-items:baseline;white-space:pre}
/* min-width:0 or the grid track refuses to shrink and the ellipsis never bites */
.ln .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.ln .sz{color:#8b9ab1;font-variant-numeric:tabular-nums;text-align:right}
.ln .bar{color:#4f83f1;white-space:pre}
.ln .pc{color:#8b9ab1;font-variant-numeric:tabular-nums;text-align:right;
  min-width:4.5em}
.ln.done .bar{color:#34d399} .ln.done .pc{color:#34d399}
.ln.bad .bar,.ln.bad .pc,.ln.bad .nm{color:#f87171}
/* normal, not pre: these lines are wrapped across source lines in the markup */
.ln.cmd{display:block;white-space:normal;color:#8b9ab1}
.ln.cmd .pr{color:#34d399}
.ln.cmd .dim{color:#64748b}
.ln.total{margin-top:6px;padding-top:8px;border-top:1px solid #202a44;
  color:#e2e8f0}
.ln.total .bar{color:#e2e8f0}
.ln.total .pc{min-width:0;color:#8b9ab1;white-space:nowrap}
.cur{color:#4f83f1;animation:blink 1.1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
/* on a phone the path is worth more than one line: give it the whole width
   and put size, bar and percentage underneath, rather than eliding it away */
@media (max-width:560px){
  .termbody{font-size:12px}
  .ln{grid-template-columns:auto auto 1fr;gap:0 10px}
  .ln .nm{grid-column:1/-1}
  .ln .pc{justify-self:end;min-width:0}
  .ln.total .nm{color:#8b9ab1}
  #rows .ln{margin-bottom:5px}
}
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
    <div class="hgroup">
    <h1 class="sr">EasyDrop</h1>
    <pre class="mark" aria-hidden="true"> _____                      ____
| ____|  __ _  ___   _   _ |  _ \  _ __   ___   _ __
|  _|   / _` |/ __| | | | || | | || '__| / _ \ | '_ \
| |___ | (_| |\__ \ | |_| || |_| || |   | (_) || |_) |
|_____| \__,_||___/  \__, ||____/ |_|    \___/ | .__/
                     |___/                     |_|</pre>
    <div class="tag">drop files here and they land on the other machine</div>
    </div>
    <img class="brandlogo" id="logo" alt="" hidden>
  </header>

  <div id="fail" class="err" hidden></div>
  <div id="ok" class="done-msg" hidden></div>

  <div id="zone">
    <pre class="target" aria-hidden="true">      ___
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

  <section class="term" id="list" hidden>
    <div class="termhead">
      <i class="d r"></i><i class="d y"></i><i class="d g"></i>
      <span class="tt">easydrop &mdash; upload</span>
      <button class="xbtn" id="cancel" hidden>cancel</button>
    </div>
    <div class="termbody">
      <div class="ln cmd"><span class="pr">$</span> <span id="listTitle"></span>
        <span class="dim" id="listSub"></span></div>
      <div id="rows"></div>
      <div class="ln total"><span class="nm">total</span><span class="sz"></span
        ><span class="bar" id="allBar"></span><span class="pc" id="allTxt"></span></div>
      <div class="ln cmd"><span class="pr">$</span> <span class="cur">&#9608;</span></div>
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
    if (c.logo) {
      const img = $('#logo');
      img.onload = () => { img.hidden = false; };
      img.src = '/drop/logo?k=' + encodeURIComponent(KEY) + '&v=' + c.logoV;
    }
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
// bars are drawn with characters, so the width is in columns, not pixels -
// narrow screens get a shorter bar rather than a sideways scroll
function barWidth() { return window.innerWidth < 560 ? 10 : 22; }

function bar(frac) {
  const w = barWidth();
  const n = Math.max(0, Math.min(w, Math.round(frac * w)));
  return '[' + '#'.repeat(n) + '.'.repeat(w - n) + ']';
}

function add(found) {
  if (!found.length || busy) return;
  $('#ok').hidden = true; $('#fail').hidden = true;
  items = found.map(f => ({file: f.file, path: f.path, sent: 0, state: ''}));
  $('#rows').textContent = '';
  for (const it of items) {
    const row = document.createElement('div');
    row.className = 'ln';
    row.innerHTML = '<span class="nm"></span><span class="sz"></span>' +
                    '<span class="bar"></span><span class="pc"></span>';
    row.querySelector('.nm').textContent = it.path;
    it.row = row;
    it.note = row.querySelector('.sz');
    it.barEl = row.querySelector('.bar');
    it.pcEl = row.querySelector('.pc');
    it.note.textContent = human(it.file.size);
    $('#rows').append(row);
  }
  const bytes = items.reduce((n, i) => n + i.file.size, 0);
  $('#list').hidden = false;
  $('#listTitle').textContent = 'send ' + items.length +
                                (items.length === 1 ? ' file' : ' files');
  $('#listSub').textContent = '# ' + human(bytes);
  paint();
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
      const frac = it.state === 'done' ? 1
                 : (it.file.size ? it.sent / it.file.size : 0);
      it.barEl.textContent = bar(frac);
      it.pcEl.textContent = it.msg || (it.state === 'done' ? 'ok'
                                       : Math.floor(frac * 100) + '%');
    }
    $('#allBar').textContent = bar(total ? sent / total : 0);
    const secs = (Date.now() - start) / 1000;
    $('#allTxt').textContent = human(sent) + '/' + human(total) +
      (busy && secs > 0.6 ? '  ' + human(sent / secs) + '/s' : '');
  });
}

let sizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(sizeTimer);
  sizeTimer = setTimeout(paint, 150);     // re-draw bars at the new width
});

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
      it.sent = 0; it.msg = 'retry'; paint();
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
          it.state = 'done'; it.msg = ''; it.row.classList.add('done');
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
    if (it) { it.state = 'bad'; it.msg = 'fail'; it.row.classList.add('bad'); }
    paint();
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

    def _recv_to_file(self, dest, length):
        total = 0
        with open(dest, "wb") as f:
            while total < length:
                chunk = self.rfile.read(min(262144, length - total))
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)
        return total

    def _share_url(self, path, cleanup):
        sid, token = make_share(path, cleanup)
        return sid, f"{self.app.base}/s/{sid}?k={token}", path.name

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if not self._local():
            return self._send(403, b"local requests only\n")
        path = urlparse(self.path).path
        if path == "/":
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if not self._authed():
            return self._send(403, b"bad or missing key\n")
        if path == "/api/logo":
            if not LOGO["data"]:
                return self._send(404, b"no logo\n")
            self.send_response(200)
            self.send_header("Content-Type", LOGO["type"])
            self.send_header("Content-Length", str(len(LOGO["data"])))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(LOGO["data"])
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
        length = _int(self.headers.get("Content-Length"), 0)

        # the logo, and a shared file, arrive as a raw body - read it before
        # anything tries to parse the request as JSON
        if path == "/api/logo":
            if length > LOGO_MAX:
                return self._json({"ok": False,
                                   "error": f"too big - keep it under "
                                            f"{human(LOGO_MAX)}"}, 413)
            ok, msg = set_logo(self.rfile.read(length))
            if ok:
                self.app.push()
            return self._json({"ok": ok, "error": None if ok else msg},
                              200 if ok else 400)

        if path == "/api/share":
            raw_name = unquote(self.headers.get("X-Share-Name", ""))
            dest = unique_path(SHARE_DIR / safe_name(raw_name))
            try:
                n = self._recv_to_file(dest, length)
            except Exception as e:
                dest.unlink(missing_ok=True)
                return self._json({"ok": False, "error": str(e)}, 500)
            sid, url, name = self._share_url(dest, cleanup=True)
            log(f"share ready: {name}  {human(n)}")
            return self._json({"ok": True, "url": url, "name": name, "id": sid})

        if path == "/api/share/file":
            bid = self.headers.get("X-Batch", "")
            with SHARE_BATCHES_LOCK:
                batch = SHARE_BATCHES.get(bid)
            if not batch:
                self.rfile.read(length)
                return self._json({"ok": False, "error": "unknown batch"}, 404)
            # the browser's relative path already starts with the folder
            # name (webkitRelativePath), same as batch["root"] does - so
            # this joins onto batch["dir"], not batch["root"], or the name
            # would be nested twice
            parts = safe_rel(unquote(self.headers.get("X-Path", "")))
            if not parts:
                self.rfile.read(length)
                return self._json({"ok": False, "error": "bad path"}, 400)
            try:
                target = under(batch["dir"], *parts)
            except ValueError:
                self.rfile.read(length)
                return self._json({"ok": False, "error": "bad path"}, 400)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._recv_to_file(target, length)
            except Exception as e:
                return self._json({"ok": False, "error": str(e)}, 500)
            return self._json({"ok": True})

        try:
            raw = self.rfile.read(length)
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        app = self.app

        if path == "/api/logo/clear":
            clear_logo()
            app.push()
            return self._json({"ok": True})
        if path == "/api/share/begin":
            bid, _root = open_share_batch(str(body.get("root") or ""))
            return self._json({"ok": True, "id": bid})
        if path == "/api/share/end":
            batch = close_share_batch(str(body.get("id") or ""))
            if not batch:
                return self._json({"ok": False, "error": "unknown batch"}, 404)
            root = batch["root"]
            try:
                if not any(root.iterdir()):
                    raise ValueError("empty folder")
                archive = tar_folder(root)
            except Exception as e:
                shutil.rmtree(batch["dir"], ignore_errors=True)
                return self._json({"ok": False, "error": str(e)}, 400)
            shutil.rmtree(batch["dir"], ignore_errors=True)
            sid, url, name = self._share_url(archive, cleanup=True)
            log(f"share ready: {name}")
            return self._json({"ok": True, "url": url, "name": name, "id": sid})
        if path == "/api/share/regen":
            result = regen_share(str(body.get("id") or ""))
            if not result:
                return self._json(
                    {"ok": False, "error": "that link is already gone"}, 404)
            sid, share = result
            url = f"{app.base}/s/{sid}?k={share['token']}"
            log(f"share re-linked: {share['name']} - the old link is dead")
            return self._json({"ok": True, "url": url, "name": share["name"],
                               "id": sid})
        if path == "/api/connect":
            app.apply_async(**{k: body.get(k) for k in
                               ("mode", "hostname", "tunnel_name",
                                "tunnel_token", "url")})
            return self._json({"ok": True})
        if path == "/api/exclude":
            app.set_exclude(body.get("exclude", ""))
            return self._json({"ok": True})
        if path == "/api/newurl":
            # answer the caller rather than letting the worker thread swallow it
            if app.mode != "quick":
                return self._json(
                    {"ok": False,
                     "error": "only Cloudflare quick tunnels get a random URL"}, 400)
            app.new_url_async()
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


def enable_ansi():
    """A Windows console starts with escape processing off, so anything we
    colour arrives as a literal <-[1m. Ask for it; if the console will not
    give it, say so, and everything below prints plain instead."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)              # stdout
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False                                 # redirected, not a console
        VT = 0x0004                                      # VIRTUAL_TERMINAL_PROCESSING
        if mode.value & VT:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | VT))
    except Exception:
        return False


COLOUR = enable_ansi()
TTY = sys.stdout.isatty() and COLOUR

try:
    import readline          # noqa: F401 - up/down history at the `--headless` prompt
    readline.set_history_length(500)
except ImportError:
    pass                      # Windows: the console already recalls history with the arrows


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
    qr [tiny|low]         print that link as a QR code to scan with a phone
                          (tiny = a quarter the size; low = the same, drawn
                           from the bottom of the cell, if tiny is striped)
    status                where files land, what is listening, what is skipped
    log [n]               replay the last n log lines (default 20)

    mode <name>           %s
    hostname <host>       domain for `mode domain` / `mode token`
    name <name>           cloudflared tunnel name (default dropzone)
    token <token>         tunnel token for `mode token`
    url <base-url>        base URL for `mode url`
    exclude <patterns>    what `send` never uploads ('exclude -' clears it)
    apply                 bring the chosen mode up and reprint the command
    newurl                re-roll the quick tunnel URL (Cloudflare picks it)
    login                 authorise cloudflared for `mode domain`

    dest [path]           show or change where files land
    open                  open that folder in the file manager
    logo [path]           show, set, or `logo remove` the drop-page logo
    share <path>          one-time download link to a file or folder
                          (again on the same path rotates it - old link dies)
    quit                  stop easycp
""" % " | ".join(MODE_IDS)


REPO = "github.com/roninimous/easycp"

WORDMARK = r"""
    ___   __ _  ___   _   _   ___  _ __
   / _ \ / _` |/ __| | | | | / __|| '_ \
  |  __/| (_| |\__ \ | |_| || (__ | |_) |
   \___| \__,_||___/  \__, | \___|| .__/
                      |___/       |_|
"""


def banner(app, full=True):
    """full=False skips the (long) paste-me command - used at the interactive
    prompt, where `show` is one word away. The piped/nohup fallback has no
    prompt to type that at, so it keeps getting the command printed in full.
    """
    out = [paint(WORDMARK, BOLD)]
    out.append(f"  saving to   {tilde(DEST)}")
    out.append(f"  listening   {app.base}")
    if app.chunk:
        out.append(f"  splitting   {app.chunk}MB per request (proxy body limit)")
    out.append(f"  skipping    {app.exclude or '(nothing)'}")
    out.append("")
    if full:
        out.append("  1. paste this into your VPS shell:")
        out.append("")
        out.append("     " + app.snippet())
        out.append("")
    else:
        out.append("  1. type " + paint("show", BOLD) +
                   " to print the paste-me command (it's long, so it's not "
                   "dumped here), then paste it into your VPS shell")
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
    print(banner(app, full=False))
    prompt = paint("easycp>", BOLD) + " "
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
        elif cmd == "qr":
            want = rest.strip().lower()
            style = want if want in ("tiny", "low") else ""
            rows_ = qr_rows(app.drop_url())
            art = qr_ansi(rows_, style=style) if TTY else ""
            if not TTY:
                # the code is drawn entirely in colour; without it there is
                # nothing to scan, so do not print a screenful of escapes
                print("\n  this console will not do colour, so a QR here "
                      "could not be scanned")
                if os.name == "nt":
                    print("  Windows Terminal handles it, or open the browser "
                          "panel without --headless")
                print("\n     " + app.drop_url() + "\n")
            elif art:
                # a code wider than the window wraps, and a wrapped QR is not
                # a QR - better to say so than to print something unscannable
                need = (len(rows_) + 4) * (1 if style == "tiny" else 2)
                have = shutil.get_terminal_size((80, 24)).columns
                if need > have:
                    print(paint(f"\n  this code needs {need} columns and the "
                                f"window is {have} - widen it"
                                + ("" if style == "tiny" else ", or try `qr tiny`"),
                                ANSI["warn"]))
                print()
                try:
                    print(art)
                except UnicodeEncodeError:
                    # a console stuck on a legacy code page cannot encode the
                    # half blocks; the default shape is spaces and always can
                    print(qr_ansi(rows_))
                    style = ""
                print("\n     " + app.drop_url())
                if not style and need <= have:
                    print(paint("     `qr tiny` is a quarter the size (or "
                                "`qr low` if tiny comes out striped)", DIM))
                elif style == "tiny":
                    print(paint("     striped? try `qr low`, or turn line "
                                "spacing down in your terminal settings", DIM))
                print()
            else:
                print("  could not build a QR code - here is the link:")
                print("     " + app.drop_url() + "\n")
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
            print("  the paste-me command changed - type " + paint("show", BOLD)
                  + " to see it, " + paint("help", BOLD) + " for everything else")
        elif cmd in ("apply", "go", "connect"):
            ok, msg = app.apply()
            print(("  " + msg) if ok else paint("  " + msg, ANSI["bad"]))
            print("  type " + paint("show", BOLD) + " to see the paste-me command, "
                  + paint("help", BOLD) + " for everything else")
        elif cmd in ("newurl", "reroll"):
            ok, msg = app.new_url()
            print(("  " + msg) if ok else paint("  " + msg, ANSI["bad"]))
            if ok:
                print("  type " + paint("show", BOLD) + " to see the updated command, "
                      + paint("help", BOLD) + " for everything else")
                print("\n     " + app.drop_url() + "\n")
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
                set_dest(Path(unescape_path(rest)).expanduser())
                app.push()
            print(f"  saving to {tilde(DEST)}")
        elif cmd == "open":
            open_folder(DEST)
            print(f"  opened {tilde(DEST)}")
        elif cmd == "logo":
            if rest.lower() in ("remove", "clear", "off"):
                clear_logo()
                app.push()
                print("  logo removed")
            elif rest:
                path = unescape_path(rest)
                try:
                    data = Path(path).expanduser().read_bytes()
                except OSError as e:
                    print(f"  could not read {path}: {e}")
                else:
                    ok, msg = set_logo(data)
                    if ok:
                        app.push()
                    print(("  " if ok else "  error: ") + msg)
            else:
                print(f"  logo: {'set' if LOGO['data'] else '(none)'}"
                      "   usage: logo <path>  |  logo remove")
        elif cmd == "share":
            if not rest:
                print("  usage: share <path>  (again on the same path rotates the link)")
            else:
                for line in share_command(app, unescape_path(rest)):
                    print(line)
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
    ap.add_argument("--set-logo", metavar="PATH",
                    help="set the drop-page logo from an image file, then exit")
    ap.add_argument("--remove-logo", action="store_true",
                    help="remove the current logo, then exit")
    args = ap.parse_args()

    if args.set_logo:
        try:
            data = Path(args.set_logo).expanduser().read_bytes()
        except OSError as e:
            sys.exit(f"could not read {args.set_logo}: {e}")
        ok, msg = set_logo(data)
        if not ok:
            sys.exit(f"  {msg}")
        print(f"  {msg}")
        return
    if args.remove_logo:
        clear_logo()
        print("  logo removed")
        return

    DEST = Path(args.dest).expanduser()
    AUTO_EXTRACT = not args.no_extract

    LOG_SINKS.append(term_sink)
    LOG_SINKS.append(lambda line: BUS.publish(
        "log", {"line": line, "cls": log_class(line.partition("] ")[2])}))

    DEST = adopt_old_dest(DEST)
    DEST.mkdir(parents=True, exist_ok=True)
    load_logo()

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
    print(paint(WORDMARK, BOLD))
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
