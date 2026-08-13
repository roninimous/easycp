# easycp

Pull files off a remote box with one pasted command.

No SSH keys to install, no `scp` syntax to remember, no inbound port on the
server. You run DropZone on your own machine, copy one line, paste it into any
VPS shell, and then:

```bash
send /var/www/html
```

The folder lands in `~/DropZone`, unpacked and ready.

```
   your laptop                                     the VPS
┌──────────────────┐                        ┌────────────────────┐
│  dropzone.py     │   <—— HTTPS PUT ——     │  send /var/www/html│
│  ~/DropZone/     │      (outbound)        │  tar → curl        │
└──────────────────┘                        └────────────────────┘
```

The transfer is a **push from the server to you**, which is why the VPS needs
no open port, no key exchange, and no client install beyond `tar` and `curl`.

## Requirements

- Python 3.8+ (uses only the standard library)
- `cloudflared` — optional, only for a public URL:
  `brew install cloudflared`

The remote box needs nothing but `tar`, `curl` and `split`, which every
mainstream distro already has.

## Quick start

```bash
python3 dropzone.py
```

A control panel opens in your browser with a command in it. Prefer the
terminal? `python3 dropzone.py --headless` gives you the same controls at a
prompt — no browser, no GUI toolkit, works over SSH.

1. **Copy the command** and paste it into your VPS shell. Nothing prints — it
   defines two shell functions, which is all it should do.
2. **Preview**, then send:

```bash
peek /var/www/html      # lists what would go, uploads nothing
send /var/www/html      # actually transfers it
```

Files arrive in `~/DropZone`, and every file that lands is named in the
activity log. `send` takes several paths at once:
`send /etc/nginx/nginx.conf /var/log/app.log`.

## The two front ends

There is no GUI toolkit anywhere — no Tk, no Qt, nothing to install.

**Browser control panel** (default). DropZone serves a small page on
`127.0.0.1` and opens it. The page is bound to loopback only, so the tunnel
never exposes it, and every request carries a one-time key printed with the
URL. It streams the activity log live over server-sent events.

**Terminal** (`--headless`). Same engine, driven from a prompt. `help` lists
everything:

```
show                  print the paste-me command again
copy                  copy it to the clipboard
status                where files land, what is listening, what is skipped
log [n]               replay the last n log lines

mode <name>           quick | domain | token | direct | url
hostname <host>       domain for `mode domain` / `mode token`
name <name>           cloudflared tunnel name
token <token>         tunnel token for `mode token`
url <base-url>        base URL for `mode url`
exclude <patterns>    what `send` never uploads ('exclude -' clears it)
apply                 bring the chosen mode up and reprint the command
login                 authorise cloudflared for `mode domain`

dest [path]           show or change where files land
open                  open that folder in the file manager
quit                  stop DropZone
```

Log lines stream into the terminal while you sit at the prompt. With no
terminal attached (`nohup`, systemd, a pipe) `--headless` prints the command
and just keeps running.

## Connection modes

Pick one in the **Connection** card, or `mode <name>` then `apply` at the
prompt. The pasted command regenerates to match.

| Mode | URL you get | Needs |
|---|---|---|
| **Quick tunnel** | random `trycloudflare.com`, new every run | `cloudflared` |
| **My domain** | your own `drop.example.com`, stable | `cloudflared` + a Cloudflare account |
| **Tunnel token** | whatever you configured in Zero Trust | a tunnel token |
| **Direct / LAN** | `http://192.168.x.x:8765` | same network or Tailscale |
| **Custom URL** | whatever you already run | your own proxy |

**My domain** logs in once (`Log in to Cloudflare`, or `login`), then creates
the tunnel and the DNS record for you. Settings persist to `~/.dropzone.json`.

Direct/LAN is not reachable from a VPS on the internet — it is for machines on
your own network, and it skips Cloudflare's 100MB request cap entirely.

## What actually gets sent

`send /var/www/html` archives that path **recursively**: hidden files, dotdirs,
everything. Symlinks are stored as links, so their targets are not followed.

Because web roots routinely contain credentials, `.git`, `node_modules` and
`.env` are skipped by default. Edit the **Never send** field (the command
updates as you type), run `exclude .git .env` at the prompt, or pass
`--exclude`. Override per call on the remote box:

```bash
DZ_EXCLUDE=".git" send /var/www/html    # keep .env this time
DZ_EXCLUDE= send /var/www/html          # send absolutely everything
```

Run `peek` first if you are unsure — it prints the exact file list and the
gzipped upload size without sending a byte.

## Command line

```
python3 dropzone.py [options]

  --port PORT           listen port (default 8765)
  --dest DEST           where received files land (default ~/DropZone)
  --tunnel MODE         auto | quick | domain | token | off
  --hostname HOST       your domain, e.g. drop.example.com
  --tunnel-name NAME    cloudflared tunnel name (default "dropzone")
  --tunnel-token TOKEN  token from the Zero Trust dashboard
  --url URL             use a base URL you already have
  --exclude "A B C"     patterns send never uploads ('' sends everything)
  --chunk-mb N          split uploads into N-MB requests (auto = 90 behind Cloudflare)
  --no-extract          keep .tgz archives instead of unpacking
  --headless            drive everything from the terminal, no browser UI
  --ui-port PORT        port for the local control panel (default: a free one)
  --no-browser          serve the control panel but do not open a window
```

```bash
python3 dropzone.py --tunnel domain --hostname drop.example.com
python3 dropzone.py --headless --tunnel off
```

## How it works

`tar` streams the path straight into `curl -T`, so nothing is staged on the VPS
disk. Because a pipe has no known length, curl uses chunked transfer encoding;
the receiver handles both that and `Content-Length`. Uploads land in a `.part`
file that is atomically renamed on completion, so a partial transfer never
looks like a finished one. `.tgz` arrivals are unpacked automatically (with
tarfile's `data` filter where available).

Requests carry an `X-Token` header compared with `secrets.compare_digest`. curl
sends `Expect: 100-continue`, so a bad token is rejected before any body moves.

Cloudflare caps request bodies at 100MB, so behind a tunnel the stream is
`split` into 90MB parts uploaded with an `X-Parts` header. The receiver buffers
them under `.parts/` and concatenates once every part has arrived.

## Security notes

- The token is regenerated **every launch**. A snippet pasted yesterday will
  401 today — re-copy it after each restart.
- While a tunnel is up, that URL is a live endpoint on the public internet.
  It is token-protected, but it is reachable by anyone who has the URL and the
  token. Close DropZone when you are done.
- Incoming filenames are stripped to a bare basename, so a hostile name cannot
  escape the destination folder.
- The control panel listens on `127.0.0.1` only and rejects requests whose
  `Host` or `Origin` is not loopback, so a web page you visit cannot drive it.
  Its key is regenerated every launch, like the upload token.

## Known rough edges

- The pasted functions live only in that shell. A new SSH session or a
  `sudo su` needs a fresh paste — or append the snippet to `~/.bashrc`.
- A long transfer dies with its SSH session. Use `tmux` for big ones.
- Killing DropZone with `SIGTERM` (e.g. `pkill`) orphans its `cloudflared`
  child; Ctrl-C, `quit`, and the panel's Quit button shut it down properly.

## License

MIT
