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

A window opens with a command in it.

1. **Copy the command** and paste it into your VPS shell. Nothing prints — it
   defines two shell functions, which is all it should do.
2. **Preview**, then send:

```bash
peek /var/www/html      # lists what would go, uploads nothing
send /var/www/html      # actually transfers it
```

Files arrive in `~/DropZone`, with progress in the log pane. `send` takes
several paths at once: `send /etc/nginx/nginx.conf /var/log/app.log`.

## Connection modes

Pick one in the **Connection** panel; the pasted command regenerates to match.

| Mode | URL you get | Needs |
|---|---|---|
| **Quick tunnel** | random `trycloudflare.com`, new every run | `cloudflared` |
| **My domain** | your own `drop.example.com`, stable | `cloudflared` + a Cloudflare account |
| **Tunnel token** | whatever you configured in Zero Trust | a tunnel token |
| **Direct / LAN** | `http://192.168.x.x:8765` | same network or Tailscale |
| **Custom URL** | whatever you already run | your own proxy |

**My domain** logs in once (`Log in to Cloudflare`), then creates the tunnel and
the DNS record for you. Settings persist to `~/.dropzone.json`.

Direct/LAN is not reachable from a VPS on the internet — it is for machines on
your own network, and it skips Cloudflare's 100MB request cap entirely.

## What actually gets sent

`send /var/www/html` archives that path **recursively**: hidden files, dotdirs,
everything. Symlinks are stored as links, so their targets are not followed.

Because web roots routinely contain credentials, `.git`, `node_modules` and
`.env` are skipped by default. Edit the **Never send** field (the command
updates as you type) or pass `--exclude`. Override per call on the remote box:

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
  --headless            no GUI, print the command instead
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

## Known rough edges

- The pasted functions live only in that shell. A new SSH session or a
  `sudo su` needs a fresh paste — or append the snippet to `~/.bashrc`.
- A long transfer dies with its SSH session. Use `tmux` for big ones.
- Killing DropZone with `SIGTERM` (e.g. `pkill`) orphans its `cloudflared`
  child; the GUI close button and Ctrl-C shut it down properly.
- macOS ships a deprecated Tk 8.5 that renders `ttk` widgets as an empty
  window, so the GUI deliberately uses classic Tk widgets only.

## License

MIT
