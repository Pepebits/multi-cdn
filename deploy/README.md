# Deployment guide

This guide takes you from an empty server to a panel that switches your domains to Gcore
during a block, step by step. Do the steps in order: until the last one, **nothing touches
your DNS** (the panel starts in dry run and only simulates changes).

| Step | What | Where | Time |
|---|---|---|---|
| [1](#1-install-the-panel) | Install the panel | Server terminal | 5 min |
| [2](#2-create-your-user) | Create your user | Server terminal | 2 min |
| [3](#3-open-the-panel) | Open the panel through an SSH tunnel | Your computer | 2 min |
| [4](#4-connect-cloudflare-and-gcore) | Connect Cloudflare and Gcore | Panel | 10 min |
| [5](#5-add-your-origin-server) | Add your origin server | Panel | 2 min |
| [6](#6-import-your-domains) | Import your domains | Panel | 5 min |
| [7](#7-prepare-each-domain-on-gcore) | Prepare each domain on Gcore | Panel | 5 min per domain |
| [8](#8-set-up-alerts) | Set up alerts | Panel | 10 min |
| [9](#9-protect-the-origin) | Protect the origin (firewall and Caddy) | Server terminal | 30 min |
| [10](#10-go-live) | Go live | Server terminal | 2 min |

**You need:** a Linux server with Docker and the compose plugin, your domains on Cloudflare
(proxied), a free [Gcore](https://gcore.com) account, and SSH access to the server. The
examples use `/var/www/multi-cdn`; any folder works.

> ⚠️ **Never publish the panel through Cloudflare or any CDN it controls.** During a block those
> IPs are unreachable, which is exactly when you need the panel. It listens on `127.0.0.1` only.

## 1. Install the panel

```bash
cd /var/www
git clone https://github.com/Pepebits/multi-cdn.git
cd multi-cdn
deploy/install.sh
```

The first run creates `.env` (permissions 600) with a new **master key**, prints it and stops.

1. **Save the master key in your password manager now.** It encrypts every credential and
   secret in the database: without it, a backup of `data/` cannot be read, not even by you.
2. Edit `.env`:

   ```bash
   nano .env
   ```

   | Variable | Value |
   |---|---|
   | `ORIGIN_VPS1_IPV4` | Your server's public IPv4 (it is stored encrypted and never published) |
   | `MULTICDN_ACME_EMAIL` | Your email, for the Let's Encrypt account of the Gcore certificates |
   | `MULTICDN_DRY_RUN` | Leave it `true` until [step 10](#10-go-live) |
   | `MULTICDN_LANG` | Optional: `es` to start the panel in Spanish (each user can switch in the footer) |

3. Run the script again. It builds the image, starts the container and waits for it:

   ```bash
   deploy/install.sh
   ```

   You should see `Panel running on 127.0.0.1:8765`.

> 💡 To keep `.env` somewhere else (so that backups of this folder do not carry the key), set
> `MULTICDN_ENV_FILE=/path/of/your/choice` in the environment; `install.sh` and
> `docker compose` both use it. `MULTICDN_SECRETS_DIR` does the same for the `config/` folder
> of the [panel secrets file](#panel-secrets-file-configsecretsenv).

## 2. Create your user

```bash
docker compose exec panel python -m app.cli create-user <user>
```

It asks for a password and shows a QR code: scan it with your authenticator app (1Password,
Google Authenticator, Aegis…). The first user can only be created from the server terminal;
more users are added later the same way.

## 3. Open the panel

From **your computer**, open an SSH tunnel and leave it running:

```bash
ssh -N -L 8765:127.0.0.1:8765 <user>@<server>
```

Then open <http://localhost:8765> and sign in with your password and the 6-digit code. The
connection goes straight to your server: it does not depend on Cloudflare.

<details>
<summary>Make the tunnel shorter to type and reconnect by itself</summary>

Add this to `~/.ssh/config` on your computer:

```
Host multicdn
    HostName <server>
    User <user>
    LocalForward 8765 127.0.0.1:8765
    ExitOnForwardFailure yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Now `ssh -N multicdn` opens it. To reconnect automatically when the network changes or the
laptop sleeps, use autossh:

```bash
brew install autossh        # Linux: apt install autossh
autossh -M 0 -N multicdn
```

If you get `bind [127.0.0.1]:8765: Address already in use`, another tunnel or a local panel is
already on that port: close it or use another local port (`-L 8766:127.0.0.1:8765`).

From a phone, any SSH client with port forwarding works (Termius, for example).
</details>

<details>
<summary>Alternative: a private network (Tailscale, WireGuard…)</summary>

More comfortable from a phone, and it lets you close SSH to the public. Traffic goes directly
between your devices and the server.

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up                  # open the link it prints and sign in
sudo ufw allow in on tailscale0    # if you use ufw
sudo tailscale serve --bg 8765     # https://<server-name>.<your-tailnet>.ts.net
```

Install Tailscale on your computer and phone with the same account. The origin firewall of
step 9 already lets the `tailscale0` interface through. Write the server's Tailscale name in
*Settings → Servers*.

Behind `tailscale serve` links and cookies are HTTPS on their own (the panel reads
`X-Forwarded-Proto`). For the history and the login lockout to see each device's address
instead of the proxy's, add `MULTICDN_TRUSTED_PROXIES=1` to `.env` and restart
(`docker compose up -d`). Leave it at 0 if the panel's port can be reached any other way:
with 1, whoever connects directly could choose the address the panel records.

Self-hosted equivalents: plain WireGuard, Headscale or NetBird.

Cloudflare Zero Trust (Access + Tunnel) is free and handy, but the panel would sit behind
Cloudflare IPs, the ones being blocked during matches. Use it only in addition to one of the
options above, never as the only way in.
</details>

The sidebar shows how you reached the panel (*SSH tunnel or local*, *Tailscale*). If it warns
about any other address, the panel is exposed: fix that before continuing.

## 4. Connect Cloudflare and Gcore

In **Settings → Provider accounts → Add credential**:

**Cloudflare.** Create an API token at *My Profile → API Tokens → Create Token → Custom token*
(not the Global API Key) with:

| Permission | Why |
|---|---|
| Zone · Zone · Read | List your zones when importing |
| Zone · DNS · Edit | Read records and switch them |
| Zone · Transform Rules · Edit | Optional: lets the panel add the secret origin header (step 9) |

Zone resources: *Include · Specific zone* (one per domain) or *All zones from an account*. No
account permissions are needed. The panel checks the token when you save it and shows which
zones it can see. If your domains live in several Cloudflare accounts, add one token per
account.

**Gcore.** In the Gcore portal, *Profile → API tokens → Create token*, permanent, with the
*Administrators* or *Engineers* role (it creates origins, certificates and CDN resources). The
panel checks it when you save it. The free plan includes 1 TB of
traffic a month and up to 30 CDN resources; the panel tracks both in *Statistics*.

## 5. Add your origin server

In **Settings → Servers**, check the server the panel created from `ORIGIN_VPS1_IPV4` (or add
it). The IP is stored encrypted and is only used for the origin of Gcore and for restoring the
Cloudflare record on the way back: it is never written to a DNS-only record.

If your sites run on several servers, add one per server, even if the panel only runs on one
of them.

## 6. Import your domains

In **Domains → Import from Cloudflare**, pick the zones and, for each hostname, whether it
should switch (`www` and the apex usually; mail or internal records, no). Then, in each
domain's page, choose:

- **Mode**: *reactive* (switch when that domain's own Cloudflare IPs are blocked),
  *preventive* (also before LaLiga matches and during mass blocks) or *manual* (alerts only).
- **Priority**: *critical* domains are protected first.

## 7. Prepare each domain on Gcore

In each domain's page, **Prepare on Gcore**. The panel:

1. creates the origin group pointing at your server,
2. issues a Let's Encrypt certificate for the hostnames by DNS-01 (a temporary TXT record in
   Cloudflare; it renews automatically),
3. creates the CDN resource with the secret origin header,
4. checks that every Gcore edge serves the site.

It takes a few minutes. The domain page then shows Gcore as **Prepared**. Your DNS has not changed:
visitors still go through Cloudflare.

> 💡 Test a full switch in dry run: *Switch to Gcore* on a domain records what it would change
> in *History*, without touching DNS.

## 8. Set up alerts

In **Settings → Notifications**:

- **Telegram**: create a bot with [@BotFather](https://t.me/BotFather), paste its token, send
  any message to the bot (or add it to a group) and paste the chat ID. *Send test message*
  checks it.
- **Email** (optional): an SMTP URL such as `smtps://user:password@smtp.example.com:465` and the
  address that receives alerts.
- **Heartbeat** (recommended): create a check at [healthchecks.io](https://healthchecks.io)
  (period 5 min, grace 10 min) and paste its ping URL. The panel pings it every 5 minutes while
  everything runs; if the panel or the server goes down, healthchecks.io alerts you.

The same tab sets the language of history entries and alerts, and the monthly Gcore quota
the panel warns about.

In **Settings → Automatic switching** you can also:

- adjust the **switching times** per priority: how long before a match the preventive policy
  moves to Gcore (default 120 min for critical domains, 90 for the rest) and how long without
  blocks before returning to Cloudflare (default 20 and 15 min). The defaults come from two
  months of real block history;
- add a [football-data.org](https://www.football-data.org) key for a second match calendar
  source;
- choose how often the block feed is read when nothing is going on (default 5 min; it is read
  every 90 s on its own around matches, during blocks or while a domain is on Gcore).

Every value you save in the panel (tokens, chat ID, SMTP, heartbeat URL, keys, DSN) is also
written to `config/secrets.env` on the server, so both stay equal: see
[Panel secrets file](#panel-secrets-file-configsecretsenv).

### Error reporting (optional)

Off by default: the panel sends nothing anywhere. To receive code errors in
[Sentry](https://sentry.io) or a self-hosted [GlitchTip](https://glitchtip.com), create a
Python/FastAPI project there and paste its DSN in **Settings → System → Error reporting**.
It applies at once to logged errors; restart the panel (`docker compose restart panel`) so the
web errors are captured too. *Send test error* checks it. The DSN can also go in
`config/secrets.env` (the environment name and the tracing rate go in `.env`):

```bash
MULTICDN_SENTRY_DSN=https://<key>@errors.example.com/<project>     # config/secrets.env
# MULTICDN_SENTRY_ENVIRONMENT=production                           # .env
```

A DSN that is not valid only turns error reporting off (Settings → System says so): it never
stops the panel from starting.

Only errors are sent: unhandled exceptions in the panel and the terminal commands, failed
switches, failed notifications and background tasks that crash. Before anything leaves the
server, every IP address (your origin's included), email and token-looking value is replaced,
and requests go without cookies, headers, bodies or local variables. Performance tracing stays
off unless you set `MULTICDN_SENTRY_TRACES_SAMPLE_RATE` (0 to 1).

## 9. Protect the origin

Goal: the server answers on ports 80/443 **only to the CDNs**, even if someone learns its IP.
Two independent layers:

1. **Firewall (nftables)**: 80/443 only from the published Cloudflare and Gcore ranges. SSH,
   Tailscale, outgoing traffic and other services are untouched.
2. **Secret header (Caddy)**: each CDN adds `X-Origin-Auth` with its own secret and Caddy
   answers 403 without it, so another Cloudflare or Gcore customer cannot reach your origin
   through their own account.

The examples use Caddy; with another web server, apply the same idea (trusted proxy ranges,
reject requests without the header).

### 9.1 Install the firewall script

```bash
sudo install -m 755 deploy/firewall/multicdn-firewall.sh /usr/local/sbin/
sudo mkdir -p /etc/multicdn
sudo cp deploy/firewall/firewall.env.example /etc/multicdn/firewall.env
sudo nano /etc/multicdn/firewall.env        # PANEL_DATA = the panel's data/ folder
sudo multicdn-firewall.sh print             # review the rules (nothing is applied yet)
sudo multicdn-firewall.sh print-caddy       # and the ranges for Caddy
```

### 9.2 Make Caddy read the real client IP

Behind a CDN, the connection comes from the CDN edge. Copy `deploy/caddy/real-ip.caddy` to
`/etc/caddy/` and follow the comments in it:

1. add the global options it shows at the top of the Caddyfile,
2. add `import real_ip` inside each `reverse_proxy` block,
3. replace `{http.request.header.CF-Connecting-IP}` with `{client_ip}` wherever you use it.

### 9.3 Apply the firewall

```bash
sudo CADDY_RELOAD=0 multicdn-firewall.sh apply   # loads nftables and writes cdn-ranges.caddy
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo multicdn-firewall.sh status                 # "direct web without CDN" counts blocked attempts
```

Check that your sites still load through Cloudflare and that `client_ip` in Caddy's log is now
the visitor's IP, not the edge's. Then enable automatic updates of the ranges:

```bash
sudo install -m 644 deploy/firewall/multicdn-firewall.{service,timer} \
  deploy/firewall/multicdn-firewall-refresh.path /etc/systemd/system/
sudo nano /etc/systemd/system/multicdn-firewall-refresh.path   # only if data/ is not in /var/www/multi-cdn
sudo systemctl daemon-reload
sudo systemctl enable --now multicdn-firewall.timer multicdn-firewall-refresh.path
```

The ranges refresh every 24 hours, right before each switch to Gcore and every hour while a
domain is served by Gcore. A failed or suspicious download (empty, or less than half the
previous list) keeps the previous rules; Caddy only reloads when the ranges change and the
config validates. *Settings → Servers* shows the firewall status and alerts if it stops
updating. To undo everything: `sudo multicdn-firewall.sh remove`.

> ⚠️ If Caddy gets its own certificates by HTTP-01, the firewall blocks Let's Encrypt. Use DNS-01
> (the Cloudflare DNS module) for the sites on this server.

### 9.4 Require the secret header

1. **Keep the secret out of the logs.** For each site with `log { ... format json }`, change the
   format to:

   ```
   format filter {
       request>headers>X-Origin-Auth hash
       wrap json
   }
   ```

   and do the same for Caddy's general log, in the global options:

   ```
   log default {
       format filter {
           request>headers>X-Origin-Auth hash
           wrap json
       }
   }
   ```

   `hash` keeps the first 4 bytes of the SHA-256, enough to see which secret arrived. Note:
   `caddy validate` run as root creates missing log files owned by root, and the next reload
   fails; run `sudo chown caddy:caddy /var/log/caddy/*.log` before reloading.

2. **Gcore** already sends the header on the domains prepared from the panel (*Update on Gcore*
   brings older ones up to date).
3. **Cloudflare**: in each domain's page, *Secret origin header → Apply on Cloudflare* adds the
   zone's transform rule (needs the optional token permission of step 4).
4. **Generate Caddy's file** with the accepted values, on the server:

   ```bash
   docker compose exec -T panel python -m app.cli origin-secrets --caddy \
     | sudo tee /etc/caddy/origin-auth.caddy >/dev/null
   sudo chown root:caddy /etc/caddy/origin-auth.caddy
   sudo chmod 640 /etc/caddy/origin-auth.caddy
   ```

   Add `import /etc/caddy/origin-auth.caddy` at the top of the Caddyfile (it only defines the
   `origin_auth` snippet; nothing changes yet), validate and reload.
5. **Check that it arrives**: in the access log, requests through each CDN carry in
   `X-Origin-Auth` the hash matching the fingerprint shown by `origin-secrets`.
6. **Enforce it** site by site with `import origin_auth` inside the site block, only on domains
   whose **two** CDNs show *Up to date* in the panel. Validate, reload and check that the site
   loads through both CDNs.

### 9.5 Check from outside

From a machine that is not a CDN, `curl` to the server's IP on 80/443 must time out (firewall).
From an allowed address without the header, it must return 403 (Caddy).

## 10. Go live

When the dry run history looks right:

```bash
nano .env                  # MULTICDN_DRY_RUN=false
docker compose up -d
```

The sidebar changes to *Live DNS changes on*. Only the server's environment can turn this on:
nobody can do it from the panel.

## Panel secrets file (config/secrets.env)

The server keeps its configuration in two files next to `compose.yaml`:

| File | What | Who writes it |
|---|---|---|
| `.env` | `MULTICDN_SECRET_KEY`, `MULTICDN_DRY_RUN`, `ORIGIN_*`, `MULTICDN_ACME_EMAIL`, cookies, language, logs… | only you |
| `config/secrets.env` | the values the panel manages: `CLOUDFLARE_API_TOKEN`, `GCORE_API_TOKEN`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SMTP_URL`, `ALERT_EMAIL_TO`, `FOOTBALL_DATA_TOKEN`, `MULTICDN_HEARTBEAT_URL`, `MULTICDN_SENTRY_DSN` | the panel, and you if you want |

The panel keeps those values in two places that stay equal: its encrypted database, which is
what it uses, and `config/secrets.env`.

- **At start-up `config/secrets.env` has priority; changes in the panel are written there.**
  Every value in the file that differs from the database is imported (encrypted) and leaves a
  history entry such as *Telegram bot token updated from config/secrets.env*, never the value.
  The panel reads the file itself, so `docker compose restart` is enough after editing it.
- **Removing a line from the file does not remove the value from the panel.** To remove a
  value, use its *Remove* button in the panel (that also removes the line).
- What you save or remove in the panel rewrites the file atomically: the line of that variable
  changes (or is appended under `# Managed by the multi-cdn panel`) and every other line and
  comment stays as it was. If a variable appears twice, the last one counts (as in Compose)
  and the panel leaves only that one. A copy of the previous managed lines (never anything
  else) is kept in `data/secrets-backups/` (permissions 600, the last 10).
- The panel refuses to write any other variable. A variable it does not manage that you put in
  `config/secrets.env` by hand is ignored and shown as a problem; `MULTICDN_DRY_RUN` there keeps
  the panel in dry run until you remove it. Values with line breaks or control characters are
  ignored and reported too.
- The file is read the way Docker Compose reads it: `#` after a space starts a comment in an
  unquoted value, quoted values end at the closing quote, `$$` is a `$`, and `'single quotes'`
  are literal. The panel quotes what it writes so Compose and the panel read the same value.

**Other routes.** A managed variable that is not in `config/secrets.env` but reaches the
container another way (`environment:` in `compose.yaml`, a line left in `.env`, systemd) is
imported only when its value is new since the last start, and it is never removed from the
environment. That way a container restarted with `docker restart`, which keeps the environment
it was created with, cannot undo a change made in the panel. Precedence:
`config/secrets.env` → another route with a new value → the panel's database.

**If the file cannot be read** (permissions, not UTF-8), the panel imports nothing at all,
keeps the values it has, and shows an error in *Settings → System* and in the open problems.

With Docker, `compose.yaml` passes only `.env` as `env_file`. `config/secrets.env` is **not**
an `env_file`: the panel reads and writes it itself through the **folder** `./config`, mounted
read-write at `/app/config`
(`MULTICDN_SECRETS_PATH=/app/config/secrets.env`; a folder so the file can be replaced
atomically, which also keeps editors that save with a rename working) and does not mount
`.env` at all. `deploy/install.sh` creates `config/` (700) and `config/secrets.env` (600) owned
by you and gives the container user (uid 10001) access with an ACL, inherited by files created
there later:

```bash
sudo apt install acl                  # if setfacl is missing
sudo setfacl -m u:10001:rwx,u:$(id -u):rwx,d:u:10001:rw,d:u:$(id -u):rw config
sudo setfacl -m u:10001:rw,u:$(id -u):rw config/secrets.env
```

To keep the folder elsewhere, set `MULTICDN_SECRETS_DIR=/path/of/your/choice` in the
environment or in `.env` (Compose and `install.sh` both read it). `MULTICDN_ENV_FILE` moves
`.env` itself the same way; a relative path without `./` works for both.

If the panel cannot write the file (no ACL, read-only, not mounted), it still saves in its
database and warns on that value, in *Settings → System → Panel secrets file* and in the open
problems: on the next restart the file's value would replace the one saved in the panel, so
update that line yourself.

> 🔒 The container can write only inside `config/`, and nothing there reaches its environment
> or Compose: the panel only takes its own variables from that file. It can never turn off dry
> run, change the master key, add variables such as `PYTHONPATH` or read the `${...}` values of
> the host.

> ⚠️ `chmod` on the folder or the file, `python -m app.cli migrate-secrets` run by hand, or an
> editor that saves the file as 0600 can reset the ACL mask: run `deploy/install.sh` (or the
> `setfacl` lines) again afterwards. `install.sh` stops without changing anything if `setfacl`
> is missing.

---

## Day to day

**Update** to a new version:

```bash
cd /var/www/multi-cdn && git pull && deploy/install.sh
```

From 0.3.0 or earlier to 0.3.1: run `deploy/install.sh` after `git pull`. It moves the
panel-managed lines from `.env` to `config/secrets.env` (a full copy of the previous `.env` is
kept next to it as `.env.bak-<date>`, permissions 600; it prints which variables moved, never
their values), creates `config/` with the ACL for the container and starts the new
`compose.yaml` (Docker Compose 2.24 or later). The move needs `python3` 3.9 or later on the
server; without it the script lists the lines to move by hand. Once the panel works, delete the
`.env.bak-*` copy (it holds your tokens). On its first start 0.3.1 imports into the database
every value of `config/secrets.env` that differs from it (see
[Panel secrets file](#panel-secrets-file-configsecretsenv)).

By hand, without `install.sh`:

```bash
mkdir -p config && chmod 700 config
python3 -m app.migrate_secrets .env config/secrets.env   # or move the lines yourself
chmod 600 config/secrets.env
sudo setfacl -m u:10001:rwx,u:$(id -u):rwx,d:u:10001:rw,d:u:$(id -u):rw config
sudo setfacl -m u:10001:rw,u:$(id -u):rw config/secrets.env
docker compose up -d
```

**Backups.** The panel makes one a day in `data/backups/` and keeps the last 14; take one by
hand with `docker compose exec panel python -m app.cli backup`. Copy them off the server if you
want to survive losing it. They are useless without the master key, so keep that key in your
password manager too.

**When the panel is down**, switch from the terminal. It uses the same code and safeguards as
the panel: it checks Gcore before switching, records the change in history, sends the alerts
and pauses automation for that domain for an hour.

```bash
cd /var/www/multi-cdn
docker compose exec panel python -m app.cli status                    # where each domain is served
docker compose exec panel python -m app.cli switch example.com gcore  # asks you to type the domain
docker compose exec panel python -m app.cli switch example.com cloudflare
# with the container stopped or stuck:
docker compose run --rm panel python -m app.cli switch example.com gcore
```

`--force` switches to Gcore even if the check fails; `--yes` skips the confirmation.

**Rotate an origin secret** without downtime (for example, if it leaked):

```bash
docker compose exec panel python -m app.cli rotate-origin-secret gcore   # the old one is still accepted
# regenerate /etc/caddy/origin-auth.caddy (step 9.4.4) and reload Caddy
# apply the new secret on that CDN in every domain (Update on Gcore / Apply on Cloudflare)
docker compose exec panel python -m app.cli retire-previous-secret gcore
# regenerate the file again and reload Caddy
```

## Moving a panel you already run elsewhere

1. Stop the old panel: two copies must never run at once (both would take decisions and send
   alerts).
2. Copy a consistent snapshot of the database and the Gcore certificates:

   ```bash
   python3 -c "import sqlite3; s=sqlite3.connect('data/multicdn.db'); d=sqlite3.connect('/tmp/multicdn.db'); s.backup(d)"
   scp /tmp/multicdn.db <user>@<server>:/var/www/multi-cdn/data/
   scp -r data/certbot <user>@<server>:/var/www/multi-cdn/data/
   ```

3. Certbot's renewal files store absolute paths; point them to the container's:

   ```bash
   sed -i "s|<old path>/data/certbot|/app/data/certbot|g" /var/www/multi-cdn/data/certbot/config/renewal/*.conf
   ```

4. Put the old master key in `MULTICDN_SECRET_KEY` of the new `.env` (not in `data/`). Copy
   the old `config/secrets.env` too if you want it on the new server (the copied database
   already has those values), then run `deploy/install.sh` (it prepares `config/` for the
   panel, see [Panel secrets file](#panel-secrets-file-configsecretsenv)). Open sessions stay
   valid. Values in the new `config/secrets.env` replace the ones in the copied database on the
   first start; with an empty file the database keeps its own.
