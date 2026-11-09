<p align="center"><img src="docs/banner.png" alt="multi-cdn" width="720"></p>

Keeps sites online during Cloudflare IP blocks by failing over to Gcore, **without ever
publishing the origin server's IP**.

In Spain, ISPs block ranges of Cloudflare IPs by court order during LaLiga matches, and
every unrelated site behind those IPs goes down with them. The usual workaround, turning
off Cloudflare's proxy, publishes the origin IP for good. multi-cdn moves each domain to a
second CDN instead, before or as soon as its Cloudflare IPs are blocked, and moves it back
once the block is over.

> The panel and the deployment guide are in Spanish for now; English is planned.

## How it works

- **Signals**: the public block feed by ISP ([hayahora.futbol](https://hayahora.futbol)),
  mass-block detection and the LaLiga match calendar (ESPN, football-data.org).
- **Decision per domain**: reactive (switch when its own IPs are blocked), preventive
  (also before matches and during mass blocks) or manual (alerts only). It returns to
  Cloudflare after 45/30 min without blocks, never decides on a stale feed, limits
  flapping, and pauses after a manual change or for maintenance.
- **DNS, guarded in code**: a hostname is either proxied by Cloudflare or a DNS-only CNAME
  to Gcore. The Cloudflare adapter refuses any write that would expose the origin.
- **Gcore prepared ahead**: origin group, Let's Encrypt certificate by DNS-01 (renewed
  automatically), CDN resource and a secret origin header, checked on every edge before a
  switch.
- **Origin protection** (`deploy/`): an nftables firewall that only lets the CDNs reach
  ports 80/443, and Caddy snippets that require the secret `X-Origin-Auth` header and
  restore the real client IP.
- **Operations**: Telegram and email alerts, an external heartbeat, origin health checks,
  statistics, Gcore traffic against its free quota, backups, and a terminal runbook for
  when the panel itself is down.

## Run it

```bash
mkdir multi-cdn && cd multi-cdn
curl -fsSLO https://raw.githubusercontent.com/Pepebits/multi-cdn/main/compose.yaml
curl -fsSL https://raw.githubusercontent.com/Pepebits/multi-cdn/main/.env.example -o .env
# set MULTICDN_SECRET_KEY in .env (see the comment there) and keep MULTICDN_DRY_RUN=true
docker compose up -d
docker compose exec panel python -m app.cli crear-usuario <user>
```

The panel listens on `127.0.0.1:8765` only. Reach it through an SSH tunnel
(`ssh -N -L 8765:127.0.0.1:8765 <user>@<server>`) or a private network such as Tailscale,
never through the CDNs it controls. DNS changes are simulated until
`MULTICDN_DRY_RUN=false` is set in the server environment; the panel cannot turn them on.

The image (`ghcr.io/pepebits/multi-cdn`, also on Docker Hub) is Alpine-based, runs as a
non-root user with a read-only root filesystem, and is built for amd64 and arm64 with an
SBOM and provenance.

Full deployment, firewall and Caddy setup: [`deploy/README.md`](deploy/README.md).

## Develop

```bash
cp .env.example .env
uv sync
uv run pytest
uv run python -m app.cli crear-usuario <user>
uv run uvicorn app.main:app --host 127.0.0.1 --port 8765
```

FastAPI with server-rendered templates, no frontend build. SQLite for inventory,
encrypted credentials, history and engine state. Examples and tests only use
`example.com` and documentation IPs.

## Security

- Login with password (scrypt) and mandatory TOTP, recovery codes, short sessions and
  lockouts; the first user can only be created from the server's terminal.
- CSRF tokens, `Origin` checks, a strict CSP without inline scripts.
- Provider credentials and the origin IP are encrypted at rest with a key kept outside
  the database, and never shown again or exported.

Report vulnerabilities privately through GitHub's security advisories, not in issues.

## Design

Neo-brutalist system shared with the other Pepebits products ([`DESIGN.md`](DESIGN.md)).
The panel is audited with axe-core and Lighthouse in light and dark themes.

## License

[Apache 2.0](LICENSE) · a [Pepebits](https://pepebits.com) product.
