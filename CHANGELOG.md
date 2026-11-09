# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-09

First release: a private panel and controller that keeps sites reachable in Spain
during the court-ordered blocks of Cloudflare IPs, by moving DNS to a second CDN
(Gcore) without ever publishing the origin server's IP.

### Added

- **Automatic failover** between Cloudflare and Gcore per domain, driven by the
  public block feed (hayahora.futbol), mass-block detection and the LaLiga match
  calendar (ESPN and football-data.org). Reactive, preventive and manual policies,
  a 45/30 min quiet period before returning, flap protection, a 1 h hold after a
  manual change and per-domain maintenance windows.
- **Origin guard**: the Cloudflare adapter refuses any DNS write that would expose
  the origin IP; a hostname is either proxied by Cloudflare or a DNS-only CNAME to
  the backup CDN.
- **Gcore preparation by API**: origin group, Let's Encrypt certificate by DNS-01
  (uploaded to Gcore and renewed 30 days before expiry, with alerts at 21 and 7
  days), CDN resource with WebSockets, host/SNI forwarding and a secret origin
  header; checked against every edge before any switch.
- **Origin protection kit** (`deploy/`): nftables firewall limited to CDN ranges,
  refreshed daily and before every switch, and Caddy snippets for the real client
  IP and the secret `X-Origin-Auth` header, applied to Cloudflare from the panel
  and rotated without downtime.
- **Panel** (FastAPI, server-rendered): domains, hostnames and provider accounts,
  live block status per ISP, statistics rebuilt from two months of feed history,
  change history with DNS diffs, light/dark theme, accessible markup.
- **Security**: password + TOTP login with recovery codes and lockouts, CSRF and
  strict CSP, credentials encrypted at rest, real DNS changes only enabled from the
  server environment.
- **Operations**: Telegram and email alerts, external heartbeat
  (healthchecks.io), origin health checks, Gcore traffic against the free quota,
  daily database backups, and a terminal runbook (`python -m app.cli estado` and
  `cambiar`) for when the panel is down.
- **Docker image** (~160 MB, Alpine, Python 3.15, non-root, read-only friendly) published to
  GitHub Container Registry and Docker Hub.

[Unreleased]: https://github.com/Pepebits/multi-cdn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Pepebits/multi-cdn/releases/tag/v0.1.0
