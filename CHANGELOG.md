# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-11-14

Interface improvements from a review of the panel in every state, on desktop and phone.

### Changed
- **Typing the domain to confirm** a switch, return or deletion works on phones: no automatic
  capital letter, the field gets the focus when the dialog opens, and the check ignores case.
- **Getting started** no longer pushes the live status down: once there are domains it is
  folded at the bottom of the overview.
- The overview and the domain list show when a domain's automatic switching is paused, in
  maintenance or failed, and the overview opens with a one-line summary (domains on Gcore,
  exposed, needing attention).
- A failed automatic switch is shown first, with a "Dismiss failure" button instead of a
  misleading "Resume now".
- The domain page's main button follows the state: "Back to Cloudflare" when it is already on
  Gcore, and a hint when the origin is exposed.
- Upcoming switch and return times are larger and add "in 52 min (local time)" next to UTC.
- Sign out, access channel and DNS mode are available on phones.
- Dark theme: saturated status colours and higher-contrast borders.
- Small buttons no longer carry the red danger shadow; larger touch targets on phones; dialogs
  fit the screen with the keyboard open; the warning about ongoing blocks comes first in the
  return dialog.
- Statistics: the last day label is no longer cut and match bands are visible.
- Matches tile says "No upcoming matches" instead of "Loading…" forever; status blocks carry
  an icon; clearer wording in both languages.

## [0.2.1] - 2026-11-14

### Changed
- **Switching times are configurable** per priority in Settings → Operation, with new defaults
  taken from two months of block history (6,103 block endings, 95 matches): blocks start a
  median of 68 min before kick-off, so the preventive switch now happens 120 min before a match
  for critical domains (90 for the rest, was 45/30); a released IP was blocked again within
  15 min only 0.05 % of the time, so the return to Cloudflare now waits 20 min without blocks
  for critical domains (15 for the rest, was 45/30).

### Fixed
- Deleting a domain could delete its Gcore resource while DNS still pointed at it (always in
  dry run, where the DNS change is only simulated). It is now refused until DNS is back on
  Cloudflare.
- A switch made from the terminal was undone by the running panel within 90 s: the engine now
  re-reads its state every cycle and re-checks pauses right before touching DNS.
- Resuming a domain paused for too many switches paused it again on the next cycle.
- A failure that repeated on a later day (for example the following match) did not alert again.
- Manual switches, maintenance and deletion no longer race with an engine cycle.
- One failing domain no longer stops the engine for the others; background errors are logged,
  and the external heartbeat reports an engine that stops completing cycles.
- A block feed answering with old data now raises an alert (and another when it recovers).
- Email alerts verify the SMTP server's TLS certificate, and multi-line alerts are no longer
  dropped.
- The statistics page no longer fails when a hostname is momentarily unresolved.
- A warning when a switching hostname has several A/AAAA records on Cloudflare, which would make
  the switch to Gcore fail.
- Firewall script: it no longer follows links planted in the panel's data folder, restores the
  previous rules if the first run after a reboot cannot download the ranges, and retries every
  5 min after a failure.
- Panel backups are created private from the start and no longer leave SQLite side files
  behind.
- Releases are only published after the full CI passes.

## [0.2.0] - 2026-11-09

### Added
- **English interface**, with Spanish kept: each browser gets its preferred language and can
  switch in the footer. History entries, alerts and terminal output follow a separate setting
  (Settings → Operation); installs that already have history keep Spanish.
- **Getting started checklist** on the overview, with links to each pending step.
- English command names for the CLI (`create-user`, `status`, `switch`, `origin-secrets`…); the
  Spanish names keep working.
- Icons on headings, buttons and notices across the panel, including Telegram and email in
  the notification settings.

### Changed
- Step-by-step deployment guide in English (`deploy/README.md`), from an empty server to live
  failover.

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

[0.2.2]: https://github.com/Pepebits/multi-cdn/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Pepebits/multi-cdn/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Pepebits/multi-cdn/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Pepebits/multi-cdn/releases/tag/v0.1.0
