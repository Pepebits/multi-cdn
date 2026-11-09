# multi-cdn

Keeps sites online during Cloudflare IP blocks by failing over to Gcore, without
exposing the origin.

In Spain, ISPs block ranges of Cloudflare IPs by court order during LaLiga matches,
taking unrelated sites down with them. multi-cdn watches the public block feed and
the match calendar, moves each domain's DNS to Gcore before or when its Cloudflare
IPs are blocked, and moves it back once the block is over. A hostname is only ever
proxied by Cloudflare or a CNAME to the backup CDN: the origin IP is never published.

It ships as a private panel (login with password + TOTP) plus the controller that
does the switching, Gcore preparation (certificates included) and alerts. The panel
is in English and Spanish.

## Run

```bash
docker run -d --name multicdn-panel --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8765:8765 -v ./data:/app/data --env-file .env \
  pepebits/multi-cdn:latest
docker exec -it multicdn-panel python -m app.cli create-user <user>
```

The panel listens on `127.0.0.1:8765`: reach it through an SSH tunnel or a private
network (Tailscale, WireGuard), never through the CDNs it controls. `.env` needs at
least `MULTICDN_SECRET_KEY`; `MULTICDN_DRY_RUN=true` (the default) only simulates DNS
changes. Full deployment guide, origin firewall and Caddy snippets:
[github.com/Pepebits/multi-cdn](https://github.com/Pepebits/multi-cdn).

Image: Alpine, non-root (uid 10001), works with a read-only root filesystem; data in
`/app/data`. Multi-arch (amd64, arm64), with SBOM and build provenance. Also published
as `ghcr.io/pepebits/multi-cdn`.
