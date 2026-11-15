"""What the panel takes from a reverse proxy in front of it (ADR-004).

uvicorn runs without --proxy-headers: with them and --forwarded-allow-ips "*", any client could
set its own address with X-Forwarded-For, dodge the login lockout, lock somebody else out or
put text of its choice in the alerts.

- ForwardedScheme: the scheme from X-Forwarded-Proto (http or https), so that url_for() builds
  https:// links and the session cookie is Secure behind `tailscale serve`. The client can only
  make its own links and cookies stricter with it.
- client_ip(): the address used for lockouts and in the history. With
  MULTICDN_TRUSTED_PROXIES=0 (default) it is the socket peer; with 1 (one proxy in front, e.g.
  `tailscale serve`) it is the right-most valid X-Forwarded-For entry, the one that proxy added.
"""

from __future__ import annotations

import ipaddress
import os

from starlette.types import ASGIApp, Receive, Scope, Send

_SCHEMES = {"http": {"http": "http", "https": "https"}, "websocket": {"http": "ws", "https": "wss"}}


class ForwardedScheme:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in _SCHEMES:
            for name, value in scope.get("headers") or ():
                if name == b"x-forwarded-proto":
                    proto = value.decode("latin-1").split(",")[-1].strip().lower()
                    if proto in ("http", "https"):
                        scope = dict(scope, scheme=_SCHEMES[scope["type"]][proto])
                    break
        await self.app(scope, receive, send)


def trusted_proxies() -> int:
    raw = os.environ.get("MULTICDN_TRUSTED_PROXIES", "0").strip()
    return 1 if raw == "1" else 0


def _valid_ip(value: str) -> str | None:
    value = value.strip()
    if value.startswith("[") and "]" in value:          # [2001:db8::1]:1234
        value = value[1:value.index("]")]
    elif value.count(":") == 1:                          # 192.0.2.1:1234
        value = value.split(":")[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def client_ip(request) -> str:
    peer = request.client.host if request.client else "?"
    if trusted_proxies() == 0:
        return peer
    entries = ",".join(request.headers.getlist("x-forwarded-for")).split(",")
    for entry in reversed(entries):
        if entry.strip():
            # Only the right-most entry was written by the proxy; anything to its left is the client's.
            return _valid_ip(entry) or peer
    return peer
