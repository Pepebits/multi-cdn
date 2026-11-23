"""Feed público de bloqueos de hayahora.futbol (no oficial).

Formato observado (nov-2026):
  {"lastUpdate": "2026-11-07 20:42:25Z",
   "data": [{"ip": "...", "isp": "Movistar", "description": "Cloudflare",
             "stateChanges": [{"timestamp": "...Z", "state": true|false}, ...]}]}
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from ..i18n import tn

FEED_URL = "https://hayahora.futbol/estado/data.json"

# Operadoras en el orden en que se muestran; clave = nombre en el feed.
ISPS: dict[str, str] = {
    "Movistar": "Movistar",
    "Vodafone": "Vodafone",
    "Orange": "Orange",
    "DIGI": "Digi",
    "Masmovil": "MásMóvil",
}


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=UTC)


@dataclass(frozen=True)
class IspState:
    blocked: bool
    since: datetime | None


@dataclass
class FeedSnapshot:
    last_update: datetime
    fetched_at: datetime
    # ip -> isp(feed name) -> estado actual
    states: dict[str, dict[str, IspState]] = field(default_factory=dict)
    providers: dict[str, str] = field(default_factory=dict)
    # ip -> [(momento, operadora, bloqueada)] en orden: el historial completo (unos 2 meses)
    history: dict[str, list[tuple[datetime, str, bool]]] = field(default_factory=dict)

    def is_stale(self, now: datetime | None = None, max_age: timedelta = timedelta(minutes=10)) -> bool:
        return (now or datetime.now(UTC)) - self.last_update > max_age

    def monitored(self, ip: str) -> bool:
        return ip in self.states

    def state(self, ip: str, isp: str) -> IspState | None:
        return self.states.get(ip, {}).get(isp)

    def blocked_ips(self, min_isps: int = 3, provider_contains: str = "Cloudflare") -> int:
        """IPs del proveedor bloqueadas ahora mismo en al menos `min_isps` operadoras."""
        count = 0
        for ip, by_isp in self.states.items():
            if provider_contains not in self.providers.get(ip, ""):
                continue
            if sum(s.blocked for s in by_isp.values()) >= min_isps:
                count += 1
        return count


# A real feed lists ~3,100 IPs at all five ISPs (Nov 2026). An empty or reshaped feed would
# otherwise read as "no blocks" and send domains back to Cloudflare in the middle of a block.
MIN_FEED_IPS = 300
MIN_FEED_ISPS = 3
MAX_FEED_DROP = 0.5  # fewer than half the IPs of the last good read: reject it (see check_feed)


class FeedFormatError(ValueError):
    """The feed answered, but not with something we can trust."""


def check_feed(snapshot: FeedSnapshot, previous: FeedSnapshot | None = None) -> None:
    """Raises FeedFormatError if the snapshot does not look like a real feed. `previous`: the
    last good read while it is still fresh; once it goes stale a lasting change is accepted."""
    ips = len(snapshot.states)
    if ips < MIN_FEED_IPS:
        raise FeedFormatError(tn("only {n} IPs instead of thousands", n=ips))
    isps = {isp for per_ip in snapshot.states.values() for isp in per_ip} & set(ISPS)
    if len(isps) < MIN_FEED_ISPS:
        raise FeedFormatError(tn("only {n} of the known ISPs", n=len(isps)))
    if previous is not None and ips < MAX_FEED_DROP * len(previous.states):
        raise FeedFormatError(tn("{n} IPs, down from {before} in the previous read", n=ips, before=len(previous.states)))


def parse_feed(payload: dict, fetched_at: datetime | None = None) -> FeedSnapshot:
    states: dict[str, dict[str, IspState]] = defaultdict(dict)
    providers: dict[str, str] = {}
    history: dict[str, list[tuple[datetime, str, bool]]] = defaultdict(list)
    for entry in payload.get("data", []):
        changes = sorted(entry.get("stateChanges", []), key=lambda c: c["timestamp"])
        if not changes:
            continue
        last = changes[-1]
        states[entry["ip"]][entry["isp"]] = IspState(blocked=bool(last["state"]), since=_ts(last["timestamp"]))
        providers[entry["ip"]] = entry.get("description", "")
        history[entry["ip"]] += [(_ts(c["timestamp"]), entry["isp"], bool(c["state"])) for c in changes]
    for changes in history.values():
        changes.sort()
    return FeedSnapshot(
        last_update=_ts(payload["lastUpdate"]),
        fetched_at=fetched_at or datetime.now(UTC),
        states=dict(states),
        providers=providers,
        history=dict(history),
    )


async def fetch_feed(client: httpx.AsyncClient, etag: str | None = None) -> tuple[FeedSnapshot | None, str | None]:
    """Conditional GET: (snapshot, ETag). With 304 Not Modified the feed has not changed:
    (None, etag), and the caller keeps its snapshot (the body is ~4.6 MB, ~0.4 MB gzipped)."""
    headers = {"If-None-Match": etag} if etag else {}
    response = await client.get(FEED_URL, timeout=20, headers=headers)
    if response.status_code == 304:
        return None, etag
    response.raise_for_status()
    return parse_feed(response.json()), response.headers.get("ETag")
