"""Calendario de partidos (señal preventiva S3).

Los bloqueos se ordenan durante los partidos de LaLiga (Primera y Segunda), así que una
ventana alrededor de cada partido permite pasar a Gcore antes de que lleguen y de que las
cachés DNS lo noten.

Fuentes:
  - ESPN (marcadores públicos, no oficiales, sin clave): Primera y Segunda.
  - football-data.org (API con clave gratuita): solo Primera en el plan gratuito.
Se unen: si un partido aparece en cualquiera de las dos, cuenta. Basta con que responda
una para tener calendario; el panel indica qué fuente falla.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from ..i18n import tn

SOURCE = "https://site.api.espn.com/apis/site/v2/sports/soccer/{league}/scoreboard"
COMPETITIONS = {"esp.1": "LaLiga", "esp.2": "LaLiga Hypermotion"}
SKIP_STATUS = {"STATUS_POSTPONED", "STATUS_CANCELED", "STATUS_ABANDONED", "STATUS_FORFEIT"}
DAYS_AHEAD = 8
MATCH_LENGTH = timedelta(hours=2, minutes=30)  # 90 min + descanso + añadido + margen


@dataclass(frozen=True)
class Match:
    competition: str
    home: str
    away: str
    kickoff: datetime
    status: str

    @property
    def name(self) -> str:
        return f"{self.home} – {self.away}"


@dataclass
class Calendar:
    matches: list[Match]
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    sources: dict = field(default_factory=dict)  # fuente -> "ok" | error

    def active(self, now: datetime, lead: timedelta) -> Match | None:
        """Partido cuya ventana [inicio − lead, inicio + duración] incluye ahora."""
        for m in self.matches:
            if m.kickoff - lead <= now <= m.kickoff + MATCH_LENGTH:
                return m
        return None

    def upcoming(self, now: datetime) -> Match | None:
        return next((m for m in self.matches if m.kickoff > now), None)

    def is_stale(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) - self.fetched_at > timedelta(hours=24)


def parse_scoreboard(payload: dict, competition: str) -> list[Match]:
    matches = []
    for event in payload.get("events", []):
        status = event.get("status", {}).get("type", {}).get("name", "")
        if status in SKIP_STATUS:
            continue
        comp = (event.get("competitions") or [{}])[0]
        teams = {c.get("homeAway"): c.get("team", {}).get("displayName", "?") for c in comp.get("competitors", [])}
        kickoff = datetime.fromisoformat(event["date"].replace("Z", "+00:00"))
        matches.append(Match(competition, teams.get("home", "?"), teams.get("away", "?"), kickoff, status))
    return matches


FD_SOURCE = "https://api.football-data.org/v4/competitions/PD/matches"
FD_SKIP = {"POSTPONED", "CANCELLED", "SUSPENDED", "AWARDED"}


def parse_football_data(payload: dict) -> list[Match]:
    return [Match("LaLiga", m["homeTeam"].get("shortName") or m["homeTeam"].get("name", "?"),
                  m["awayTeam"].get("shortName") or m["awayTeam"].get("name", "?"),
                  datetime.fromisoformat(m["utcDate"].replace("Z", "+00:00")), m.get("status", ""))
            for m in payload.get("matches", []) if m.get("status") not in FD_SKIP]


async def _espn(client: httpx.AsyncClient, now: datetime) -> list[Match]:
    """Un día por petición (la fuente no admite rangos). Una liga caída invalida la fuente entera."""
    found: dict[tuple, Match] = {}
    for league, label in COMPETITIONS.items():
        for offset in range(-1, DAYS_AHEAD + 1):
            day = now + timedelta(days=offset)
            r = await client.get(SOURCE.format(league=league), params={"dates": f"{day:%Y%m%d}"}, timeout=20)
            r.raise_for_status()
            for m in parse_scoreboard(r.json(), label):
                found[(m.competition, m.home, m.away, m.kickoff)] = m
    return list(found.values())


async def _football_data(client: httpx.AsyncClient, token: str, now: datetime) -> list[Match]:
    r = await client.get(FD_SOURCE, headers={"X-Auth-Token": token}, timeout=20, params={
        "dateFrom": f"{now - timedelta(days=1):%Y-%m-%d}", "dateTo": f"{now + timedelta(days=DAYS_AHEAD):%Y-%m-%d}"})
    if r.status_code in (401, 403):
        raise RuntimeError(tn("football-data.org rejected the key (HTTP {status})", status=r.status_code))
    r.raise_for_status()
    return parse_football_data(r.json())


def merge(primary: list[Match], extra: list[Match]) -> list[Match]:
    """Une las fuentes. Los nombres de equipo no coinciden entre ellas: un partido de la segunda
    fuente se añade solo si no hay ninguno de la misma competición a la misma hora."""
    seen = {(m.competition, m.kickoff) for m in primary}
    return sorted(primary + [m for m in extra if (m.competition, m.kickoff) not in seen], key=lambda m: m.kickoff)


async def fetch_calendar(client: httpx.AsyncClient, now: datetime | None = None,
                         football_data_token: str | None = None) -> Calendar:
    now = now or datetime.now(UTC)
    sources: dict[str, str] = {}
    espn: list[Match] = []
    fd: list[Match] = []
    try:
        espn = await _espn(client, now)
        sources["ESPN"] = "ok"
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        sources["ESPN"] = f"{type(exc).__name__}: {exc}"
    if football_data_token:
        try:
            fd = await _football_data(client, football_data_token, now)
            sources["football-data.org"] = "ok"
        except (httpx.HTTPError, ValueError, KeyError, RuntimeError) as exc:
            sources["football-data.org"] = str(exc) if isinstance(exc, RuntimeError) else f"{type(exc).__name__}: {exc}"
    if "ok" not in sources.values():
        raise RuntimeError("; ".join(f"{k}: {v}" for k, v in sources.items()))
    return Calendar(merge(espn, fd), sources=sources)


async def fetch_past_laliga(client: httpx.AsyncClient, token: str, start: datetime, end: datetime) -> list[Match]:
    """Partidos de LaLiga de un periodo pasado (para las estadísticas): una sola petición."""
    r = await client.get(FD_SOURCE, headers={"X-Auth-Token": token}, timeout=30, params={
        "dateFrom": f"{start:%Y-%m-%d}", "dateTo": f"{end:%Y-%m-%d}"})
    r.raise_for_status()
    return parse_football_data(r.json())
