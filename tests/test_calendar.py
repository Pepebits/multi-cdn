"""Calendario con dos fuentes: ESPN (Primera y Segunda) y football-data.org (Primera)."""

import asyncio
from datetime import UTC, datetime

import httpx
import pytest

from app.signals import calendar

NOW = datetime(2026, 11, 8, 12, tzinfo=UTC)


def espn_event(date, home, away, status="STATUS_SCHEDULED"):
    return {"date": date, "status": {"type": {"name": status}}, "competitions": [{"competitors": [
        {"homeAway": "home", "team": {"displayName": home}}, {"homeAway": "away", "team": {"displayName": away}}]}]}


def fd_match(date, home, away, status="TIMED"):
    return {"utcDate": date, "status": status, "homeTeam": {"shortName": home}, "awayTeam": {"shortName": away}}


def client(espn_ok=True, fd_status=200):
    def handler(request: httpx.Request):
        if request.url.host == "site.api.espn.com":
            if not espn_ok:
                return httpx.Response(500)
            league = request.url.path.split("/")[-2]
            day = request.url.params["dates"]
            events = []
            if league == "esp.1" and day == "20261108":
                events = [espn_event("2026-11-08T20:00Z", "Atlético Madrid", "Barcelona")]
            if league == "esp.2" and day == "20261109":
                events = [espn_event("2026-11-09T19:30Z", "Albacete", "Eibar")]
            return httpx.Response(200, json={"events": events})
        assert request.headers["X-Auth-Token"] == "fd-token"
        return httpx.Response(fd_status, json={"matches": [
            fd_match("2026-11-08T20:00:00Z", "Atleti", "Barça"),            # mismo partido que en ESPN
            fd_match("2026-11-10T18:00:00Z", "Sevilla FC", "Betis"),        # solo en football-data
            fd_match("2026-11-11T18:00:00Z", "Girona", "Getafe", "POSTPONED"),
        ]})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def fetch(**kw):
    async def run():
        async with client(**{k: v for k, v in kw.items() if k in ("espn_ok", "fd_status")}) as c:
            return await calendar.fetch_calendar(c, NOW, football_data_token=kw.get("token"))
    return asyncio.run(run())


def test_sources_are_merged_without_duplicates():
    cal = fetch(token="fd-token")
    assert [m.name for m in cal.matches] == ["Atlético Madrid – Barcelona", "Albacete – Eibar", "Sevilla FC – Betis"]
    assert cal.sources == {"ESPN": "ok", "football-data.org": "ok"}


def test_one_source_is_enough():
    cal = fetch(espn_ok=False, token="fd-token")
    assert [m.name for m in cal.matches] == ["Atleti – Barça", "Sevilla FC – Betis"]
    assert cal.sources["ESPN"].startswith("HTTPStatusError")
    cal = fetch(fd_status=403, token="fd-token")
    assert "rechazó la clave" in cal.sources["football-data.org"] and len(cal.matches) == 2


def test_no_source_raises():
    with pytest.raises(RuntimeError, match="ESPN"):
        fetch(espn_ok=False)


def test_panel_saves_the_key_encrypted_and_shows_sources(client, monkeypatch):
    from app import main
    state = client.app.state.mc

    async def fake_fetch(http, now=None, football_data_token=None):
        assert football_data_token == "fd-token-123"
        return calendar.Calendar([], sources={"ESPN": "ok", "football-data.org": "ok"})
    monkeypatch.setattr(main.match_calendar, "fetch_calendar", fake_fetch)
    r = client.post("/ajustes/operacion/football-data", data={"token": "fd-token-123"}, follow_redirects=True)
    assert "Clave guardada y verificada" in r.text and "Responde" in r.text
    row = state.secrets.conn.execute("SELECT ciphertext FROM secrets WHERE name='football_data_token'").fetchone()
    assert b"fd-token-123" not in row[0]
    r = client.post("/ajustes/operacion/football-data/eliminar", follow_redirects=True)
    assert state.secrets.get("football_data_token") is None
