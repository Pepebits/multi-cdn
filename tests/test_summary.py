"""Weekly summary: when it is due, what it says, once per week, and the switch in Settings."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx

from app import event_codes, summary
from app.notifier import Notifier, format_text, should_notify
from app.signals.hayahora import parse_feed

MONDAY = datetime(2026, 11, 23, 7, 30, tzinfo=UTC)  # a Monday, after 07:00 UTC
CF_IP = "188.114.96.5"


def blocked_feed(now: datetime):
    """example.com's Cloudflare IP blocked at three ISPs for 3 h, two days before `now`."""
    ts = lambda d: (now - d).strftime("%Y-%m-%d %H:%M:%SZ")
    return parse_feed({"lastUpdate": ts(timedelta(0)), "data": [
        {"ip": CF_IP, "isp": isp, "description": "Cloudflare",
         "stateChanges": [{"timestamp": ts(timedelta(days=2, hours=3)), "state": True},
                          {"timestamp": ts(timedelta(days=2)), "state": False}]}
        for isp in ("Movistar", "Vodafone", "Orange")]})


def test_due_only_on_monday_morning_and_once_per_week(client):
    state = client.app.state.mc
    assert not summary.due(state, MONDAY.replace(hour=6))
    assert not summary.due(state, MONDAY + timedelta(days=1))  # Tuesday
    assert summary.send_if_due(state, MONDAY)
    assert not summary.send_if_due(state, MONDAY + timedelta(hours=3))  # same week: once
    assert summary.due(state, MONDAY + timedelta(days=7))


def test_the_summary_counts_blocks_unprotected_time_and_quiet_domains(client):
    state = client.app.state.mc
    state.feed = blocked_feed(MONDAY)
    state.engine.remember_ips("example.com", [CF_IP], now=MONDAY)
    summary.send_if_due(state, MONDAY)
    event = state.events.list(limit=1)[0]
    assert event.code == event_codes.WEEKLY_SUMMARY
    assert event.summary.startswith("Resumen semanal") and "1 episodio de bloqueo" in event.summary
    assert "3 h sin protección" in event.summary
    assert "example.com: 1 episodio de bloqueo · 3 h sin protección" in event.signals
    assert "example.net: sin bloqueos" in event.signals


def test_it_is_sent_with_one_line_per_domain(client):
    state = client.app.state.mc
    summary.send_if_due(state, MONDAY)
    event = state.events.list(limit=1)[0]
    as_dict = {"kind": event.kind, "summary": event.summary, "domain": None, "signals": event.signals,
               "code": event.code, "actor": "auto", "dns_diff": [], "transition": None, "simulated": False}
    assert should_notify(as_dict)
    _subject, body = format_text(as_dict)
    assert body.startswith("📊 Multi-CDN: Resumen semanal") and body.endswith("example.com: sin bloqueos\nexample.net: sin bloqueos")
    sent = []
    transport = httpx.MockTransport(lambda r: sent.append(json.loads(r.content)) or httpx.Response(200, json={"ok": True}))

    class Secrets(dict):
        def get(self, k, d=None):
            return super().get(k, d)
    n = Notifier(Secrets(telegram_token="t", telegram_chat_id="42"),
                 client_factory=lambda **kw: httpx.AsyncClient(transport=transport, **kw))
    asyncio.run(n.send(as_dict))
    assert "example.net: sin bloqueos" in sent[0]["text"]


def test_turned_off_in_settings_it_is_not_sent(client):
    state = client.app.state.mc
    page = client.get("/ajustes/notificaciones").text
    assert "Resumen semanal" in page and 'action="/ajustes/notificaciones/resumen"' in page
    r = client.post("/ajustes/notificaciones/resumen", data={"enabled": "0"}, follow_redirects=True)
    assert "Resumen semanal desactivado" in r.text
    assert not summary.send_if_due(state, MONDAY)
    client.post("/ajustes/notificaciones/resumen", data={"enabled": "1"})
    assert summary.send_if_due(state, MONDAY)
