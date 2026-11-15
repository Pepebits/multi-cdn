from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app import alerts
from app.db import EventStore
from app.error_reporting import scrub_origin, set_origin_ips

T0 = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def _state(tmp_path):
    return SimpleNamespace(events=EventStore(tmp_path / "a.db"))


def test_problem_waits_alerts_once_and_recovers(tmp_path):
    s = _state(tmp_path)
    assert not alerts.problem(s, "feed_down", "down", after=timedelta(seconds=90), now=T0)
    assert alerts.problem(s, "feed_down", "down", after=timedelta(seconds=90), now=T0 + timedelta(seconds=95))
    assert not alerts.problem(s, "feed_down", "down", after=timedelta(seconds=90), now=T0 + timedelta(minutes=5))
    # survives a restart: a new state on the same database
    s2 = SimpleNamespace(events=EventStore(tmp_path / "a.db"))
    lasted = alerts.clear(s2, "feed_down", lambda d: f"back after {alerts.minutes(d)} min", now=T0 + timedelta(minutes=12))
    assert lasted == timedelta(minutes=12)
    assert [e.summary for e in s2.events.list()] == ["back after 12 min", "down"]
    assert alerts.clear(s2, "feed_down", "again") is None


def test_short_problem_is_silent_and_fingerprint_realerts(tmp_path):
    s = _state(tmp_path)
    alerts.problem(s, "x", "p", after=timedelta(minutes=5), now=T0)
    alerts.clear(s, "x", "recovered", now=T0 + timedelta(minutes=1))
    assert s.events.list() == []
    alerts.problem(s, "d:example.com", "a", fingerprint="no_zone", now=T0)
    alerts.problem(s, "d:example.com", "b", fingerprint="no_zone", now=T0)
    alerts.problem(s, "d:example.com", "c", fingerprint="no_zone,not_prepared", now=T0)
    assert [e.summary for e in s.events.list()] == ["c", "a"]
    assert set(alerts.active(s, "d:")) == {"d:example.com"}
    alerts.forget(s, "d:")
    assert alerts.active(s) == {}


def test_scrub_origin_is_narrow():
    set_origin_ips(lambda: {"192.0.2.10", "2001:db8::10"})
    try:
        out = scrub_origin("origin 192.0.2.10:443 and 2001:0db8:0:0:0:0:0:10 failed; edge 192.0.2.100, "
                           "client 203.0.113.5, 192.0.2.1; token rejected")
        assert out == ("origin [origin IP]:443 and [origin IP] failed; edge 192.0.2.100, "
                       "client 203.0.113.5, 192.0.2.1; token rejected")
        assert scrub_origin(None) is None
    finally:
        set_origin_ips(lambda: ())
