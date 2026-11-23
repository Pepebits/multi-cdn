"""Self-restart when the panel is stuck, and the alert on the next start."""

from datetime import UTC, datetime, timedelta

from app import watchdog


class Exit(Exception):
    pass


def dog(state, clock=None):
    def fake_exit(code):
        raise Exit(code)
    return watchdog.Watchdog(state, exit_fn=fake_exit, clock=clock or (lambda: 0.0))


def test_a_blocked_event_loop_ends_the_process(client):
    state = client.app.state.mc
    now = [0.0]
    d = dog(state, clock=lambda: now[0])
    now[0] = watchdog.LOOP_STUCK - 1
    assert d.check_stuck() is False
    now[0] = watchdog.LOOP_STUCK + 1
    try:
        d.check_stuck()
        raise AssertionError("expected exit")
    except Exit as exc:
        assert exc.args[0] == watchdog.EXIT_CODE
    assert "dejó de responder" in state.events.get_value(watchdog.REASON_KEY)


def test_stale_panel_loops_end_the_process_after_20_min(client):
    state = client.app.state.mc
    start = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
    state.started_at = start - timedelta(hours=1)
    state.dns_checked_at = start - timedelta(hours=1)  # the DNS loop is stuck
    d = dog(state)
    d.check_loops(start)
    d.check_loops(start + timedelta(minutes=19))
    try:
        d.check_loops(start + timedelta(minutes=20))
        raise AssertionError("expected exit")
    except Exit:
        pass
    assert "dns" in state.events.get_value(watchdog.REASON_KEY)


def test_loops_that_recover_reset_the_count(client):
    state = client.app.state.mc
    start = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
    state.started_at = start - timedelta(hours=1)
    state.dns_checked_at = start - timedelta(hours=1)
    d = dog(state)
    d.check_loops(start)
    state.dns_checked_at = start + timedelta(minutes=15)
    d.check_loops(start + timedelta(minutes=15))
    assert d.stale_since is None
    state.dns_checked_at = start - timedelta(hours=1)
    d.check_loops(start + timedelta(minutes=30))  # stale again: counts from here, no exit yet


def test_no_exit_during_the_startup_grace(client):
    state = client.app.state.mc
    state.started_at = datetime.now(UTC)
    state.dns_checked_at = None
    dog(state).check_loops(datetime.now(UTC) + timedelta(minutes=1))


def test_the_next_start_reports_why_it_restarted(client):
    state = client.app.state.mc
    state.events.set_value(watchdog.REASON_KEY, "dejó de responder durante más de 5 min")
    watchdog.report_previous_exit(state)
    assert state.events.list(limit=1)[0].summary == ("El panel se ha reiniciado solo: dejó de responder durante "
                                                     "más de 5 min")
    assert state.events.get_value(watchdog.REASON_KEY) is None
    watchdog.report_previous_exit(state)  # only once
    assert len([e for e in state.events.list(limit=5) if "reiniciado solo" in e.summary]) == 1


def test_off_in_tests_and_by_setting(monkeypatch):
    monkeypatch.setenv("MULTICDN_OFFLINE", "1")
    assert not watchdog.enabled()
    monkeypatch.setenv("MULTICDN_OFFLINE", "0")
    monkeypatch.setenv("MULTICDN_WATCHDOG", "0")
    assert not watchdog.enabled()
    monkeypatch.setenv("MULTICDN_WATCHDOG", "1")
    assert watchdog.enabled()
