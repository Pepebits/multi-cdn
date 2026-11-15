import sentry_sdk

from app import error_reporting as er


def test_off_without_dsn(monkeypatch):
    monkeypatch.delenv("MULTICDN_SENTRY_DSN", raising=False)
    assert er.init("test") is False
    assert not sentry_sdk.get_client().is_active()


def test_on_with_dsn_uses_private_defaults(monkeypatch):
    monkeypatch.setenv("MULTICDN_SENTRY_DSN", "https://public@errors.example.com/1")
    monkeypatch.setenv("MULTICDN_SENTRY_TRACES_SAMPLE_RATE", "nonsense")
    try:
        assert er.init("test") is True
        opts = sentry_sdk.get_client().options
        assert opts["data_collection"]["user_info"] is False
        assert opts["data_collection"]["stack_frame_variables"] is False
        assert opts["include_local_variables"] is False
        assert opts["max_request_body_size"] == "never"
        assert opts["server_name"] == "multi-cdn"
        assert opts["traces_sample_rate"] is None
        assert opts["environment"] == "production"
        assert opts["release"] != "multi-cdn@unknown" and opts["release"].startswith("multi-cdn@")
    finally:
        sentry_sdk.get_client().close()
        sentry_sdk.init()  # back to the inactive client


def test_scrub_text_removes_ips_tokens_and_emails():
    text = ("connect to 192.0.2.10:443 and [2001:db8::1] failed; "
            "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0/sendMessage "
            "Authorization: Bearer abcdefghijklmnop smtp://user:pass@mail.example.com "
            "/cb?token=s3cr3t&x=1 owner admin@example.com at 12:30:45")
    out = er.scrub_text(text)
    for leaked in ("192.0.2.10", "2001:db8::1", "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0",
                   "abcdefghijklmnop", "user:pass", "s3cr3t", "admin@example.com"):
        assert leaked not in out
    assert "12:30:45" in out          # times are not IPv6 addresses
    assert "&x=1" in out
    assert er.scrub_text("multi-cdn@0.2.2") == "multi-cdn@0.2.2"   # the release is not an email


def test_before_send_drops_request_details_and_locals():
    event = {
        "user": {"ip_address": "192.0.2.1"},
        "request": {"url": "http://localhost/x", "cookies": {"s": "1"}, "headers": {"X": "1"},
                    "data": "a", "query_string": "token=1"},
        "exception": {"values": [{"value": "origin 198.51.100.7 unreachable",
                                  "stacktrace": {"frames": [{"function": "f", "vars": {"ip": "1"}}]}}]},
        "extra": {"nested": ["203.0.113.9"]},
    }
    out = er.before_send(event)
    assert "user" not in out
    assert set(out["request"]) == {"url"}
    exc = out["exception"]["values"][0]
    assert exc["value"] == "origin [ip] unreachable"
    assert "vars" not in exc["stacktrace"]["frames"][0]
    assert out["extra"]["nested"] == ["[ip]"]


def test_background_tasks_noop_when_off():
    er.watch_background_tasks()  # inactive client: must not raise or patch anything
