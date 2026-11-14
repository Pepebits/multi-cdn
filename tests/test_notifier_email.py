"""Email alerts: verified TLS and subjects that survive multi-line summaries."""

import ssl

import pytest

from app import notifier, notify


class FakeSecrets(dict):
    pass


class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.context = host, port, context
        self.tls_context, self.sent = None, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.tls_context = context

    def login(self, user, password):
        pass

    def send_message(self, msg):
        self.sent.append(msg)


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(notifier.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(notifier.smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP.instances


def _verifies(ctx):
    return isinstance(ctx, ssl.SSLContext) and ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


@pytest.mark.parametrize("scheme", ["smtp", "smtps"])
def test_email_verifies_tls(smtp, scheme):
    n = notifier.Notifier(FakeSecrets(smtp_url=f"{scheme}://a%40x.com:pw@mail.x.com", alert_email_to="ops@x.com"))
    assert n._email("subject", "body") == "ok"
    s = smtp[0]
    assert _verifies(s.tls_context if scheme == "smtp" else s.context)


@pytest.mark.parametrize("scheme", ["smtp", "smtps"])
def test_smtp_check_verifies_tls(smtp, scheme):
    ok, _msg = notify._smtp_check(f"{scheme}://user:pw@mail.x.com")
    s = smtp[0]
    assert ok and _verifies(s.tls_context if scheme == "smtp" else s.context)


def test_multiline_summary_still_sends_email(smtp):
    summary = "Certificate renewal failed: certbot said\nError: challenge failed\n  detail: timeout"
    event = {"actor": "auto", "kind": "error", "summary": summary, "domain": "example.com",
             "dns_diff": [], "signals": []}
    subject, body = notifier.format_text(event)
    n = notifier.Notifier(FakeSecrets(smtp_url="smtp://mail.x.com", alert_email_to="ops@x.com"))
    assert n._email(subject, body) == "ok"
    msg = smtp[0].sent[0]
    assert "\n" not in msg["Subject"] and "Error: challenge failed detail: timeout" in msg["Subject"]
    assert "  detail: timeout" in msg.get_content()  # el texto completo sigue en el cuerpo


def test_unexpected_error_is_logged_not_raised(monkeypatch, caplog):
    def boom(*a, **kw):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(notifier.smtplib, "SMTP", boom)
    n = notifier.Notifier(FakeSecrets(smtp_url="smtp://mail.x.com", alert_email_to="ops@x.com"))
    assert n._email("s", "b") == "RuntimeError"
    assert "email notification failed" in caplog.text
