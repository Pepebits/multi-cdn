"""Certificate issuance with a stand-in for certbot: the arguments it gets, the Cloudflare token
kept out of them, reuse of a valid certificate and how a failure is reported."""

import asyncio
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import certs

FAKE_CERTBOT = """#!{python}
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
record = {{"args": args, "token": os.environ.get("MULTICDN_ACME_CF_TOKEN")}}
Path({calls!r}).write_text(json.dumps(record))
if os.environ.get("FAKE_CERTBOT_FAIL"):
    print("Some challenges have failed.\\nDetail: DNS problem: NXDOMAIN")
    sys.exit(1)
live = Path(args[args.index("--config-dir") + 1]) / "live" / args[args.index("--cert-name") + 1]
live.mkdir(parents=True, exist_ok=True)
(live / "fullchain.pem").write_text(Path({pem!r}).read_text())
(live / "privkey.pem").write_text("KEY")
"""


def self_signed(names: list[str], days: int) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def certbot(tmp_path, monkeypatch):
    """A fake certbot that records its call and writes a certificate for the requested names."""
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "data" / "multicdn.db"))
    pem, calls = tmp_path / "issued.pem", tmp_path / "calls.json"
    pem.write_text(self_signed(["example.com", "www.example.com"], 90))
    script = tmp_path / "certbot"
    script.write_text(FAKE_CERTBOT.format(python=sys.executable, calls=str(calls), pem=str(pem)))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(certs, "CERTBOT", script)
    return {"calls": calls, "pem": pem}


def issue(names=("example.com", "www.example.com")):
    lines = []
    cert = asyncio.run(certs.issue("example.com", list(names), "cf-token-secret", lines.append))
    return cert, lines


def test_issue_passes_the_hosts_and_keeps_the_token_out_of_the_arguments(certbot):
    cert, _lines = issue()
    record = json.loads(certbot["calls"].read_text())
    args = record["args"]
    assert args[:2] == ["certonly", "--non-interactive"] and "--keep-until-expiring" in args
    assert [args[i + 1] for i, a in enumerate(args) if a == "-d"] == ["example.com", "www.example.com"]
    assert record["token"] == "cf-token-secret" and "cf-token-secret" not in " ".join(args)
    assert cert.names == ["example.com", "www.example.com"] and cert.privkey == "KEY"
    assert cert.not_after - datetime.now(UTC) > timedelta(days=88)


def test_a_valid_certificate_for_the_same_hosts_is_reused(certbot):
    issue()
    certbot["calls"].unlink()
    _cert, lines = issue()
    assert not certbot["calls"].exists() and any("reused" in line or "reutiliza" in line for line in lines)
    issue(("example.com", "www.example.com", "api.example.com"))  # different hosts: asks certbot again
    assert certbot["calls"].exists()


def test_a_certificate_close_to_expiry_goes_back_to_certbot(certbot):
    certbot["pem"].write_text(self_signed(["example.com", "www.example.com"], 20))
    issue()
    certbot["calls"].unlink()
    issue()
    assert certbot["calls"].exists()


def test_certbot_failure_reports_its_last_lines(certbot, monkeypatch):
    monkeypatch.setenv("FAKE_CERTBOT_FAIL", "1")
    with pytest.raises(RuntimeError, match="NXDOMAIN"):
        issue()
    assert certs.read_cert("example.com") is None


def test_staging_and_contact_email_options(certbot, monkeypatch):
    monkeypatch.setenv("MULTICDN_ACME_STAGING", "1")
    monkeypatch.setenv("MULTICDN_ACME_EMAIL", "ops@example.com")
    issue()
    args = json.loads(certbot["calls"].read_text())["args"]
    assert "--staging" in args and args[args.index("-m") + 1] == "ops@example.com"
    assert os.environ.get("MULTICDN_ACME_CF_TOKEN") is None  # only in the child's environment
