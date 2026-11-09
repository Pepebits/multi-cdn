"""Certificados Let's Encrypt por DNS-01 en Cloudflare (certbot --manual + app.acme_hook).

Se usa DNS-01 porque el certificado tiene que existir ANTES de que el dominio apunte a
Gcore: la validación HTTP llegaría a Cloudflare, no al CDN de respaldo.
Los ficheros quedan en data/certbot (ignorado por git); la clave privada nunca sale
de ahí salvo para subirla a Gcore.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

CERTBOT = Path(sys.executable).parent / "certbot"


@dataclass
class IssuedCert:
    fullchain: str
    privkey: str
    not_after: datetime
    names: list[str]


def _base_dir() -> Path:
    db = Path(os.environ.get("MULTICDN_DB", "data/multicdn.db"))
    return db.parent / "certbot"


def read_cert(cert_name: str) -> IssuedCert | None:
    live = _base_dir() / "config" / "live" / cert_name
    if not (live / "fullchain.pem").exists():
        return None
    fullchain = (live / "fullchain.pem").read_text()
    cert = x509.load_pem_x509_certificate(fullchain.encode())
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    return IssuedCert(fullchain, (live / "privkey.pem").read_text(), cert.not_valid_after_utc, sorted(names))


async def issue(cert_name: str, hostnames: list[str], cloudflare_token: str, log) -> IssuedCert:
    """Emite (o renueva si hace falta) un certificado que cubre `hostnames`."""
    existing = read_cert(cert_name)
    if existing and sorted(hostnames) == existing.names and (existing.not_after - datetime.now(UTC)).days > 30:
        log(f"Certificado vigente hasta {existing.not_after:%d/%m/%Y}: se reutiliza")
        return existing
    base = _base_dir()
    for sub in ("config", "work", "logs"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    hook = f"{sys.executable} -m app.acme_hook"
    args = [
        str(CERTBOT), "certonly", "--non-interactive", "--agree-tos",
        "--manual", "--preferred-challenges", "dns",
        "--manual-auth-hook", f"{hook} auth", "--manual-cleanup-hook", f"{hook} cleanup",
        "--config-dir", str(base / "config"), "--work-dir", str(base / "work"), "--logs-dir", str(base / "logs"),
        "--cert-name", cert_name, "--max-log-backups", "10", "--key-type", "rsa", "--rsa-key-size", "2048", "--expand", "--keep-until-expiring",
    ]
    email = os.environ.get("MULTICDN_ACME_EMAIL")
    args += ["-m", email] if email else ["--register-unsafely-without-email"]
    if os.environ.get("MULTICDN_ACME_STAGING") == "1":
        args.append("--staging")
    for h in hostnames:
        args += ["-d", h]
    # El token va a los hooks por el entorno de este proceso: nunca a disco.
    env = os.environ | {"MULTICDN_ACME_CF_TOKEN": cloudflare_token,
                        "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
    log(f"Solicitando certificado para {', '.join(hostnames)} (DNS-01 en Cloudflare, ~1 min)")
    proc = await asyncio.create_subprocess_exec(*args, env=env, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    if proc.returncode != 0:
        tail = "\n".join(out.decode(errors="replace").strip().splitlines()[-6:])
        raise RuntimeError(f"certbot falló:\n{tail}")
    cert = read_cert(cert_name)
    if cert is None:
        raise RuntimeError("certbot terminó pero no se encuentra el certificado")
    log(f"Certificado emitido, válido hasta {cert.not_after:%d/%m/%Y}")
    return cert
