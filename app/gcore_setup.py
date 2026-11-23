"""Prepara un dominio en Gcore: origen, certificado (DNS-01), recurso CDN y verificación.

No toca el DNS público: el dominio sigue en Cloudflare hasta que se conmute.
"""

from __future__ import annotations

import hashlib
import logging
import secrets as pysecrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from . import certs, event_codes
from .error_reporting import scrub_origin
from .i18n import format_when, notify_lang, tn, tnn, tr
from .providers import gcore

log = logging.getLogger("multicdn")


@dataclass
class Job:
    domain: str
    started: datetime = field(default_factory=lambda: datetime.now(UTC))
    lines: list[tuple[str, str]] = field(default_factory=list)  # (nivel, texto)
    done: bool = False
    ok: bool = False

    def log(self, text: str, level: str = "info") -> None:
        self.lines.append((level, scrub_origin(str(text))))  # shown in the panel: never the origin IP


def fingerprint(secret: str) -> str:
    """Huella corta para saber qué versión del secreto tiene aplicada cada CDN, sin guardarlo dos veces."""
    import hashlib
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def rotate_origin_secret(secret_store, cdn: str) -> str:
    """Nuevo secreto para un CDN. El anterior se conserva para que Caddy acepte los dos mientras
    se aplica el nuevo; se retira con retire_previous_secret()."""
    current = secret_store.get(f"origin_auth:{cdn}")
    if current:
        secret_store.set(f"origin_auth:{cdn}:anterior", current)
    value = pysecrets.token_urlsafe(32)
    secret_store.set(f"origin_auth:{cdn}", value)
    return value


def retire_previous_secret(secret_store, cdn: str) -> bool:
    if secret_store.get(f"origin_auth:{cdn}:anterior"):
        secret_store.delete(f"origin_auth:{cdn}:anterior")
        return True
    return False


def caddy_origin_snippet(secret_store) -> str:
    """Snippet (origin_auth) con los valores aceptados: actual y, si hay rotación en curso, anterior."""
    values = []
    for cdn in ("cloudflare", "gcore"):
        values.append(origin_secret(secret_store, cdn))
        previous = secret_store.get(f"origin_auth:{cdn}:anterior")
        if previous:
            values.append(previous)
    lines = "\n".join(f"\t\theader X-Origin-Auth {v}" for v in values)
    return ("# Generado por `python -m app.cli secretos-origen --caddy`: no editar a mano (contiene secretos).\n"
            "(origin_auth) {\n\t@sin_cdn not {\n" + lines + "\n\t}\n"
            "\trespond @sin_cdn \"Forbidden\" 403 {\n\t\tclose\n\t}\n"
            "\t# No se quita aquí con request_header: Caddy lo ejecutaría antes que respond y no quedaría\n"
            "\t# cabecera que comprobar. La quita header_up en el snippet (real_ip) del reverse_proxy.\n}\n")


def origin_secret(secret_store, cdn: str = "gcore") -> str:
    key = f"origin_auth:{cdn}"
    value = secret_store.get(key)
    if not value:
        value = pysecrets.token_urlsafe(32)
        secret_store.set(key, value)
    return value


RENEW_BEFORE = timedelta(days=30)


def certificate_name(name: str, cert) -> str:
    """Name of the certificate on Gcore. upload_certificate() reuses one with the same name, so
    the name includes a hash of the chain: a re-issue on the same day is uploaded, not mistaken
    for the previous one; the same certificate (a retried preparation) is reused."""
    digest = hashlib.sha256(cert.fullchain.encode()).hexdigest()[:8]
    return f"multicdn-{name}-{cert.not_after:%Y%m%d}-{digest}"


async def prepare_domain(state, name: str, job: Job, renewal: bool = False) -> None:
    try:
        await _prepare(state, name, job, renewal)
        job.ok = True
    except NotRenewedYet:
        job.log(tr("certbot kept the current certificate: Gcore was not touched; it is tried again tomorrow"))
        job.ok = True
    except Exception as exc:  # se muestra en el panel y queda en el historial
        job.log(str(exc), "error")
        summary = tn("Certificate renewal on Gcore failed: {error}", error=exc) if renewal \
            else tn("Preparation on Gcore failed: {error}", error=exc)
        state.events.add(actor="auto", kind="error", domain=name, summary=summary[:500])
    finally:
        job.done = True


class NotRenewedYet(Exception):
    """certbot kept the current certificate: nothing to upload to Gcore (tried again tomorrow)."""


async def _prepare(state, name: str, job: Job, renewal: bool = False) -> None:
    inv = state.inventory
    domain = inv.domains[name]
    existed = bool(domain.gcore_resource_id)
    gc_token = state.creds.secret(domain.gcore_credential)
    cf_token = state.creds.secret(domain.cloudflare_credential)
    if not gc_token:
        raise RuntimeError(tn("Assign a Gcore credential to the domain (Configuration)"))
    if not cf_token:
        raise RuntimeError(tn("Assign a Cloudflare credential to the domain: it is needed to issue the certificate via DNS-01"))

    hosts = [h for h in domain.hostnames if h.origin_kind != "tunnel"]
    skipped = [h.name for h in domain.hostnames if h.origin_kind == "tunnel"]
    if skipped:
        job.log(tr("Skipped because they use Cloudflare Tunnel (no origin IP): {hosts}", hosts=", ".join(skipped)), "warn")
    if not hosts:
        raise RuntimeError(tn("No hostname has an IP origin: Gcore cannot serve this domain"))
    servers = {h.server for h in hosts}
    if len(servers) > 1:
        raise RuntimeError(tn("The hostnames are on several servers ({servers}); a Gcore resource uses a single origin",
                              servers=", ".join(sorted(servers))))
    server_id = servers.pop()
    origin_ip = inv.servers[server_id].origin_ipv4
    if not origin_ip:
        raise RuntimeError(tn("Server {server} has no origin IP registered (Settings → Servers)", server=server_id))

    names = [h.name for h in hosts]
    primary = name if name in names else names[0]
    secondary = [n for n in names if n != primary]

    target = await gcore.account_cname(gc_token)
    job.log(tr("Gcore account verified · DNS target: {target}", target=target))

    group_id = await gcore.ensure_origin_group(gc_token, f"multicdn-{server_id}", str(origin_ip))
    job.log(tr("Origin group multicdn-{server} ready (id {id}, HTTPS :443)", server=server_id, id=group_id))

    cert = await certs.issue(name, names, cf_token, job.log)
    if renewal and domain.cert_not_after and cert.not_after <= datetime.fromisoformat(domain.cert_not_after):
        # Same certificate as on Gcore (certbot decided it is not due yet): uploading it again and
        # touching the resource would repeat the work and the "renewed" alert every day.
        raise NotRenewedYet
    ssl_name = certificate_name(name, cert)
    ssl_id = await gcore.upload_certificate(gc_token, ssl_name, cert.fullchain, cert.privkey)
    job.log(tr("Certificate uploaded to Gcore as {name} (id {id})", name=ssl_name, id=ssl_id))

    secret = origin_secret(state.secrets)
    payload = gcore.resource_payload(primary, secondary, group_id, ssl_id, secret)
    resource_id = await gcore.ensure_resource(gc_token, payload)
    state.events.set_value(f"origin_header_gcore:{name}", fingerprint(secret))
    job.log(tr("CDN resource ready (id {id}): {hosts} · cache only if the origin asks for it · WebSockets · "
               "X-Origin-Auth header", id=resource_id, hosts=", ".join(names)))

    previous_ssl = domain.gcore_ssl_id
    state.store.set_gcore(name, resource_id, ssl_id, cert.not_after.isoformat(), target, names)
    state.reload()
    if previous_ssl and previous_ssl != ssl_id:
        try:
            await gcore.delete_certificate(gc_token, previous_ssl)
            job.log(tr("Previous certificate (id {id}) deleted from Gcore", id=previous_ssl))
        except Exception as exc:  # no es crítico: queda huérfano pero sin uso
            job.log(tr("Could not delete the previous certificate (id {id}): {error}", id=previous_ssl, error=exc), "warn")

    job.log(tr("Checking the Gcore edge (it may take a few minutes to propagate)…"))
    for n in names:
        try:
            ok, msg = await gcore.probe_edge(target, n)
        except Exception as exc:  # la propagación puede tardar: no invalida la preparación
            ok, msg = False, f"{n}: {type(exc).__name__}"
        job.log(msg, "ok" if ok else "warn")

    code = None
    if renewal:
        code = event_codes.CERT_RENEWED
        summary = tn("Certificate renewed on Gcore, valid until {date}", date=format_when(cert.not_after, notify_lang(), time=False))
    elif existed:  # recurso ya existente: configuración y cabecera secreta al día, mismo DNS
        summary = tn("Updated on Gcore: resource {id}, certificate until {date}", id=resource_id, date=format_when(cert.not_after, notify_lang(), time=False))
    else:
        code = event_codes.GCORE_PREPARED
        summary = tn("Prepared on Gcore: resource {id}, certificate until {date}", id=resource_id, date=format_when(cert.not_after, notify_lang(), time=False))
    state.events.add(actor="auto", kind="config", domain=name, summary=summary, code=code,
                     signals=[tn("target {target}", target=target), tn("origin multicdn-{server}", server=server_id)])
    job.log(tr("Done. Public DNS was not touched: the domain is still served through Cloudflare."), "ok")


def due_for_renewal(domain, now: datetime | None = None) -> bool:
    if not domain.gcore_resource_id or not domain.cert_not_after:
        return False
    return datetime.fromisoformat(domain.cert_not_after) - (now or datetime.now(UTC)) < RENEW_BEFORE


CERT_ALERT_DAYS = (21, 7)  # la renovación empieza a 30 días: si llega aquí, algo falla


def cert_expiry_alerts(state, now: datetime | None = None) -> list[str]:
    """Avisa (una vez por nivel y certificado) si un certificado de Gcore sigue sin renovar
    a 21 o 7 días de caducar, o ya ha caducado. Devuelve los dominios avisados."""
    now = now or datetime.now(UTC)
    warned = []
    for name, domain in state.inventory.domains.items():
        if not (domain.gcore_resource_id and domain.cert_not_after):
            continue
        not_after = datetime.fromisoformat(domain.cert_not_after)
        days = (not_after - now).days
        level = 0 if days < 0 else next((d for d in sorted(CERT_ALERT_DAYS) if days <= d), None)
        if level is None:
            continue
        key, mark = f"cert_alert:{name}", f"{domain.cert_not_after}:{level}"
        if state.events.get_value(key) == mark:
            continue
        date = format_when(not_after, notify_lang(), now=now, time=False)
        when = tn("expired on {date}", date=date) if level == 0 \
            else tnn("expires on {date} (in {n} day)", "expires on {date} (in {n} days)", days, date=date)
        state.events.add(actor="auto", kind="alert", domain=name,
                         summary=tn("Gcore certificate not renewed: {when}. Check the renewal on the domain page "
                                    "(Gcore backup); without it, switching to Gcore would fail", when=when))
        state.events.set_value(key, mark)
        warned.append(name)
    return warned


async def renew_and_check(state) -> None:
    """Tarea diaria: renovar lo que toque y avisar de lo que siga sin renovar."""
    await renew_due_certificates(state)
    state.reload()
    cert_expiry_alerts(state)


# Renewal starts 30 days ahead; while the domain is busy it waits, but not past this margin.
RENEW_DEFER_UNTIL = timedelta(days=7)


def renewal_busy(state, name: str, now: datetime | None = None) -> str | None:
    """Why renewing this domain should wait (it updates the Gcore resource, which then propagates
    for a few minutes and would make a switch fail its check), or None."""
    from .engine import failover
    now = now or datetime.now(UTC)
    cfg = state.inventory.domains[name]
    if name in state.blocked_domains:
        return tn("its Cloudflare IPs are blocked")
    view = next((v for v in state.views() if v.name == name), None)
    if view is not None and view.status == "gcore":
        return tn("it is being served by Gcore")
    calendar = state.calendar
    if calendar is not None and not calendar.is_stale(now) and calendar.active(now, failover.match_lead(state, cfg.priority)):
        return tn("a match is on or about to start")
    return None


async def renew_due_certificates(state, now: datetime | None = None) -> list[str]:
    """Renueva los certificados de Gcore que caducan en menos de 30 días. Devuelve los dominios tratados."""
    now = now or datetime.now(UTC)
    renewed = []
    for name, domain in list(state.inventory.domains.items()):
        if not due_for_renewal(domain, now):
            continue
        left = datetime.fromisoformat(domain.cert_not_after) - now
        if left > RENEW_DEFER_UNTIL and (busy := renewal_busy(state, name, now)):
            log.info("certificate renewal of %s deferred: %s", name, busy)
            continue
        job = state.jobs[name] = Job(domain=name)
        job.log(tr("Automatic renewal: the certificate expires in less than 30 days"))
        await prepare_domain(state, name, job, renewal=True)
        renewed.append(name)
    return renewed
