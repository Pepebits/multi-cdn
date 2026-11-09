"""Prepara un dominio en Gcore: origen, certificado (DNS-01), recurso CDN y verificación.

No toca el DNS público: el dominio sigue en Cloudflare hasta que se conmute.
"""

from __future__ import annotations

import secrets as pysecrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from . import certs
from .providers import gcore



@dataclass
class Job:
    domain: str
    started: datetime = field(default_factory=lambda: datetime.now(UTC))
    lines: list[tuple[str, str]] = field(default_factory=list)  # (nivel, texto)
    done: bool = False
    ok: bool = False

    def log(self, text: str, level: str = "info") -> None:
        self.lines.append((level, text))


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


async def prepare_domain(state, name: str, job: Job, renewal: bool = False) -> None:
    try:
        await _prepare(state, name, job, renewal)
        job.ok = True
    except Exception as exc:  # se muestra en el panel y queda en el historial
        job.log(str(exc), "error")
        what = "Renovación del certificado en Gcore fallida" if renewal else "Preparación en Gcore fallida"
        state.events.add(actor="auto", kind="error", domain=name, summary=f"{what}: {exc}"[:500])
    finally:
        job.done = True


async def _prepare(state, name: str, job: Job, renewal: bool = False) -> None:
    inv = state.inventory
    domain = inv.domains[name]
    existed = bool(domain.gcore_resource_id)
    gc_token = state.creds.secret(domain.gcore_credential)
    cf_token = state.creds.secret(domain.cloudflare_credential)
    if not gc_token:
        raise RuntimeError("Asigna una credencial de Gcore al dominio (Configuración)")
    if not cf_token:
        raise RuntimeError("Asigna una credencial de Cloudflare al dominio: hace falta para emitir el certificado por DNS-01")

    hosts = [h for h in domain.hostnames if h.origin_kind != "tunnel"]
    skipped = [h.name for h in domain.hostnames if h.origin_kind == "tunnel"]
    if skipped:
        job.log(f"Se omiten por ser Cloudflare Tunnel (sin IP de origen): {', '.join(skipped)}", "warn")
    if not hosts:
        raise RuntimeError("Ningún hostname tiene origen por IP: Gcore no puede servir este dominio")
    servers = {h.server for h in hosts}
    if len(servers) > 1:
        raise RuntimeError(f"Los hostnames están en varios servidores ({', '.join(sorted(servers))}); un recurso Gcore usa un solo origen")
    server_id = servers.pop()
    origin_ip = inv.servers[server_id].origin_ipv4
    if not origin_ip:
        raise RuntimeError(f"El servidor {server_id} no tiene IP de origen registrada (Ajustes → Servidores)")

    names = [h.name for h in hosts]
    primary = name if name in names else names[0]
    secondary = [n for n in names if n != primary]

    target = await gcore.account_cname(gc_token)
    job.log(f"Cuenta Gcore verificada · destino DNS: {target}")

    group_id = await gcore.ensure_origin_group(gc_token, f"multicdn-{server_id}", str(origin_ip))
    job.log(f"Grupo de origen multicdn-{server_id} listo (id {group_id}, HTTPS :443)")

    cert = await certs.issue(name, names, cf_token, job.log)
    ssl_name = f"multicdn-{name}-{cert.not_after:%Y%m%d}"
    ssl_id = await gcore.upload_certificate(gc_token, ssl_name, cert.fullchain, cert.privkey)
    job.log(f"Certificado subido a Gcore como {ssl_name} (id {ssl_id})")

    secret = origin_secret(state.secrets)
    payload = gcore.resource_payload(primary, secondary, group_id, ssl_id, secret)
    resource_id = await gcore.ensure_resource(gc_token, payload)
    state.events.set_value(f"origin_header_gcore:{name}", fingerprint(secret))
    job.log(f"Recurso CDN listo (id {resource_id}): {', '.join(names)} · caché solo si el origen la pide · WebSockets · cabecera X-Origin-Auth")

    previous_ssl = domain.gcore_ssl_id
    state.store.set_gcore(name, resource_id, ssl_id, cert.not_after.isoformat(), target, names)
    state.reload()
    if previous_ssl and previous_ssl != ssl_id:
        try:
            await gcore.delete_certificate(gc_token, previous_ssl)
            job.log(f"Certificado anterior (id {previous_ssl}) borrado de Gcore")
        except Exception as exc:  # no es crítico: queda huérfano pero sin uso
            job.log(f"No se pudo borrar el certificado anterior (id {previous_ssl}): {exc}", "warn")

    job.log("Comprobando el borde de Gcore (puede tardar unos minutos en propagarse)…")
    for n in names:
        try:
            ok, msg = await gcore.probe_edge(target, n)
        except Exception as exc:  # la propagación puede tardar: no invalida la preparación
            ok, msg = False, f"{n}: {type(exc).__name__}"
        job.log(msg, "ok" if ok else "warn")

    if renewal:
        summary = f"Certificado renovado en Gcore, válido hasta {cert.not_after:%d/%m/%Y}"
    elif existed:  # recurso ya existente: configuración y cabecera secreta al día, mismo DNS
        summary = f"Actualizado en Gcore: recurso {resource_id}, certificado hasta {cert.not_after:%d/%m/%Y}"
    else:
        summary = f"Preparado en Gcore: recurso {resource_id}, certificado hasta {cert.not_after:%d/%m/%Y}"
    state.events.add(actor="auto", kind="config", domain=name, summary=summary,
                     signals=[f"destino {target}", f"origen multicdn-{server_id}"])
    job.log("Listo. El DNS público no se ha tocado: el dominio sigue sirviéndose por Cloudflare.", "ok")


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
        when = f"caducó el {not_after:%d/%m/%Y}" if level == 0 else f"caduca el {not_after:%d/%m/%Y} (en {days} días)"
        state.events.add(actor="auto", kind="alert", domain=name,
                         summary=f"Certificado de Gcore sin renovar: {when}. Revisa la renovación en la ficha del dominio "
                                 "(Respaldo Gcore); sin él, el cambio a Gcore fallaría")
        state.events.set_value(key, mark)
        warned.append(name)
    return warned


async def renew_and_check(state) -> None:
    """Tarea diaria: renovar lo que toque y avisar de lo que siga sin renovar."""
    await renew_due_certificates(state)
    state.reload()
    cert_expiry_alerts(state)


async def renew_due_certificates(state) -> list[str]:
    """Renueva los certificados de Gcore que caducan en menos de 30 días. Devuelve los dominios tratados."""
    renewed = []
    for name, domain in list(state.inventory.domains.items()):
        if not due_for_renewal(domain):
            continue
        job = state.jobs[name] = Job(domain=name)
        job.log("Renovación automática: el certificado caduca en menos de 30 días")
        await prepare_domain(state, name, job, renewal=True)
        renewed.append(name)
    return renewed
