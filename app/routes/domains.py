"""Domains: list, import from Cloudflare, domain page, hostnames, Gcore preparation, manual
switches and the automatic-switching controls."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import alerts
from ..engine import failover
from ..engine.failover import SwitchFailed
from ..gcore_setup import RENEW_BEFORE, Job, prepare_domain
from ..i18n import N_, tn, tr
from ..providers import cloudflare as cf
from ..providers import gcore
from ..providers.cloudflare import OriginExposureError, plan_to_gcore
from ..signals import calendar as match_calendar
from ..state import State
from ..tasks import (
    recheck_dns_soon,
    run_engine,
)
from ..views import build_domain
from .common import (
    _actor,
    _after_inventory_change,
    _back,
    _common,
    _require_domain,
    _state,
    templates,
)

router = APIRouter()


# ---------------------------------------------------------------- Dominios

@router.get("/dominios", response_class=HTMLResponse)
async def dominios(request: Request):
    s = _state(request)
    return templates.TemplateResponse(request, "dominios.html", _common(
        request, "dominios",
        domains=s.views(),
        changes={n: failover.change_indicator(s, n) for n in s.inventory.domains},
        autos={n: failover.describe(s, n) for n in s.inventory.domains},
        servers=list(s.inventory.servers),
        cf_creds=s.creds.list("cloudflare"),
    ))


@router.post("/dominios")
async def crear_dominio(
    request: Request, name: str = Form(...), priority: str = Form("medium"), policy: str = Form("reactive"),
    server: str = Form(...), hostnames: str = Form(""),
):
    s = _state(request)
    url = request.url_for("dominios")
    try:
        domain = s.store.upsert_domain(name, policy=policy, priority=priority)
        hosts = [h for h in hostnames.split() if h] or [domain, f"www.{domain}"]
        for h in hosts:
            s.store.upsert_hostname(domain, h, server=server)
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=domain, summary=tn("Domain added with {n} hostnames", n=len(hosts)))
    await _after_inventory_change(s)
    return _back(request.url_for("dominio", name=domain), ok=tr("Domain added"))


@router.get("/dominios/importar", response_class=HTMLResponse)
async def importar(request: Request, cuenta: int | None = None, zone: str | None = None):
    s = _state(request)
    cf_creds = s.creds.list("cloudflare")
    if not cf_creds:
        return _back(request.url_for("ajustes_cuentas"), error=tr("Add a Cloudflare credential first"))
    if cuenta is None or cuenta not in {c.id for c in cf_creds}:
        cuenta = cf_creds[0].id
    token = s.creds.secret(cuenta) or ""  # undecryptable: Cloudflare rejects it and the page says so
    ctx = {"zones": [], "records": [], "zone": None, "servers": list(s.inventory.servers), "load_error": None,
           "cf_creds": cf_creds, "cuenta": cuenta}
    try:
        ctx["zones"] = await cf.list_zones(token)
        if zone:
            ctx["zone"] = next((z for z in ctx["zones"] if z["id"] == zone), None)
            if ctx["zone"]:
                ctx["records"] = await cf.list_web_records(token, zone)
    except (RuntimeError, httpx.HTTPError) as exc:
        ctx["load_error"] = str(exc)
    existing = {h.name for d in s.inventory.domains.values() for h in d.hostnames}
    return templates.TemplateResponse(request, "importar.html", _common(request, "dominios", existing=existing, **ctx))


@router.post("/dominios/importar")
async def importar_guardar(request: Request):
    s = _state(request)
    form = await request.form()
    try:
        cuenta = int(str(form.get("cuenta", "")))
        s.creds.get(cuenta)
    except ValueError:
        return _back(request.url_for("dominios"), error=tr("Invalid Cloudflare credential"))
    token = s.creds.secret(cuenta)
    zone_id = str(form.get("zone_id", ""))
    if not token or not zone_id:
        return _back(request.url_for("dominios"), error=tr("The credential or the zone is missing"))
    zones = {z["id"]: z for z in await cf.list_zones(token)}
    if zone_id not in zones:
        return _back(request.url_for("importar"), error=tr("Zone not found in the account"))
    records = {r["id"]: r for r in await cf.list_web_records(token, zone_id)}
    chosen = [records[rid] for rid in form.getlist("record") if rid in records]
    if not chosen:
        return _back(request.url_for("importar"), cuenta=cuenta, zone=zone_id, error=tr("Select at least one record"))
    domain = zones[zone_id]["name"]
    try:
        s.store.upsert_domain(domain, policy=str(form.get("policy", "reactive")),
                              priority=str(form.get("priority", "medium")), zone_id=zone_id)
        current = s.inventory.domains.get(domain)
        s.store.set_credentials(domain, cuenta, current.gcore_credential if current else None)
        for r in chosen:
            s.store.upsert_hostname(domain, r["name"], server=str(form.get("server", "")), cloudflare_record_id=r["id"])
            s.store.set_cloudflare_record(r["name"], r["id"], r["origin_kind"], r["tunnel_target"], r["cname_target"])
    except ValueError as exc:
        return _back(request.url_for("importar"), cuenta=cuenta, zone=zone_id, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=domain,
                 summary=tn("Imported {n} hostnames from Cloudflare", n=len(chosen)))
    await _after_inventory_change(s)
    return _back(request.url_for("dominio", name=domain), ok=tr("Imported {n} hostnames from Cloudflare", n=len(chosen)))


@router.get("/dominios/{name}", response_class=HTMLResponse)
async def dominio(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    view = build_domain(name, s.inventory.domains[name], s.resolutions, s.feed, s.engine.get(name).cf_ips)
    if name in s.cf_sync_errors:
        view.alerts.append(tr("Could not read its records on Cloudflare: {error}", error=s.cf_sync_errors[name]))
    if multi := s.cf_multi_records.get(name):
        view.alerts.append(tr("{hosts}: more than one A/AAAA record on Cloudflare. The switch to Gcore turns the record into a "
                              "CNAME, which Cloudflare rejects while the others exist: keep a single record per hostname",
                              hosts=", ".join(multi)))
    cert_not_after = s.inventory.domains[name].cert_not_after
    cert_until = datetime.fromisoformat(cert_not_after) if cert_not_after else None
    return templates.TemplateResponse(request, "dominio.html", _common(
        request, "dominios", d=view, cfg=s.inventory.domains[name],
        servers=list(s.inventory.servers), events=s.events.list(domain=name, limit=10),
        cf_creds=s.creds.list("cloudflare"), gc_creds=s.creds.list("gcore"), job=s.jobs.get(name),
        auto=failover.describe(s, name), maintenance_options={k: tr(v) for k, v in MAINTENANCE_OPTIONS.items()},
        origin_header=origin_header_view(s, name),
        inventory_servers={sid: bool(srv.origin_ipv4) for sid, srv in s.inventory.servers.items()},
        cert_until=cert_until,
        renew_from=cert_until - RENEW_BEFORE if cert_until else None,
        tl=domain_timeline_view(s, name),
    ))


TIMELINE_DAYS = 7


def domain_timeline_view(s: State, name: str, days: int = TIMELINE_DAYS, now: datetime | None = None) -> dict:
    """Domain page: the last `days` UTC days on Gcore, blocked and with matches (stats + charts)."""
    from .. import charts, stats
    now = now or datetime.now(UTC)
    cfg = s.inventory.domains[name]
    start, end = stats.timeline_window(days, now)
    hosts = [h.name for h in cfg.hostnames if h.failover] or [h.name for h in cfg.hostnames]
    current = {h: r.provider for h in hosts if (r := s.resolutions.get(h))}
    tl = stats.domain_timeline(s.events.list(domain=name, limit=5000), hosts, current, start, end, now,
                               feed=s.feed, ips=s.engine.get(name).cf_ips,
                               matches=s.calendar.matches if s.calendar else (),
                               match_length=match_calendar.MATCH_LENGTH)
    gcore = [p for p in tl["periods"] if p.kind == "gcore"]
    return tl | {"days": days, "lanes": charts.domain_lanes(tl), "fmt_duration": stats.fmt_duration,
                 "gcore_count": len(gcore), "blocked_count": sum(p.kind == "blocked" for p in tl["periods"]),
                 "match_count": sum(p.kind == "match" for p in tl["periods"]),
                 "gcore_total": stats.fmt_duration(sum((p.duration(now) for p in gcore), timedelta(0))),
                 "has_feed": s.feed is not None, "has_ips": bool(s.engine.get(name).cf_ips)}


@router.post("/dominios/{name}/hostnames/{host}/quitar")
async def hostname_quitar(request: Request, name: str, host: str):
    s = _state(request)
    url = request.url_for("dominio", name=name)
    domain = s.inventory.domains.get(name)
    if domain is None or host not in {h.name for h in domain.hostnames}:
        raise HTTPException(404)
    if len(domain.hostnames) == 1:
        return _back(url, error=tr("It is the last hostname: delete the whole domain if you no longer want to monitor it"))
    if ((r := s.resolutions.get(host)) and r.provider == "gcore") or (s.cf_live.get(host) or {}).get("to_backup"):
        # Removed while on Gcore, nothing would ever bring it back to Cloudflare.
        return _back(url, error=tr("{host} is served by Gcore now: switch it back to Cloudflare before removing it", host=host))
    s.store.delete_hostname(host)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("{host} removed from the inventory (DNS unchanged)", host=host))
    await _after_inventory_change(s)
    return _back(url, ok=tr("{host} removed from the inventory. Its DNS has not been changed.", host=host))


@router.post("/dominios/{name}/configuracion")
async def dominio_config(
    request: Request, name: str, priority: str = Form(...), policy: str = Form(...), zone_id: str = Form(""),
    cloudflare_credential: str = Form(""), gcore_credential: str = Form(""),
):
    s = _state(request)
    url = request.url_for("dominio", name=name)
    _require_domain(s, name)
    try:
        ids = {}
        for provider, raw in (("cloudflare", cloudflare_credential), ("gcore", gcore_credential)):
            ids[provider] = int(raw) if raw else None
            if ids[provider] is not None and s.creds.get(ids[provider]).provider != provider:
                raise ValueError(tr("credential of the wrong provider"))
        s.store.upsert_domain(name, policy=policy, priority=priority, zone_id=zone_id.strip() or None)
        s.store.set_credentials(name, ids["cloudflare"], ids["gcore"])
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Priority {priority}, policy {policy}", priority=priority, policy=policy))
    await _after_inventory_change(s)
    return _back(url, ok=tr("Settings saved"))


@router.post("/dominios/{name}/hostnames")
async def hostnames_guardar(request: Request, name: str):
    """Guarda la tabla de hostnames (servidor y destino Gcore) y añade los nuevos."""
    s = _state(request)
    url = request.url_for("dominio", name=name)
    _require_domain(s, name)
    form = await request.form()
    try:
        for h in s.inventory.domains[name].hostnames:
            s.store.upsert_hostname(name, h.name, server=str(form.get(f"server:{h.name}", h.server)),
                                    gcore_target=str(form.get(f"gcore:{h.name}", "")).strip() or None)
            s.store.set_failover(h.name, bool(form.get(f"failover:{h.name}")))
        for new in str(form.get("new_hostnames", "")).split():
            s.store.upsert_hostname(name, new, server=str(form.get("new_server")))
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Hostnames updated"))
    await _after_inventory_change(s)
    return _back(url, ok=tr("Hostnames saved"))


def origin_header_view(s: State, name: str) -> dict:
    """Si cada CDN tiene aplicado el secreto actual (por huella), para la ficha del dominio."""
    from ..gcore_setup import fingerprint, origin_secret
    domain = s.inventory.domains[name]
    out = {}
    for cdn in ("cloudflare", "gcore"):
        applied = s.events.get_value(f"origin_header_{cdn}:{name}")
        current = fingerprint(origin_secret(s.secrets, cdn))
        if cdn == "gcore" and not domain.gcore_resource_id:
            out[cdn] = ("nodata", tr("Not prepared"))
        elif not applied:
            out[cdn] = ("blocked", tr("Not applied"))
        elif applied != current:
            out[cdn] = ("blocked", tr("Old secret"))
        else:
            out[cdn] = ("free", tr("Up to date"))
    return out


@router.post("/dominios/{name}/origen/cloudflare")
async def origen_cloudflare(request: Request, name: str):
    from ..gcore_setup import fingerprint, origin_secret
    s = _state(request)
    domain = s.inventory.domains.get(name)
    if domain is None:
        raise HTTPException(404)
    url = request.url_for("dominio", name=name)
    token = s.creds.secret(domain.cloudflare_credential)
    if not token or not domain.zone_id:
        return _back(url, "cabecera", error=tr("Assign a Cloudflare credential and zone to the domain"))
    secret = origin_secret(s.secrets, "cloudflare")
    try:
        outcome = await cf.ensure_origin_header(token, domain.zone_id, secret)
    except (RuntimeError, httpx.HTTPError) as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=tn("Secret header on Cloudflare: {error}", error=exc))
        return _back(url, "cabecera", error=tr("Could not apply it on Cloudflare: {error}", error=exc))
    s.events.set_value(f"origin_header_cloudflare:{name}", fingerprint(secret))
    if outcome in ORIGIN_RULE_EVENT:  # cloudflare.py returns Spanish codes
        summary, msg = tn(ORIGIN_RULE_EVENT[outcome]), tr(ORIGIN_RULE_FLASH[outcome])
    else:
        summary = tn("Secret header on Cloudflare: rule {outcome}", outcome=outcome)
        msg = tr("Cloudflare rule {outcome}: requests to the origin carry the secret header", outcome=outcome)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=summary)
    return _back(url, "cabecera", ok=msg)


ORIGIN_RULE_EVENT = {
    "creada": N_("Secret header on Cloudflare: rule created"),
    "actualizada": N_("Secret header on Cloudflare: rule updated"),
    "sin cambios": N_("Secret header on Cloudflare: rule unchanged"),
}
ORIGIN_RULE_FLASH = {
    "creada": N_("Cloudflare rule created: requests to the origin carry the secret header"),
    "actualizada": N_("Cloudflare rule updated: requests to the origin carry the secret header"),
    "sin cambios": N_("Cloudflare rule unchanged: requests to the origin carry the secret header"),
}


@router.post("/dominios/{name}/gcore/preparar")
async def gcore_preparar(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    job = s.jobs.get(name)
    if job and not job.done:
        return _back(request.url_for("dominio", name=name), error=tr("A preparation is already in progress"))
    job = s.jobs[name] = Job(domain=name)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Gcore preparation started"))
    asyncio.create_task(prepare_domain(s, name, job))
    return RedirectResponse(str(request.url_for("dominio", name=name)) + "#gcore", status_code=303)


@router.post("/dominios/{name}/eliminar")
async def dominio_eliminar(request: Request, name: str, confirm: str = Form(""), dns_action: str = Form("cloudflare"),
                           delete_gcore: str = Form("")):
    """Antes de dejar de vigilar el dominio, decide dónde queda servido. Si algo falla, no se elimina."""
    s = _state(request)
    domain = s.inventory.domains.get(name)
    if domain is None:
        raise HTTPException(404)
    back = request.url_for("dominio", name=name)
    if confirm.strip().lower() != name.lower():
        return _back(back, error=tr("Type the domain name to delete it"))
    if dns_action not in ("cloudflare", "gcore", "none"):
        return _back(back, error=tr("Invalid option"))
    if dns_action == "gcore" and delete_gcore:
        return _back(back, error=tr("You cannot leave it on Gcore and delete its Gcore resource at the same time"))
    if delete_gcore and domain.gcore_resource_id and any(
            (r := s.resolutions.get(h.name)) is None or r.provider not in ("cloudflare",) for h in domain.hostnames if h.failover):
        # El DNS tarda en propagar (y en simulación ni siquiera cambia): borrar ahora el recurso
        # dejaría la web apuntando a nada.
        return _back(back, error=tr("Its DNS is not on Cloudflare yet. Return it to Cloudflare first, wait until the "
                                    "public DNS shows it there, then delete the domain and its Gcore resource"))
    async with s.engine_lock:
        return await _delete_domain(request, s, name, domain, back, dns_action, delete_gcore)


async def _delete_domain(request, s, name, domain, back, dns_action, delete_gcore):
    client = s.cloudflare_for(domain)
    diff, changes = [], []
    try:
        for h in domain.hostnames:
            current = s.resolutions.get(h.name)
            provider = current.provider if current else "unresolved"
            if dns_action == "cloudflare" and provider not in ("cloudflare",):
                origin = s.inventory.servers[h.server].origin_ipv4 if h.server in s.inventory.servers else None
                changes.append((h, cf.plan_restore(h, str(origin) if origin else None), provider))
            elif dns_action == "gcore" and provider != "gcore" and h.failover:
                if not h.gcore_target:
                    raise ValueError(tn("{hostname} has no Gcore target", hostname=h.name))
                changes.append((h, plan_to_gcore(h.name, h.gcore_target), provider))
        for h, change, provider in changes:
            await client.apply(domain.zone_id, h.cloudflare_record_id, change)
            diff.append([h.name, failover.dns_before(provider), change.describe()])
        if delete_gcore and domain.gcore_resource_id:
            token = s.creds.secret(domain.gcore_credential)
            if not token:
                raise ValueError(tn("There is no Gcore credential to delete the resource"))
            await gcore.delete_resource(token, domain.gcore_resource_id)
    except (OriginExposureError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=tn("Not deleted: {error}", error=exc))
        return _back(back, error=tr("It has not been deleted: {error}", error=exc))

    s.store.delete_domain(name)
    s.engine.forget(name)
    alerts.forget(s, f"auto_not_ready:{name}")
    where = DELETE_WHERE[dns_action]
    gcore_deleted = bool(delete_gcore and domain.gcore_resource_id)

    def outcome(t):
        return t(where) + (" · " + t(GCORE_DELETED) if gcore_deleted else "")

    s.events.add(actor=_actor(request), kind="config", domain=name, transition=None,
                 summary=tn("Domain deleted; {outcome}", outcome=outcome(tn)),
                 dns_diff=diff, simulated=client.dry_run and bool(diff))
    await _after_inventory_change(s)
    if client.dry_run and diff:
        msg = tr("{domain} deleted; {outcome} (simulated DNS changes)", domain=name, outcome=outcome(tr))
    else:
        msg = tr("{domain} deleted; {outcome}", domain=name, outcome=outcome(tr))
    return _back(request.url_for("dominios"), ok=msg)


GCORE_DELETED = N_("Gcore resource deleted")
DELETE_WHERE = {"cloudflare": N_("it stays on Cloudflare"), "gcore": N_("it stays on Gcore"), "none": N_("its DNS stays unchanged")}


@router.post("/dominios/{name}/volver")
async def volver_cloudflare(request: Request, name: str, confirm: str = Form("")):
    """Restaura en Cloudflare (con proxy) los hostnames que no estén ya en Cloudflare."""
    s = _state(request)
    _require_domain(s, name)
    url = request.url_for("dominio", name=name)
    if confirm.strip().lower() != name.lower():
        return _back(url, error=tr("Type the domain name to confirm"))
    async with s.engine_lock:  # no cruzarse con un ciclo del motor
        try:
            diff, simulated = await failover.return_to_cloudflare(s, name, force_all=s.dry_run and s.engine.get(name).sim_backup is True)
        except SwitchFailed as exc:
            s.events.add(actor=_actor(request), kind="error", domain=name, summary=tn("Return to Cloudflare failed: {error}", error=exc), dns_diff=exc.diff)
            return _back(url, error=tr("Could not return to Cloudflare: {error}", error=exc))
        if not diff:
            return _back(url, ok=tr("All hostnames were already on Cloudflare"))
        s.engine.manual_change(name, to_backup=False, simulated=simulated)
    s.events.add(actor=_actor(request), kind="switch", domain=name, transition="GCORE → CF",
                 summary=tn("Manual return to Cloudflare from the panel"), dns_diff=diff, simulated=simulated)
    await _after_inventory_change(s)
    if not simulated and os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(recheck_dns_soon(s))
    if simulated:
        msg = tr("Simulated return (dry run): DNS was not touched. Automatic switching for this domain is paused for 1 h")
    else:
        msg = tr("Return to Cloudflare applied; it may take a few minutes to propagate. "
                 "Automatic switching for this domain is paused for 1 h")
    return _back(url, ok=msg)


@router.post("/dominios/{name}/cambiar")
async def cambiar(request: Request, name: str, target: str = Form(...), confirm: str = Form("")):
    s = _state(request)
    _require_domain(s, name)
    url = request.url_for("dominio", name=name)
    if confirm.strip().lower() != name.lower():
        return _back(url, error=tr("Type the domain name to confirm"))
    if target != "gcore":
        return _back(url, error=tr("Target not available yet"))
    async with s.engine_lock:  # no cruzarse con un ciclo del motor
        try:
            diff, simulated = await failover.switch_to_gcore(s, name)
        except SwitchFailed as exc:
            if exc.diff:
                s.events.add(actor=_actor(request), kind="error", domain=name, summary=str(exc), dns_diff=exc.diff)
            return _back(url, error=str(exc))
        s.engine.manual_change(name, to_backup=True, simulated=simulated)
    s.events.add(actor=_actor(request), kind="switch", domain=name, transition="CF → GCORE",
                 summary=tn("Manual switch to Gcore from the panel"), dns_diff=diff, simulated=simulated)
    await _after_inventory_change(s)
    if not simulated and os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(recheck_dns_soon(s))
    if simulated:
        msg = tr("Simulated switch (dry run): DNS was not touched. Automatic switching for this domain is paused for 1 h")
    else:
        msg = tr("Switch to Gcore applied; it may take a few minutes to propagate. "
                 "Automatic switching for this domain is paused for 1 h")
    return _back(url, ok=msg)


MAINTENANCE_OPTIONS = {1: "1 h", 6: "6 h", 24: "24 h", 168: N_("7 days"), 0: N_("until resumed")}


@router.post("/dominios/{name}/automatico/mantenimiento")
async def automatico_mantenimiento(request: Request, name: str, horas: int = Form(...)):
    s = _state(request)
    _require_domain(s, name)
    url = request.url_for("dominio", name=name)
    if horas not in MAINTENANCE_OPTIONS:
        return _back(url, error=tr("Invalid duration"))
    until = datetime.now(UTC) + timedelta(hours=horas) if horas else None
    # Sin esperar al ciclo en curso: _act vuelve a mirar la pausa en la base de datos justo antes
    # de tocar el DNS, así que la pausa también frena un cambio que ya estaba comprobando Gcore.
    s.engine.maintenance(name, until)
    s.events.add(actor=_actor(request), kind="config", domain=name,
                 summary=tn("Maintenance: automatic switching paused ({duration})", duration=tn(MAINTENANCE_OPTIONS[horas])))
    return _back(url, ok=tr("Automatic switching paused ({duration}). Alerts keep coming.", duration=tr(MAINTENANCE_OPTIONS[horas])))


@router.post("/dominios/{name}/automatico/reanudar")
async def automatico_reanudar(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    s.engine.resume(name)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Automatic switching resumed"))
    asyncio.create_task(run_engine(s))
    return _back(request.url_for("dominio", name=name), ok=tr("Automatic switching resumed"))


@router.post("/dominios/{name}/automatico/descartar")
async def automatico_descartar(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    s.engine.clear_error(name)
    return _back(request.url_for("dominio", name=name), ok=tr("Last failure dismissed"))
