"""Settings: provider accounts, servers, notifications, automatic switching and system."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from .. import envfile, envparse, error_reporting, heartbeat, i18n, notify
from ..credentials import ENV_TOKENS, PROVIDERS
from ..engine import failover
from ..gcore_usage import refresh_usage
from ..i18n import N_, tn, tr, trn
from ..inventory_store import origin_key
from ..providers import cloudflare as cf
from ..providers import gcore
from ..secrets_store import CREDENTIALS
from ..state import State
from ..tasks import (
    FEED_INTERVAL_OPTIONS,
    feed_interval,
    feed_mode,
    refresh_calendar,
    refresh_cloudflare,
)
from .common import (
    _actor,
    _after_inventory_change,
    _card,
    _env_view,
    _env_warning,
    _secret_save,
    _settings_page,
    _state,
    _with_env_warning,
    env_mismatches,
)

router = APIRouter()


# ---------------------------------------------------------------- Ajustes
# Six tabs in setup order (_macros.settings_tabs): cuentas, servidores, notificaciones, cambio
# (automatic switching), sistema, cuenta. Every save returns to its card (?card=<id>#<id>) and
# the card shows the message (_macros.card_flash).


@router.get("/ajustes")
async def ajustes(request: Request):
    return RedirectResponse(request.url_for("ajustes_cuentas"), status_code=303)


@router.get("/ajustes/operacion")
async def ajustes_operacion(request: Request):
    """Before 0.3.1: Settings → Operation, now Automatic switching (and System)."""
    return RedirectResponse(request.url_for("ajustes_cambio"), status_code=301)


# ---- 1. Cuentas de proveedor

async def _check_credential(s: State, cred_id: int) -> tuple[bool, str]:
    cred, secret = s.creds.get(cred_id), s.creds.secret(cred_id)
    if not secret:
        ok, msg, scope = False, tn("Cannot decrypt it: has the master key changed?"), None
    elif cred.provider == "cloudflare":
        ok, msg = await cf.verify_token(secret)
        scope = None
        if ok:
            zones = await cf.list_zones(secret)
            scope = ", ".join(z["name"] for z in zones) or tn("no zone")
            msg = tn("Token active · access to {n} zone(s)", n=len(zones))
            assigned = [z["name"] for z in zones if z["name"] in s.inventory.domains and s.store.assign_zone(z["name"], z["id"], cred_id)]
            if assigned:
                msg = tn("Token active · access to {n} zone(s) · assigned to {domains}", n=len(zones), domains=", ".join(assigned))
                s.reload()
                await refresh_cloudflare(s)
    else:
        ok, msg = await gcore.verify_token(secret)
        scope = None
        if ok and os.environ.get("MULTICDN_OFFLINE") != "1":
            asyncio.create_task(refresh_usage(s))
    s.creds.record_check(cred_id, ok, msg, scope)
    return ok, msg


@router.get("/ajustes/cuentas", response_class=HTMLResponse)
async def ajustes_cuentas(request: Request):
    s = _state(request)
    creds = []
    for c in s.creds.list():
        info = s.creds.env_status(c)
        creds.append((c, s.creds.usage(c.id),
                      _env_view(info["source"], info["at"], info["env"], info["state"], info["error"])))
    return _settings_page(request, "cuentas", "ajustes_cuentas.html", creds=creds, providers=PROVIDERS,
                          key_on_disk=s.secrets.key_on_disk, usage=s.gcore_usage, env_removed=s.creds.env_removed())


@router.post("/ajustes/cuentas")
async def cuenta_crear(request: Request, provider: str = Form(...), label: str = Form(""), secret: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    try:
        cred_id = s.creds.add(provider, label, secret)
    except ValueError as exc:
        return _card(url, "nueva-cuenta", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("{provider} credential added: {label}", provider=PROVIDERS[provider], label=label.strip()))
    try:
        ok, msg = await _check_credential(s, cred_id)
    except httpx.HTTPError as exc:
        ok, msg = False, tr("Saved, but it could not be verified: {error}", error=type(exc).__name__)
    card = f"cuenta-{cred_id}"
    if ok:
        return _card(url, card, ok=tr('"{label}" saved. {msg}', label=label.strip(), msg=msg))
    return _card(url, card, error=tr('"{label}" saved, but the verification failed: {msg}', label=label.strip(), msg=msg))


@router.post("/ajustes/cuentas/{cred_id}/probar")
async def cuenta_probar(request: Request, cred_id: int):
    return await _probe_credential(request, cred_id)


async def _probe_credential(request: Request, cred_id: int, extra: str = "") -> RedirectResponse:
    s = _state(request)
    try:
        ok, msg = await _check_credential(s, cred_id)
    except (ValueError, httpx.HTTPError) as exc:
        ok, msg = False, str(exc) or type(exc).__name__
    if extra:
        msg = f"{extra} · {msg}"
    return _card(request.url_for("ajustes_cuentas"), f"cuenta-{cred_id}", **({"ok": msg} if ok else {"error": msg}))


@router.post("/ajustes/cuentas/{cred_id}/rotar")
async def cuenta_rotar(request: Request, cred_id: int, secret: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    if not secret.strip():
        return _card(url, f"cuenta-{cred_id}", error=tr("Enter the new credential"))
    try:
        s.creds.rotate(cred_id, secret)
        cred = s.creds.get(cred_id)
    except ValueError as exc:
        return _card(url, f"cuenta-{cred_id}", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Credential rotated: {label}", label=cred.label))
    extra = ""
    if (linked := s.creds.env_credential(cred.provider)) and linked.id == cred_id:
        env = ENV_TOKENS[cred.provider]
        extra = _env_warning(envfile.write_back(s.secrets, env, secret), env)
    return await _probe_credential(request, cred_id, extra)


@router.post("/ajustes/cuentas/{cred_id}/eliminar")
async def cuenta_eliminar(request: Request, cred_id: int):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    try:
        cred = s.creds.get(cred_id)
        linked = s.creds.env_credential(cred.provider)
        s.creds.delete(cred_id)
    except ValueError as exc:
        return _card(url, f"cuenta-{cred_id}", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Credential deleted: {label}", label=cred.label))
    msg = tr('"{label}" deleted', label=cred.label)
    if linked and linked.id == cred_id:
        env = ENV_TOKENS[cred.provider]
        msg = _with_env_warning(msg, envfile.write_back(s.secrets, env, None), env)
    return _card(url, "lista-cuentas", ok=msg)


# ---- 2. Servidores

def _ip_hint(ip: str | None) -> str | None:
    """Only the last part of the origin IP, like any other secret: "···.10"."""
    if not ip:
        return None
    return "···." + ip.rsplit(".", 1)[-1] if "." in ip else "···:" + ip.rsplit(":", 1)[-1]


@router.get("/ajustes/servidores", response_class=HTMLResponse)
async def ajustes_servidores(request: Request):
    s = _state(request)
    servers = [{"id": sid, "private_address": srv.private_address, "ip_hint": _ip_hint(s.secrets.get(origin_key(sid))),
                "hostnames": sum(h.server == sid for d in s.inventory.domains.values() for h in d.hostnames)}
               for sid, srv in s.inventory.servers.items()]
    from .. import firewall_status
    fw = firewall_status.read()
    return _settings_page(request, "servidores", "ajustes_servidores.html", servers=servers, fw=fw,
                          fw_changes=firewall_status.changes(), fw_problem=fw.problem(datetime.now(UTC)) if fw else None)


@router.post("/ajustes/servidores")
async def servidor_guardar(request: Request, server_id: str = Form(...), origin_ipv4: str = Form(""),
                           private_address: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    sid = server_id.strip().lower()
    try:
        s.store.upsert_server(sid, origin_ipv4.strip() or None, private_address.strip() or None)
    except ValueError as exc:
        return _card(url, "nuevo-servidor", error=tr("Server: {error}", error=exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Server {server} saved", server=server_id))
    await _after_inventory_change(s)
    return _card(url, f"servidor-{sid}", ok=tr("Server {server} saved", server=sid))


@router.post("/ajustes/servidores/{server_id}/editar")
async def servidor_editar(request: Request, server_id: str, new_id: str = Form(...), origin_ipv4: str = Form(""),
                          private_address: str = Form("")):
    """An empty IP field keeps the current IP (it is never shown); "Remove IP" removes it."""
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    if server_id not in s.inventory.servers:
        raise HTTPException(404)
    try:
        s.store.validate_server(origin_ipv4.strip() or None, private_address.strip() or None)  # before renaming
        s.store.rename_server(server_id, new_id)
        target = new_id.strip().lower()
        s.store.upsert_server(target, origin_ipv4.strip() or None, private_address.strip() or None)
    except ValueError as exc:
        return _card(url, f"servidor-{server_id}", error=tr("Server: {error}", error=exc))
    s.events.add(actor=_actor(request), kind="config",
                 summary=(tn("Server {server} updated (now {new})", server=server_id, new=target) if target != server_id
                          else tn("Server {server} updated", server=server_id)))
    await _after_inventory_change(s)
    return _card(url, f"servidor-{target}", ok=tr("Server {server} saved", server=target))


def hostnames_on_backup(s: State, server_id: str) -> list[str]:
    """Hostnames of this server that are on Gcore now (public DNS or the live Cloudflare record):
    returning them to Cloudflare needs the origin IP."""
    return sorted(h.name for d in s.inventory.domains.values() for h in d.hostnames
                  if h.server == server_id and (((r := s.resolutions.get(h.name)) and r.provider == "gcore")
                                                or (s.cf_live.get(h.name) or {}).get("to_backup")))


@router.post("/ajustes/servidores/{server_id}/quitar-ip")
async def servidor_quitar_ip(request: Request, server_id: str):
    s = _state(request)
    if server_id not in s.inventory.servers:
        raise HTTPException(404)
    if on_backup := hostnames_on_backup(s, server_id):
        return _card(request.url_for("ajustes_servidores"), f"servidor-{server_id}", error=trn(
            "{hostnames} is served by Gcore now and needs this IP to go back to Cloudflare: switch it back first",
            "{hostnames} are served by Gcore now and need this IP to go back to Cloudflare: switch them back first",
            len(on_backup), hostnames=", ".join(on_backup)))
    s.secrets.delete(origin_key(server_id))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Server {server}: origin IP removed", server=server_id))
    await _after_inventory_change(s)
    return _card(request.url_for("ajustes_servidores"), f"servidor-{server_id}",
                 ok=tr("Origin IP of {server} removed", server=server_id))


@router.post("/ajustes/servidores/{server_id}/eliminar")
async def servidor_eliminar(request: Request, server_id: str):
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    try:
        s.store.delete_server(server_id)
    except ValueError as exc:
        return _card(url, f"servidor-{server_id}", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Server {server} deleted", server=server_id))
    await _after_inventory_change(s)
    return _card(url, "servidores-titulo", ok=tr("Server {server} deleted", server=server_id))


# ---- 3. Notificaciones

@router.get("/ajustes/notificaciones", response_class=HTMLResponse)
async def ajustes_notificaciones(request: Request):
    s = _state(request)
    failures, notes = heartbeat.checks(s)
    return _settings_page(request, "notificaciones", "ajustes_notificaciones.html",
                          fields={f.name: f for f in s.secrets.all_status()}, beat=s.last_beat,
                          beat_failures=[tr(x) for x in failures], beat_notes=[tr(x) for x in notes],
                          notify_lang=i18n.notify_lang(), quota_gb=s.events.get_setting("gcore_quota_gb"),
                          weekly_summary=bool(s.events.get_setting("weekly_summary")))


@router.post("/ajustes/notificaciones/resumen")
async def resumen_semanal(request: Request, enabled: str = Form("")):
    s = _state(request)
    on = enabled == "1"
    s.events.set_setting("weekly_summary", int(on))
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Weekly summary enabled") if on else tn("Weekly summary disabled"))
    return _card(request.url_for("ajustes_notificaciones"), "resumen",
                 ok=tr("Weekly summary enabled") if on else tr("Weekly summary disabled"))


CHANNELS = {"telegram": ("telegram_token", "telegram_chat_id"), "email": ("smtp_url", "alert_email_to")}
NOTIFY_FIELDS = {name for names in CHANNELS.values() for name in names}


@router.post("/ajustes/notificaciones/canal/{canal}")
async def canal_guardar(request: Request, canal: str):
    """Guarda todos los campos rellenos del canal; los vacíos conservan su valor actual."""
    s = _state(request)
    if canal not in CHANNELS:
        raise HTTPException(404)
    form = await request.form()
    saved, failed, failed_keys = [], None, []
    values = {name: str(form.get(name, "")).strip() for name in CHANNELS[canal]}
    if any(envparse.bad_chars(v) for v in values.values()):
        return _card(request.url_for("ajustes_notificaciones"), f"canal-{canal}", error=tr("Enter a value"))
    for name, value in values.items():
        if value:
            if reason := _secret_save(s, name, value):
                failed, failed_keys = reason, [*failed_keys, CREDENTIALS[name][1]]
            saved.append(CREDENTIALS[name][0])  # translated at use: tr()/tn() below
    url = request.url_for("ajustes_notificaciones")
    if not saved:
        return _card(url, f"canal-{canal}", error=tr("You have not entered any new value"))
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Notifications: {fields} updated", fields=", ".join(tn(x) for x in saved)))
    msg = tr("Saved: {fields}", fields=", ".join(tr(x) for x in saved))
    return _card(url, f"canal-{canal}", ok=_with_env_warning(msg, failed, ", ".join(failed_keys)))


@router.post("/ajustes/notificaciones/latido")
async def latido_guardar(request: Request, heartbeat_url: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    value = heartbeat_url.strip()
    if not heartbeat.valid_url(value):
        return _card(url, "latido", error=tr("Paste the full ping URL (https://hc-ping.com/…)"))
    host = urlparse(value).hostname or ""
    if os.environ.get("MULTICDN_OFFLINE") != "1" and not await heartbeat.host_is_public(host, s.inventory.origin_ips):
        return _card(url, "latido", error=tr("The ping URL must point to a public server: {host} does not resolve to a public address",
                                             host=host))
    reason = _secret_save(s, "heartbeat_url", value)
    s.events.add(actor=_actor(request), kind="config", summary=tn("External heartbeat: URL updated"))
    return await _beat_now(request, _env_warning(reason, "MULTICDN_HEARTBEAT_URL"))


@router.post("/ajustes/notificaciones/latido/probar")
async def latido_probar(request: Request):
    return await _beat_now(request)


async def _beat_now(request: Request, warning: str = "") -> RedirectResponse:
    """Sends a heartbeat now and says how it went (plus `warning`, when saving left one)."""
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    b = await heartbeat.beat(s)
    if b is None:
        msg, ok = tr("The external heartbeat URL is missing"), False
    elif b.result != "ok":
        msg, ok = tr("Could not send the heartbeat: {result}", result=b.result), False
    elif b.ok:
        msg, ok = tr("Heartbeat sent: all good"), True
    else:
        msg, ok = tr("Heartbeat sent: failure reported ({detail})", detail=b.detail), True
    if warning:
        msg = f"{msg.rstrip('.')}. {warning}"
    return _card(url, "latido", **({"ok": msg} if ok else {"error": msg}))


# Fixed paths before /ajustes/notificaciones/{name}: the first matching route wins.
@router.post("/ajustes/notificaciones/idioma")
@router.post("/ajustes/operacion/idioma")  # before 0.3.1
async def idioma_guardar(request: Request, lang: str = Form("")):
    """Language of history, alerts and terminal output (what is stored or sent)."""
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    code = i18n.normalize(lang)
    if code is None:
        return _card(url, "idioma", error=tr("Language not available"))
    s.events.set_value("notify_lang", code)
    i18n.set_notify(code)
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Language of history and alerts: {language}", language=i18n.LANGS[code]))
    return _card(url, "idioma", ok=tr("Language of history and alerts saved: {language}", language=i18n.LANGS[code]))


@router.post("/ajustes/notificaciones/cuota")
@router.post("/ajustes/operacion/cuota")  # before 0.3.1
async def cuota_guardar(request: Request, gcore_quota_gb: int = Form(...)):
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    try:
        s.events.set_setting("gcore_quota_gb", gcore_quota_gb)
    except ValueError as exc:
        return _card(url, "cuota", error=tr("Quota: {error}", error=exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Gcore monthly quota: {gb} GB", gb=gcore_quota_gb))
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(refresh_usage(s))
    return _card(url, "cuota", ok=tr("Quota saved: {gb} GB per month", gb=gcore_quota_gb))


def _field_card(name: str) -> str:
    return "latido" if name == "heartbeat_url" else ("canal-telegram" if name.startswith("telegram") else "canal-email")


@router.post("/ajustes/notificaciones/{name}")
async def notificacion_guardar(request: Request, name: str, value: str = Form("")):
    s = _state(request)
    if name not in NOTIFY_FIELDS:
        raise HTTPException(404)
    url = request.url_for("ajustes_notificaciones")
    if not value.strip() or envparse.bad_chars(value.strip()):
        return _card(url, _field_card(name), error=tr("Enter a value"))
    reason = _secret_save(s, name, value)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Notifications: {fields} updated", fields=tn(CREDENTIALS[name][0])))
    return _card(url, _field_card(name), ok=_with_env_warning(tr("{field} saved", field=tr(CREDENTIALS[name][0])),
                                                              reason, CREDENTIALS[name][1]))


@router.post("/ajustes/notificaciones/{name}/eliminar")
async def notificacion_eliminar(request: Request, name: str):
    s = _state(request)
    if name not in NOTIFY_FIELDS | {"heartbeat_url"}:
        raise HTTPException(404)
    reason = _secret_save(s, name, None)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Notifications: {field} removed", field=tn(CREDENTIALS[name][0])))
    return _card(request.url_for("ajustes_notificaciones"), _field_card(name),
                 ok=_with_env_warning(tr("{field} removed", field=tr(CREDENTIALS[name][0])), reason, CREDENTIALS[name][1]))


@router.post("/ajustes/notificaciones/probar/{canal}")
async def notificacion_probar(request: Request, canal: str):
    s = _state(request)
    try:
        if canal == "telegram":
            token = s.secrets.get("telegram_token")
            ok, msg = await notify.verify_telegram(token, s.secrets.get("telegram_chat_id")) if token else (False, tr("The bot token is missing"))
        elif canal == "email":
            smtp = s.secrets.get("smtp_url")
            ok, msg = await notify.verify_smtp(smtp) if smtp else (False, tr("The SMTP server is missing"))
        else:
            raise HTTPException(404)
    except httpx.HTTPError as exc:
        ok, msg = False, tr("Network error: {error}", error=type(exc).__name__)
    return _card(request.url_for("ajustes_notificaciones"), f"canal-{canal}", **({"ok": msg} if ok else {"error": msg}))


# ---- 4. Cambio automático

FEED_REASONS = {
    "feed": N_("feed failing"),
    "calendar": N_("no match calendar"),
    "gcore": N_("domain on Gcore"),
    "blocks": N_("blocks underway"),
}


def feed_reason_text(s: State, now: datetime | None = None) -> str:
    """Why the feed is read at its current pace, for the pill on Settings → Automatic switching."""
    now = now or datetime.now(UTC)
    _seconds, reason = feed_mode(s, now)
    if reason is None:
        return tr("nothing going on")
    if reason == "match":
        match = s.calendar.active(now, max(failover.match_lead(s, p) for p in failover.PRIORITIES)) if s.calendar else None
        if match is None or match.kickoff <= now:
            return tr("match in progress")
        minutes = int((match.kickoff - now).total_seconds() // 60)
        return tr("match in {time}", time=f"{minutes // 60} h" if minutes >= 120 else f"{minutes} min")
    return tr(FEED_REASONS[reason])


def feed_option_label(seconds: int) -> str:
    if seconds == FEED_INTERVAL_OPTIONS[-1]:
        return tr("{minutes} min (default)", minutes=seconds // 60)
    return tr("{minutes} min", minutes=seconds // 60) if seconds % 60 == 0 else tr("{seconds} s", seconds=seconds)


@router.get("/ajustes/cambio", response_class=HTMLResponse)
async def ajustes_cambio(request: Request):
    s = _state(request)
    eligible = [n for n, d in s.inventory.domains.items() if failover.eligible(d)]
    on_gcore = {n for n, d in s.inventory.domains.items()
                if any((r := s.resolutions.get(h.name)) and r.provider == "gcore" for h in d.hostnames)}
    return _settings_page(
        request, "cambio", "ajustes_cambio.html", dry_run_env=s.dry_run_env, auto_on=failover.auto_enabled(s),
        auto_count=len(eligible), auto_on_gcore=len(on_gcore & set(eligible)),
        calendar=s.calendar, calendar_error=s.calendar_error, fd=s.secrets.status("football_data_token"),
        now=datetime.now(UTC),
        timings={p: {"match_lead": int(failover.match_lead(s, p).total_seconds() // 60),
                     "return_after": int(failover.return_after(s, p).total_seconds() // 60),
                     "default_lead": failover.DEFAULT_MATCH_LEAD[p], "default_wait": failover.DEFAULT_RETURN_AFTER[p]}
                 for p in failover.PRIORITIES},
        limits=failover.TIMING_LIMITS, feed_options=[(v, feed_option_label(v)) for v in FEED_INTERVAL_OPTIONS],
        feed_idle=s.events.get_setting("feed_interval"), feed_now=feed_interval(s, quiet=True),
        feed_why=feed_reason_text(s))


@router.post("/ajustes/cambio/tiempos")
@router.post("/ajustes/operacion/tiempos")  # before 0.3.1
async def tiempos_guardar(request: Request):
    """Antelación antes de un partido y espera sin bloqueos para volver, por prioridad."""
    s = _state(request)
    url = request.url_for("ajustes_cambio")
    form = await request.form()
    values = {}
    for kind, (lo, hi) in failover.TIMING_LIMITS.items():
        for p in failover.PRIORITIES:
            if form.get("reset"):
                values[(kind, p)] = failover.TIMING_DEFAULTS[kind][p]
                continue
            try:
                minutes = int(str(form.get(failover.timing_key(kind, p), "")))
            except ValueError:
                return _card(url, "tiempos", error=tr("Enter whole minutes"))
            if not lo <= minutes <= hi:
                return _card(url, "tiempos", error=tr("Times must be between {lo} and {hi} min", lo=lo, hi=hi))
            values[(kind, p)] = minutes
    for (kind, p), minutes in values.items():
        s.events.set_value(failover.timing_key(kind, p), str(minutes))
    summary = "; ".join(tn("{priority}: {lead} min before a match, back after {wait} min without blocks",
                           priority=tn(PRIORITY_NAME[p]), lead=values[("match_lead", p)], wait=values[("return_after", p)])
                        for p in failover.PRIORITIES)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Switching times: {summary}", summary=summary))
    return _card(url, "tiempos", ok=tr("Default switching times restored") if form.get("reset") else tr("Switching times saved"))


PRIORITY_NAME = {"critical": N_("Critical"), "medium": N_("Medium"), "low": N_("Low")}


@router.post("/ajustes/cambio/feed")
@router.post("/ajustes/operacion/feed")  # before 0.3.1
async def feed_guardar(request: Request, seconds: str = Form("")):
    """Idle interval between block feed reads (ADR-001); the fast one (90 s) is fixed."""
    s = _state(request)
    url = request.url_for("ajustes_cambio")
    try:
        value = int(seconds)
    except ValueError:
        value = 0
    if value not in FEED_INTERVAL_OPTIONS:
        return _card(url, "feed", error=tr("Choose one of the listed intervals"))
    s.events.set_setting("feed_interval", value)
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Block feed read every {seconds} s when nothing is going on", seconds=value))
    return _card(url, "feed", ok=tr("Feed interval saved"))


@router.post("/ajustes/cambio/automatico")
@router.post("/ajustes/operacion/automatico")  # before 0.3.1
async def automatico_global(request: Request, enabled: str = Form("")):
    s = _state(request)
    on = enabled == "1"
    s.events.set_setting("auto_switch", int(on))
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Automatic CDN switching enabled") if on else tn("Automatic CDN switching disabled for all domains"))
    return _card(request.url_for("ajustes_cambio"), "automatico",
                 ok=tr("Automatic switching enabled") if on else tr("Automatic switching disabled"))


@router.post("/ajustes/cambio/football-data")
@router.post("/ajustes/operacion/football-data")  # before 0.3.1
async def football_data_guardar(request: Request, token: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cambio")
    if not token.strip() or envparse.bad_chars(token.strip()):
        return _card(url, "calendario", error=tr("Enter the key"))
    reason = _secret_save(s, "football_data_token", token)
    s.events.add(actor=_actor(request), kind="config", summary=tn("football-data.org key saved"))
    await refresh_calendar(s)
    result = s.calendar.sources.get("football-data.org") if s.calendar else s.calendar_error
    if result == "ok" and s.calendar is not None:
        msg = tr("Key saved and verified · {n} matches in the calendar", n=len(s.calendar.matches))
        return _card(url, "calendario", ok=_with_env_warning(msg, reason, "FOOTBALL_DATA_TOKEN"))
    msg = tr("Key saved, but football-data.org is not responding properly: {result}", result=result)
    return _card(url, "calendario", error=_with_env_warning(msg, reason, "FOOTBALL_DATA_TOKEN"))


@router.post("/ajustes/cambio/football-data/quitar")
@router.post("/ajustes/operacion/football-data/eliminar")  # before 0.3.1
async def football_data_eliminar(request: Request):
    s = _state(request)
    reason = _secret_save(s, "football_data_token", None)
    s.events.add(actor=_actor(request), kind="config", summary=tn("football-data.org key removed"))
    await refresh_calendar(s)
    return _card(request.url_for("ajustes_cambio"), "calendario",
                 ok=_with_env_warning(tr("football-data.org key removed"), reason, "FOOTBALL_DATA_TOKEN"))


# ---- 5. Sistema

@router.get("/ajustes/sistema", response_class=HTMLResponse)
async def ajustes_sistema(request: Request):
    s = _state(request)
    return _settings_page(
        request, "sistema", "ajustes_sistema.html", key_on_disk=s.secrets.key_on_disk,
        ev_stats=s.events.stats(), ev_days=s.events.get_setting("events_max_days"),
        ev_rows=s.events.get_setting("events_max_rows"), error_reporting=error_reporting.status(),
        dsn=s.secrets.status("sentry_dsn"), env_file=envfile.status(s.secrets), env_mismatches=env_mismatches(s),
        env_managed=sorted(envfile.MANAGED), secrets_display=envfile.DISPLAY)


DSN_PROBLEMS = {
    "shape": N_("That is not a DSN: copy it from the project's settings (https://key@host/project)"),
    "https": N_("The DSN must use https"),
    "host": N_("The DSN must point to a public server name, not an IP address or a local name"),
}


@router.post("/ajustes/sistema/errores")
async def errores_guardar(request: Request, dsn: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_sistema")
    value = dsn.strip()
    if not value:
        return _card(url, "errores", error=tr("Paste the DSN"))
    if problem := error_reporting.dsn_problem(value):
        return _card(url, "errores", error=tr(DSN_PROBLEMS[problem]))
    host = urlparse(value).hostname or ""
    if os.environ.get("MULTICDN_OFFLINE") != "1" and not await heartbeat.host_is_public(host, s.inventory.origin_ips):
        return _card(url, "errores", error=tr("The DSN must point to a public server: {host} does not resolve to a public address",
                                              host=host))
    reason = _secret_save(s, "sentry_dsn", value)
    await asyncio.to_thread(error_reporting.reconfigure, value)  # closes the previous client: may wait
    s.events.add(actor=_actor(request), kind="config", summary=tn("Error reporting DSN updated"))
    return _card(url, "errores", ok=_with_env_warning(tr("Error reporting DSN saved"), reason, "MULTICDN_SENTRY_DSN"))


@router.post("/ajustes/sistema/errores/quitar")
async def errores_quitar(request: Request):
    s = _state(request)
    reason = _secret_save(s, "sentry_dsn", None)
    await asyncio.to_thread(error_reporting.reconfigure, None)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Error reporting DSN removed"))
    return _card(request.url_for("ajustes_sistema"), "errores",
                 ok=_with_env_warning(tr("Error reporting is off: nothing is sent"), reason, "MULTICDN_SENTRY_DSN"))


@router.post("/ajustes/sistema/errores/probar")
async def errores_probar(request: Request):
    url = request.url_for("ajustes_sistema")
    event_id = await asyncio.to_thread(error_reporting.send_test)  # waits up to 5 s for it to leave
    if not event_id:
        return _card(url, "errores", error=tr("Error reporting is off: save a DSN first"))
    return _card(url, "errores", ok=tr("Test error sent · event {id}", id=event_id))


@router.post("/ajustes/sistema/retencion")
@router.post("/ajustes/operacion/retencion")  # before 0.3.1
async def retencion_guardar(request: Request, events_max_days: int = Form(...), events_max_rows: int = Form(...)):
    s = _state(request)
    url = request.url_for("ajustes_sistema")
    try:
        s.events.set_setting("events_max_days", events_max_days)
        s.events.set_setting("events_max_rows", events_max_rows)
    except ValueError as exc:
        return _card(url, "mantenimiento", error=tr("Retention: {error}", error=exc))
    deleted = s.events.prune()
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("History retention: {days} days, at most {rows} events", days=events_max_days, rows=events_max_rows))
    return _card(url, "mantenimiento", ok=trn("Retention saved · {n} old event deleted",
                                              "Retention saved · {n} old events deleted", deleted))


@router.get("/ajustes/ficha-emergencia.txt")
async def ficha_emergencia(request: Request):
    from ..emergency import sheet
    return PlainTextResponse(
        sheet(_state(request).inventory, tr), media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="multicdn-emergency-sheet.txt"'},
    )


@router.get("/ajustes/inventario.yaml")
async def exportar(request: Request):
    return PlainTextResponse(
        _state(request).store.export_yaml(), media_type="application/yaml",
        headers={"Content-Disposition": 'attachment; filename="inventory.yaml"'},
    )
