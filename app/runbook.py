"""Cambio de CDN desde la terminal, para cuando el panel no está disponible (plan §9.6).

Usa el mismo código que el panel: la salvaguarda que impide exponer el origen, la comprobación
previa de Gcore, el historial, los avisos por Telegram/email y la pausa de 1 h del automático.

En el VPS:
  docker compose exec panel python -m app.cli estado
  docker compose exec panel python -m app.cli cambiar example.com gcore
Con el contenedor parado:
  docker compose run --rm panel python -m app.cli cambiar example.com cloudflare
"""

from __future__ import annotations

import asyncio
import os

import httpx

from .config import load_dotenv
from .i18n import tn

TARGETS = {"gcore": "Gcore", "cloudflare": "Cloudflare"}


def _state():
    from .auth import AuthStore
    from .credentials import CredentialStore
    from .db import EventStore
    from .inventory_store import InventoryStore
    from .main import State
    from .notifier import Notifier
    from .secrets_store import SecretStore

    db = os.environ.get("MULTICDN_DB", "data/multicdn.db")
    secrets = SecretStore(db)
    events = EventStore(db)
    events.listeners.append(Notifier(secrets))
    from . import i18n
    from .main import load_notify_lang
    load_notify_lang(events)
    i18n.set_ui(i18n.notify_lang())  # the terminal speaks the notification language
    state = State(store=InventoryStore(secrets), secrets=secrets, creds=CredentialStore(secrets),
                  auth=AuthStore(secrets), events=events,
                  dry_run_env=os.environ.get("MULTICDN_DRY_RUN", "true").lower() != "false")
    state.client = httpx.AsyncClient(headers={"User-Agent": "multicdn-controller"})
    return state


async def _observe(state) -> None:
    """DNS público y registros reales en Cloudflare, sin lanzar el motor automático."""
    from .main import apply_cf_live, refresh_cloudflare
    from .signals import dnscheck

    await refresh_cloudflare(state)
    if not state.cf_ranges:
        state.cf_ranges = await dnscheck.fetch_cloudflare_ranges(state.client)
    hosts = [h.name for d in state.inventory.domains.values() for h in d.hostnames]
    state.resolutions = await dnscheck.resolve_all(hosts, state.cf_ranges, state.inventory.origin_ips)
    apply_cf_live(state)


async def _drain() -> None:
    """Deja terminar los avisos pendientes (Telegram/email) antes de salir."""
    me = asyncio.current_task()
    await asyncio.gather(*[t for t in asyncio.all_tasks() if t is not me], return_exceptions=True)


def _mode(state) -> str:
    return tn("Mode: DRY RUN (DNS is not touched)") if state.dry_run else tn("Mode: live")


def _no_switch() -> str:
    return "  " + tn("(does not switch)")


async def status(out=print) -> int:
    from .views import build_all

    state = _state()
    try:
        await _observe(state)
        out(_mode(state))
        for d in build_all(state.inventory, state.resolutions, state.feed, state.engine.known_ips()):
            out(f"\n{d.name}  ·  {d.status_label}")
            for h in d.hosts:
                out(f"  {h.name:34} {h.provider_label:18} {h.dns_text}{'' if h.failover else _no_switch()}")
        return 0
    finally:
        await state.client.aclose()


async def switch(name: str, target: str, *, assume_yes: bool = False, force: bool = False,
                 out=print, ask=input) -> int:
    from .engine import failover

    if target not in TARGETS:
        out(tn("Invalid target: {target} (gcore or cloudflare)", target=target))
        return 2
    state = _state()
    try:
        if name not in state.inventory.domains:
            out(tn("{domain} is not in the inventory", domain=name))
            return 2
        await _observe(state)
        domain = state.inventory.domains[name]
        out(_mode(state))
        for h in domain.hostnames:
            r = state.resolutions.get(h.name)
            now = tn("now: {provider}", provider=r.provider if r else tn("unresolved"))
            out(f"  {h.name:34} {now}{'' if h.failover else _no_switch()}")
        if target == "gcore":
            out(tn("Checking that Gcore serves the domain…"))
            problem = await failover.check_backup(state, name)
            if problem:
                out(tn("WARNING: {problem}", problem=problem))
                if not force:
                    out(tn("Not switching. Repeat with --force if you still want to move it to Gcore."))
                    return 1
            else:
                out(tn("Gcore responds on all its edges."))
        if not assume_yes and ask(tn("Type {domain} to move it to {target}: ", domain=name,
                                     target=TARGETS[target])).strip() != name:
            out(tn("Cancelled: nothing has changed"))
            return 1
        try:
            if target == "gcore":
                diff, simulated = await failover.switch_to_gcore(state, name)
            else:
                diff, simulated = await failover.return_to_cloudflare(
                    state, name, force_all=state.dry_run and state.engine.get(name).sim_backup is True)
        except failover.SwitchFailed as exc:
            state.events.add(actor="cli", kind="error", domain=name, summary=tn("Switch from the terminal failed: {error}", error=exc),
                             dns_diff=exc.diff)
            out(tn("ERROR: {error}", error=exc))
            return 1
        if not diff:
            out(tn("Nothing to change: it was already on {target}", target=TARGETS[target]))
            return 0
        state.engine.manual_change(name, to_backup=target == "gcore", simulated=simulated)
        transition = "CF → GCORE" if target == "gcore" else "GCORE → CF"
        state.events.add(actor="cli", kind="switch", domain=name, transition=transition,
                         summary=tn("Manual switch to {target} from the terminal", target=TARGETS[target]),
                         dns_diff=diff, simulated=simulated)
        for host, before, after in diff:
            out(f"  {host}: {before} → {after}")
        out(tn("Simulated: DNS has not been touched. Automatic mode for this domain is paused for 1 h.")
            if simulated else tn("Applied. Automatic mode for this domain is paused for 1 h."))
        return 0
    finally:
        await _drain()
        await state.client.aclose()


def run(coro) -> int:
    load_dotenv()
    return asyncio.run(coro)
