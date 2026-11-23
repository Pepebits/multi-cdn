"""Envío de alertas por Telegram y email a partir de los eventos del historial.

Qué se avisa:
  - cambios de CDN reales (no los simulados)
  - alertas (origen expuesto, bloqueos que empiezan o terminan, feed caído)
  - errores (conmutación o preparación fallida, renovación de certificado fallida)
  - seguridad (bloqueo por intentos fallidos)
  - preparación en Gcore y renovación de certificados correctas
Los avisos iguales se agrupan: el mismo texto no se repite en 10 minutos.
Los de inicio y fin de bloqueo tienen además un tope por dominio (BLOCK_BURST por hora): si el
estado va y viene, se avisa una vez de que se silencian y el resto queda solo en el historial.
"""

from __future__ import annotations

import asyncio
import html
import logging
import smtplib
import ssl
import time
from email.message import EmailMessage
from urllib.parse import unquote, urlparse

import httpx

from . import event_codes
from .i18n import tn

log = logging.getLogger("multicdn.notify")
DEDUP_SECONDS = 600
BLOCK_BURST, BLOCK_WINDOW = 4, 3600
RETRY_DELAYS = (5, 30)  # seconds before the 2nd and 3rd attempt of a failed delivery
BLOCK_CODES = (event_codes.BLOCK_START, event_codes.BLOCK_END)
# Configuración que se avisa: la primera preparación y las renovaciones automáticas (una
# actualización la lanza el usuario, que ya lo ve en el panel).
NOTIFIED_CONFIG = (event_codes.GCORE_PREPARED, event_codes.CERT_RENEWED, event_codes.WEEKLY_SUMMARY)
ICON = {"switch": "🔀", "alert": "⚠️", "error": "❌", "auth": "🔐", "config": "✅"}


def should_notify(event: dict) -> bool:
    kind = event["kind"]
    if kind == "switch":
        return not event.get("simulated")
    if kind in ("alert", "error"):
        return True
    if kind == "auth":
        return event.get("code") == event_codes.LOGIN_LOCKED
    if kind == "config":
        return event.get("code") in NOTIFIED_CONFIG
    return False


def format_text(event: dict) -> tuple[str, str]:
    """Devuelve (asunto, cuerpo en texto plano)."""
    weekly = event.get("code") == event_codes.WEEKLY_SUMMARY
    icon = "📊" if weekly else ICON.get(event["kind"], "ℹ️")
    title = f"{icon} {event.get('domain') or 'Multi-CDN'}: {event['summary']}"
    lines = [title]
    if event.get("transition"):
        lines.append(tn("Switch: {transition}", transition=event["transition"]))
    for host, before, after in event.get("dns_diff") or []:
        lines.append(f"  {host}: {before} → {after}")
    if weekly:
        lines += event.get("signals") or []  # one line per domain, not "Signals: a · b"
        return title[:150], "\n".join(lines)
    if event.get("signals"):
        lines.append(tn("Signals: {signals}", signals=" · ".join(event["signals"])))
    lines.append(tn("By: {actor}", actor=event["actor"]))
    return title[:150], "\n".join(lines)


class Notifier:
    def __init__(self, secrets, client_factory=httpx.AsyncClient, events=None, retry_delays=RETRY_DELAYS):
        self.secrets = secrets
        self.client_factory = client_factory
        # Where to note an alert that could not be delivered (the history); None in tests.
        self.events = events
        self.retry_delays = retry_delays
        self._recent: dict[str, float] = {}
        self._block_sent: dict[str, list[float]] = {}  # dominio -> envíos de inicio/fin de bloqueo en la última hora

    # Llamado por EventStore.add (síncrono): programa el envío sin bloquear.
    def __call__(self, event: dict) -> None:
        if not should_notify(event):
            return
        key = f"{event.get('domain')}|{event['summary']}"
        now = time.monotonic()
        if now - self._recent.get(key, -DEDUP_SECONDS) < DEDUP_SECONDS:
            return
        self._recent[key] = now
        if event.get("code") in BLOCK_CODES:
            domain = event.get("domain") or ""
            sent = [t for t in self._block_sent.get(domain, []) if now - t < BLOCK_WINDOW]
            self._block_sent[domain] = sent + [now]
            if len(sent) > BLOCK_BURST:
                return
            if len(sent) == BLOCK_BURST:
                event = {**event, "summary": tn(
                    "Block state keeps changing; block alerts for this domain are muted for 1 h (see the panel history)")}
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # fuera del servidor (CLI, scripts): sin envío
        loop.create_task(self.send(event))

    async def send(self, event: dict) -> dict[str, str]:
        subject, body = format_text(event)
        results = {}
        if self.secrets.get("telegram_token") and self.secrets.get("telegram_chat_id"):
            results["telegram"] = await self._retry(lambda: self._telegram(body))
        if self.secrets.get("smtp_url") and self.secrets.get("alert_email_to"):
            results["email"] = await self._retry(lambda: asyncio.to_thread(self._email, subject, body))
        for channel, outcome in results.items():
            if outcome != "ok":
                log.error("%s notification not sent: %s", channel, outcome)
                if self.events is not None:  # kind "verify" is never notified: no loop
                    self.events.add(actor="auto", kind="verify", domain=event.get("domain"), summary=tn(
                        "Alert not delivered by {channel} ({error}): {summary}", channel=channel.capitalize(),
                        error=outcome, summary=event["summary"][:200]))
        return results

    async def _retry(self, attempt) -> str:
        """Tries once and again after each delay in retry_delays; the last outcome."""
        outcome = await attempt()
        for delay in self.retry_delays:
            if outcome == "ok":
                break
            await asyncio.sleep(delay)
            outcome = await attempt()
        return outcome

    async def _telegram(self, text: str) -> str:
        token, chat = self.secrets.get("telegram_token"), self.secrets.get("telegram_chat_id")
        first, _, rest = text.partition("\n")
        message = f"<b>{html.escape(first)}</b>" + (f"\n<pre>{html.escape(rest)}</pre>" if rest else "")
        try:
            async with self.client_factory(timeout=15) as c:
                r = await c.post(f"https://api.telegram.org/bot{token}/sendMessage",
                                 json={"chat_id": chat, "text": message[:4000], "parse_mode": "HTML",
                                       "disable_web_page_preview": True})
            return "ok" if r.status_code == 200 and r.json().get("ok") else f"HTTP {r.status_code}"
        except httpx.HTTPError as exc:
            return type(exc).__name__

    def _email(self, subject: str, body: str) -> str:
        u = urlparse(self.secrets.get("smtp_url"))
        to = self.secrets.get("alert_email_to")
        sender = unquote(u.username) if u.username and "@" in unquote(u.username) else to
        # Una cabecera no admite saltos de línea (EmailMessage lanza ValueError): el asunto va en
        # una sola línea y el texto completo queda en el cuerpo.
        subject = " ".join(f"[Multi-CDN] {subject}".split())
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = subject, sender, to
            msg.set_content(body)
            port = u.port or (465 if u.scheme == "smtps" else 587)
            context = ssl.create_default_context()  # verifica certificado y nombre del servidor
            if u.scheme == "smtps":
                server = smtplib.SMTP_SSL(u.hostname, port, timeout=20, context=context)
            else:
                server = smtplib.SMTP(u.hostname, port, timeout=20)
            with server as s:
                if u.scheme == "smtp":
                    s.starttls(context=context)
                if u.username:
                    s.login(unquote(u.username), unquote(u.password or ""))
                s.send_message(msg)
            return "ok"
        except (smtplib.SMTPException, OSError) as exc:
            return type(exc).__name__
        except Exception as exc:  # nunca debe matar la tarea de envío sin dejar rastro
            log.exception("email notification failed")
            return type(exc).__name__
