"""Envío de alertas por Telegram y email a partir de los eventos del historial.

Qué se avisa:
  - cambios de CDN reales (no los simulados)
  - alertas (origen expuesto, bloqueos que empiezan o terminan, feed caído)
  - errores (conmutación o preparación fallida, renovación de certificado fallida)
  - seguridad (bloqueo por intentos fallidos)
  - preparación en Gcore y renovación de certificados correctas
Los avisos iguales se agrupan: el mismo texto no se repite en 10 minutos.
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

from .i18n import LANGS, N_, tn, translate

log = logging.getLogger("multicdn.notify")
DEDUP_SECONDS = 600
ICON = {"switch": "🔀", "alert": "⚠️", "error": "❌", "auth": "🔐", "config": "✅"}
# Resúmenes de configuración que se avisan (mismas claves que en gcore_setup), en cualquier idioma:
# el historial guarda el texto en el idioma en que se escribió.
NOTIFIED_CONFIG = (N_("Prepared on Gcore: resource {id}, certificate until {date}"),
                   N_("Certificate renewed on Gcore, valid until {date}"))


def _config_prefixes() -> tuple[str, ...]:
    return tuple(translate(key, lang).split("{")[0] for key in NOTIFIED_CONFIG for lang in LANGS)


def should_notify(event: dict) -> bool:
    kind = event["kind"]
    if kind == "switch":
        return not event.get("simulated")
    if kind in ("alert", "error"):
        return True
    if kind == "auth":
        summary = event["summary"].lower()
        return "bloque" in summary or "blocked" in summary
    if kind == "config":
        # Primera preparación y renovaciones automáticas; una actualización la lanza el usuario.
        return event["summary"].startswith(_config_prefixes())
    return False


def format_text(event: dict) -> tuple[str, str]:
    """Devuelve (asunto, cuerpo en texto plano)."""
    title = f"{ICON.get(event['kind'], 'ℹ️')} {event.get('domain') or 'Multi-CDN'}: {event['summary']}"
    lines = [title]
    if event.get("transition"):
        lines.append(tn("Switch: {transition}", transition=event["transition"]))
    for host, before, after in event.get("dns_diff") or []:
        lines.append(f"  {host}: {before} → {after}")
    if event.get("signals"):
        lines.append(tn("Signals: {signals}", signals=" · ".join(event["signals"])))
    lines.append(tn("By: {actor}", actor=event["actor"]))
    return title[:150], "\n".join(lines)


class Notifier:
    def __init__(self, secrets, client_factory=httpx.AsyncClient):
        self.secrets = secrets
        self.client_factory = client_factory
        self._recent: dict[str, float] = {}

    # Llamado por EventStore.add (síncrono): programa el envío sin bloquear.
    def __call__(self, event: dict) -> None:
        if not should_notify(event):
            return
        key = f"{event.get('domain')}|{event['summary']}"
        now = time.monotonic()
        if now - self._recent.get(key, -DEDUP_SECONDS) < DEDUP_SECONDS:
            return
        self._recent[key] = now
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # fuera del servidor (CLI, scripts): sin envío
        loop.create_task(self.send(event))

    async def send(self, event: dict) -> dict[str, str]:
        subject, body = format_text(event)
        results = {}
        if self.secrets.get("telegram_token") and self.secrets.get("telegram_chat_id"):
            results["telegram"] = await self._telegram(body)
        if self.secrets.get("smtp_url") and self.secrets.get("alert_email_to"):
            results["email"] = await asyncio.to_thread(self._email, subject, body)
        for channel, outcome in results.items():
            if outcome != "ok":
                log.warning("%s notification not sent: %s", channel, outcome)
        return results

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
