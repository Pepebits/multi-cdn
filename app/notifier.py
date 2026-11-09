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
import time
from email.message import EmailMessage
from urllib.parse import unquote, urlparse

import httpx

log = logging.getLogger("multicdn.notify")
DEDUP_SECONDS = 600
ICON = {"switch": "🔀", "alert": "⚠️", "error": "❌", "auth": "🔐", "config": "✅"}


def should_notify(event: dict) -> bool:
    kind = event["kind"]
    if kind == "switch":
        return not event.get("simulated")
    if kind in ("alert", "error"):
        return True
    if kind == "auth":
        return "bloque" in event["summary"].lower()
    if kind == "config":
        s = event["summary"]
        # Primera preparación y renovaciones automáticas; una actualización la lanza el usuario.
        return s.startswith("Preparado en Gcore") or s.startswith("Certificado renovado")
    return False


def format_text(event: dict) -> tuple[str, str]:
    """Devuelve (asunto, cuerpo en texto plano)."""
    title = f"{ICON.get(event['kind'], 'ℹ️')} {event.get('domain') or 'Multi-CDN'}: {event['summary']}"
    lines = [title]
    if event.get("transition"):
        lines.append(f"Cambio: {event['transition']}")
    for host, before, after in event.get("dns_diff") or []:
        lines.append(f"  {host}: {before} → {after}")
    if event.get("signals"):
        lines.append("Señales: " + " · ".join(event["signals"]))
    lines.append(f"Por: {event['actor']}")
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
                log.warning("aviso por %s no enviado: %s", channel, outcome)
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
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = f"[Multi-CDN] {subject}", sender, to
        msg.set_content(body)
        try:
            port = u.port or (465 if u.scheme == "smtps" else 587)
            cls = smtplib.SMTP_SSL if u.scheme == "smtps" else smtplib.SMTP
            with cls(u.hostname, port, timeout=20) as s:
                if u.scheme == "smtp":
                    s.starttls()
                if u.username:
                    s.login(unquote(u.username), unquote(u.password or ""))
                s.send_message(msg)
            return "ok"
        except (smtplib.SMTPException, OSError) as exc:
            return type(exc).__name__
