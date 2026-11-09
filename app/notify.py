"""Verificación de canales de notificación (el envío de alertas llega en la fase 3)."""

from __future__ import annotations

import asyncio
import smtplib
from urllib.parse import unquote, urlparse

import httpx


async def verify_telegram(token: str, chat_id: str | None) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"https://api.telegram.org/bot{token}/getMe")
        if r.status_code != 200 or not r.json().get("ok"):
            return False, "Telegram rechazó el token del bot"
        bot = r.json()["result"]["username"]
        if not chat_id:
            return True, f"Bot @{bot} válido; falta el chat ID"
        r = await client.post(f"https://api.telegram.org/bot{token}/sendMessage",
                              json={"chat_id": chat_id, "text": "Multi-CDN: prueba de notificación ✅"})
    if r.status_code == 200 and r.json().get("ok"):
        return True, f"Mensaje de prueba enviado por @{bot}"
    return False, f"El bot @{bot} no pudo escribir en el chat {chat_id}"


def _smtp_check(url: str) -> tuple[bool, str]:
    u = urlparse(url)
    if u.scheme not in ("smtp", "smtps") or not u.hostname:
        return False, "Usa smtp://… o smtps://usuario:contraseña@host:puerto"
    port = u.port or (465 if u.scheme == "smtps" else 587)
    cls = smtplib.SMTP_SSL if u.scheme == "smtps" else smtplib.SMTP
    with cls(u.hostname, port, timeout=15) as s:
        if u.scheme == "smtp":
            s.starttls()
        if u.username:
            s.login(unquote(u.username), unquote(u.password or ""))
    return True, f"Conexión y autenticación correctas con {u.hostname}:{port}"


async def verify_smtp(url: str) -> tuple[bool, str]:
    try:
        return await asyncio.to_thread(_smtp_check, url)
    except (smtplib.SMTPException, OSError) as exc:
        return False, f"SMTP: {type(exc).__name__}"
