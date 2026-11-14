"""Verificación de canales de notificación (el envío de alertas llega en la fase 3)."""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from urllib.parse import unquote, urlparse

import httpx

from .i18n import tr


async def verify_telegram(token: str, chat_id: str | None) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"https://api.telegram.org/bot{token}/getMe")
        if r.status_code != 200 or not r.json().get("ok"):
            return False, tr("Telegram rejected the bot token")
        bot = r.json()["result"]["username"]
        if not chat_id:
            return True, tr("Bot @{bot} is valid; the chat ID is missing", bot=bot)
        r = await client.post(f"https://api.telegram.org/bot{token}/sendMessage",
                              json={"chat_id": chat_id, "text": tr("Multi-CDN: test notification ✅")})
    if r.status_code == 200 and r.json().get("ok"):
        return True, tr("Test message sent by @{bot}", bot=bot)
    return False, tr("Bot @{bot} could not write to chat {chat}", bot=bot, chat=chat_id)


def _smtp_check(url: str) -> tuple[bool, str]:
    u = urlparse(url)
    if u.scheme not in ("smtp", "smtps") or not u.hostname:
        return False, tr("Use smtp://… or smtps://user:password@host:port")
    port = u.port or (465 if u.scheme == "smtps" else 587)
    context = ssl.create_default_context()  # verifica certificado y nombre del servidor
    if u.scheme == "smtps":
        server = smtplib.SMTP_SSL(u.hostname, port, timeout=15, context=context)
    else:
        server = smtplib.SMTP(u.hostname, port, timeout=15)
    with server as s:
        if u.scheme == "smtp":
            s.starttls(context=context)
        if u.username:
            s.login(unquote(u.username), unquote(u.password or ""))
    return True, tr("Connection and authentication OK with {host}:{port}", host=u.hostname, port=port)


async def verify_smtp(url: str) -> tuple[bool, str]:
    try:
        return await asyncio.to_thread(_smtp_check, url)
    except (smtplib.SMTPException, OSError) as exc:
        return False, f"SMTP: {type(exc).__name__}"
