"""Gestión de usuarios del panel desde el servidor.

Uso:
  uv run python -m app.cli crear-usuario <usuario>
  uv run python -m app.cli cambiar-password <usuario>
  uv run python -m app.cli reiniciar-totp <usuario>
  uv run python -m app.cli cerrar-sesiones [<usuario>]
  uv run python -m app.cli listar-usuarios
  uv run python -m app.cli secretos-origen [--caddy|--mostrar]   (X-Origin-Auth: huellas, fichero de Caddy)
  uv run python -m app.cli rotar-secreto-origen cloudflare|gcore
  uv run python -m app.cli retirar-secreto-anterior cloudflare|gcore
  uv run python -m app.cli copia-seguridad [<fichero>]
  uv run python -m app.cli estado                                  (dónde se sirve cada dominio)
  uv run python -m app.cli cambiar <dominio> gcore|cloudflare [--si] [--forzar]
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from .auth import PASSWORD_MIN, AuthStore
from .config import load_dotenv
from .db import EventStore
from .secrets_store import SecretStore


def _store() -> tuple[AuthStore, EventStore]:
    load_dotenv()
    db = os.environ.get("MULTICDN_DB", "data/multicdn.db")
    return AuthStore(SecretStore(db)), EventStore(db)


def _ask_password() -> str:
    while True:
        first = getpass.getpass(f"Nueva contraseña (mínimo {PASSWORD_MIN} caracteres): ")
        if len(first) < PASSWORD_MIN:
            print("Demasiado corta.")
            continue
        if getpass.getpass("Repite la contraseña: ") != first:
            print("No coinciden.")
            continue
        return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Panel Multi-CDN desde la terminal")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("crear-usuario", "cambiar-password", "reiniciar-totp"):
        sub.add_parser(name).add_argument("usuario")
    sub.add_parser("cerrar-sesiones").add_argument("usuario", nargs="?")
    sub.add_parser("listar-usuarios")
    so = sub.add_parser("secretos-origen", help="huellas de los secretos de X-Origin-Auth")
    so.add_argument("--caddy", action="store_true", help="imprime el fichero (origin_auth) para Caddy, con los valores")
    so.add_argument("--mostrar", action="store_true", help="muestra los valores (para configurar un CDN a mano)")
    for cmd in ("rotar-secreto-origen", "retirar-secreto-anterior"):
        sub.add_parser(cmd).add_argument("cdn", choices=["cloudflare", "gcore"])
    sub.add_parser("copia-seguridad").add_argument("destino", nargs="?")
    sub.add_parser("estado", help="dónde se sirve cada dominio")
    sw = sub.add_parser("cambiar", help="cambia un dominio de CDN sin el panel")
    sw.add_argument("dominio")
    sw.add_argument("destino", choices=["gcore", "cloudflare"])
    sw.add_argument("--si", action="store_true", help="no pedir confirmación")
    sw.add_argument("--forzar", action="store_true", help="pasar a Gcore aunque falle la comprobación previa")
    args = parser.parse_args(argv)
    if args.cmd in ("estado", "cambiar"):
        from . import runbook
        if args.cmd == "estado":
            return runbook.run(runbook.status())
        return runbook.run(runbook.switch(args.dominio, args.destino, assume_yes=args.si, force=args.forzar))
    if args.cmd == "copia-seguridad":
        from pathlib import Path

        from .backup import backup
        load_dotenv()
        print(f"Copia guardada en {backup(Path(args.destino) if args.destino else None)}")
        return 0
    auth, events = _store()

    if args.cmd in ("secretos-origen", "rotar-secreto-origen", "retirar-secreto-anterior"):
        from .gcore_setup import (caddy_origin_snippet, fingerprint, origin_secret, retire_previous_secret,
                                  rotate_origin_secret)
        secrets = SecretStore(os.environ.get("MULTICDN_DB", "data/multicdn.db"))
        if args.cmd == "rotar-secreto-origen":
            rotate_origin_secret(secrets, args.cdn)
            events.add(actor="cli", kind="config", summary=f"Secreto de origen de {args.cdn} rotado (el anterior sigue aceptado)")
            print(f"Nuevo secreto para {args.cdn}. Ahora: regenera el fichero de Caddy (--caddy) y recárgalo,")
            print("aplica el secreto en ese CDN (panel: «Aplicar en Cloudflare» o «Actualizar en Gcore») y, cuando")
            print(f"todos sus dominios estén al día, retira el anterior: retirar-secreto-anterior {args.cdn}")
            return 0
        if args.cmd == "retirar-secreto-anterior":
            done = retire_previous_secret(secrets, args.cdn)
            if done:
                events.add(actor="cli", kind="config", summary=f"Secreto de origen anterior de {args.cdn} retirado")
            print("Retirado: regenera el fichero de Caddy (--caddy) y recárgalo." if done else "No había secreto anterior.")
            return 0
        if args.caddy:
            print(caddy_origin_snippet(secrets), end="")
            return 0
        for cdn in ("cloudflare", "gcore"):
            value = origin_secret(secrets, cdn)
            prev = secrets.get(f"origin_auth:{cdn}:anterior")
            print(f"{cdn:10} huella {fingerprint(value)}" + (f" · anterior {fingerprint(prev)} aún aceptado" if prev else "")
                  + (f" · valor {value}" if args.mostrar else ""))
        if not args.mostrar:
            print("Los valores no se muestran. Fichero para Caddy: secretos-origen --caddy | sudo tee /etc/caddy/origin-auth.caddy")
        return 0

    if args.cmd == "listar-usuarios":
        for u in auth.list_users():
            print(f"{u.username}\tTOTP {'activo' if u.totp_enabled else 'pendiente'}")
        return 0

    user = auth.get_user(args.usuario) if getattr(args, "usuario", None) else None
    if args.cmd == "crear-usuario":
        auth.create_user(args.usuario, _ask_password())
        events.add(actor="cli", kind="auth", summary=f"Usuario {args.usuario.lower()} creado desde la terminal")
        print(f"Usuario {args.usuario.lower()} creado. Al entrar en el panel se te pedirá configurar el TOTP.")
        return 0
    if args.usuario and user is None:
        print(f"No existe el usuario {args.usuario}", file=sys.stderr)
        return 1
    if args.cmd == "cambiar-password":
        auth.set_password(user.id, _ask_password())
        auth.close_sessions(user.id)
        events.add(actor="cli", kind="auth", summary=f"Contraseña de {user.username} cambiada desde la terminal")
        print("Contraseña cambiada y sesiones cerradas.")
    elif args.cmd == "reiniciar-totp":
        auth.reset_totp(user.id)
        events.add(actor="cli", kind="auth", summary=f"TOTP de {user.username} reiniciado desde la terminal")
        print("TOTP reiniciado: se configurará de nuevo en el próximo inicio de sesión.")
    elif args.cmd == "cerrar-sesiones":
        n = auth.close_sessions(user.id if user else None)
        events.add(actor="cli", kind="auth", summary=f"{n} sesiones cerradas desde la terminal")
        print(f"{n} sesiones cerradas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
