"""Server-side commands: panel users, origin secrets, backups and switching without the panel.

Usage (the Spanish names of 0.1.0 still work as aliases):
  python -m app.cli create-user <user>
  python -m app.cli change-password <user>
  python -m app.cli reset-totp <user>
  python -m app.cli close-sessions [<user>]
  python -m app.cli list-users
  python -m app.cli origin-secrets [--caddy|--show]     (X-Origin-Auth fingerprints, Caddy file)
  python -m app.cli rotate-origin-secret cloudflare|gcore
  python -m app.cli retire-previous-secret cloudflare|gcore
  python -m app.cli backup [<file>]
  python -m app.cli status                              (where each domain is served)
  python -m app.cli switch <domain> gcore|cloudflare [--yes] [--force]
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from .auth import PASSWORD_MIN, AuthStore
from .config import load_dotenv
from .db import EventStore
from .i18n import tn, tnn
from .secrets_store import SecretStore


def _store() -> tuple[AuthStore, EventStore]:
    load_dotenv()
    db = os.environ.get("MULTICDN_DB", "data/multicdn.db")
    events = EventStore(db)
    _speak_notify_lang(events)
    return AuthStore(SecretStore(db)), events


def _speak_notify_lang(events: EventStore | None = None) -> None:
    """The terminal speaks the notification language (Settings → Operation)."""
    from . import i18n
    if events is not None:
        from .main import load_notify_lang
        load_notify_lang(events)
    i18n.set_ui(i18n.notify_lang())


def _ask_password() -> str:
    while True:
        first = getpass.getpass(tn("New password (at least {min} characters): ", min=PASSWORD_MIN))
        if len(first) < PASSWORD_MIN:
            print(tn("Too short."))
            continue
        if getpass.getpass(tn("Repeat the password: ")) != first:
            print(tn("They do not match."))
            continue
        return first


# English name -> Spanish aliases (the Spanish names were the original ones and keep working).
COMMANDS = {
    "create-user": ["crear-usuario"],
    "change-password": ["cambiar-password"],
    "reset-totp": ["reiniciar-totp"],
    "close-sessions": ["cerrar-sesiones"],
    "list-users": ["listar-usuarios"],
    "origin-secrets": ["secretos-origen"],
    "rotate-origin-secret": ["rotar-secreto-origen"],
    "retire-previous-secret": ["retirar-secreto-anterior"],
    "backup": ["copia-seguridad"],
    "status": ["estado"],
    "switch": ["cambiar"],
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Multi-CDN panel from the terminal")
    sub = parser.add_subparsers(dest="typed", required=True, metavar="command")

    def add(name: str, help_: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, aliases=COMMANDS[name], help=help_)
        p.set_defaults(cmd=name)
        return p

    add("create-user", "create a panel user (asks for the password)").add_argument("user")
    add("change-password", "change a user's password and close their sessions").add_argument("user")
    add("reset-totp", "reset a user's TOTP (set up again at next sign-in)").add_argument("user")
    add("close-sessions", "close the sessions of one user, or of everyone").add_argument("user", nargs="?")
    add("list-users", "list the panel users")
    so = add("origin-secrets", "fingerprints of the X-Origin-Auth secrets")
    so.add_argument("--caddy", action="store_true", help="print the file (origin_auth) for Caddy, with the values")
    so.add_argument("--show", "--mostrar", dest="show", action="store_true",
                    help="show the values (to configure a CDN by hand)")
    add("rotate-origin-secret", "new origin secret for a CDN (the previous one stays accepted)").add_argument(
        "cdn", choices=["cloudflare", "gcore"])
    add("retire-previous-secret", "stop accepting a CDN's previous origin secret").add_argument(
        "cdn", choices=["cloudflare", "gcore"])
    add("backup", "back up the database").add_argument("destination", nargs="?")
    add("status", "where each domain is being served")
    sw = add("switch", "switch a domain's CDN without the panel")
    sw.add_argument("domain")
    sw.add_argument("target", choices=["gcore", "cloudflare"])
    sw.add_argument("--yes", "--si", dest="yes", action="store_true", help="do not ask for confirmation")
    sw.add_argument("--force", "--forzar", dest="force", action="store_true",
                    help="move to Gcore even if the pre-check fails")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd in ("status", "switch"):
        from . import runbook
        if args.cmd == "status":
            return runbook.run(runbook.status())
        return runbook.run(runbook.switch(args.domain, args.target, assume_yes=args.yes, force=args.force))
    if args.cmd == "backup":
        from pathlib import Path

        from .backup import backup
        load_dotenv()
        _speak_notify_lang()
        print(tn("Backup saved to {path}", path=backup(Path(args.destination) if args.destination else None)))
        return 0
    auth, events = _store()

    if args.cmd in ("origin-secrets", "rotate-origin-secret", "retire-previous-secret"):
        from .gcore_setup import (caddy_origin_snippet, fingerprint, origin_secret, retire_previous_secret,
                                  rotate_origin_secret)
        secrets = SecretStore(os.environ.get("MULTICDN_DB", "data/multicdn.db"))
        if args.cmd == "rotate-origin-secret":
            rotate_origin_secret(secrets, args.cdn)
            events.add(actor="cli", kind="config",
                       summary=tn("Origin secret for {cdn} rotated (the previous one is still accepted)", cdn=args.cdn))
            print(tn("New secret for {cdn}. Now: regenerate the Caddy file (--caddy) and reload it,", cdn=args.cdn))
            print(tn("apply the secret on that CDN (panel: «Apply on Cloudflare» or «Update on Gcore») and, when"))
            print(tn("all its domains are up to date, retire the previous one: retire-previous-secret {cdn}",
                     cdn=args.cdn))
            return 0
        if args.cmd == "retire-previous-secret":
            done = retire_previous_secret(secrets, args.cdn)
            if done:
                events.add(actor="cli", kind="config", summary=tn("Previous origin secret for {cdn} retired", cdn=args.cdn))
            print(tn("Retired: regenerate the Caddy file (--caddy) and reload it.") if done
                  else tn("There was no previous secret."))
            return 0
        if args.caddy:
            print(caddy_origin_snippet(secrets), end="")
            return 0
        for cdn in ("cloudflare", "gcore"):
            value = origin_secret(secrets, cdn)
            prev = secrets.get(f"origin_auth:{cdn}:anterior")
            line = tn("{cdn} fingerprint {fingerprint}", cdn=f"{cdn:10}", fingerprint=fingerprint(value))
            if prev:
                line += tn(" · previous {fingerprint} still accepted", fingerprint=fingerprint(prev))
            if args.show:
                line += tn(" · value {value}", value=value)
            print(line)
        if not args.show:
            print(tn("Values are not shown. File for Caddy: "
                     "origin-secrets --caddy | sudo tee /etc/caddy/origin-auth.caddy"))
        return 0

    if args.cmd == "list-users":
        for u in auth.list_users():
            print(f"{u.username}\t" + (tn("TOTP active") if u.totp_enabled else tn("TOTP pending")))
        return 0

    user = auth.get_user(args.user) if getattr(args, "user", None) else None
    if args.cmd == "create-user":
        auth.create_user(args.user, _ask_password())
        events.add(actor="cli", kind="auth", summary=tn("User {user} created from the terminal", user=args.user.lower()))
        print(tn("User {user} created. When you sign in to the panel you will be asked to set up TOTP.",
                 user=args.user.lower()))
        return 0
    if args.user and user is None:
        print(tn("User {user} does not exist", user=args.user), file=sys.stderr)
        return 1
    if args.cmd == "change-password":
        auth.set_password(user.id, _ask_password())
        auth.close_sessions(user.id)
        events.add(actor="cli", kind="auth", summary=tn("Password of {user} changed from the terminal", user=user.username))
        print(tn("Password changed and sessions closed."))
    elif args.cmd == "reset-totp":
        auth.reset_totp(user.id)
        events.add(actor="cli", kind="auth", summary=tn("TOTP of {user} reset from the terminal", user=user.username))
        print(tn("TOTP reset: it will be set up again at the next sign-in."))
    elif args.cmd == "close-sessions":
        n = auth.close_sessions(user.id if user else None)
        events.add(actor="cli", kind="auth", summary=tnn("{n} session closed from the terminal",
                                                          "{n} sessions closed from the terminal", n))
        print(tnn("{n} session closed.", "{n} sessions closed.", n))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
