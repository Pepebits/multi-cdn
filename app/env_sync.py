"""Startup import of the server's .env into the encrypted database (0.3.1).

The database is the only source the panel reads secrets from. At every start (panel, CLI,
and error reporting before the app exists) the .env has priority: each env-backed secret whose
.env value differs from the stored one is imported and leaves a history entry, never with the
value. Changes made in the panel are written back to .env (envfile), so both stay equal.
"""

from __future__ import annotations

import logging

from .credentials import ENV_LABEL, PROVIDERS, CredentialStore
from .db import EventStore
from .i18n import N_, set_notify, tn
from .secrets_store import CREDENTIALS, SecretStore

log = logging.getLogger("multicdn")
PROVIDER_TOKEN = N_("{provider} token")


def load_notify_lang(events: EventStore) -> None:
    """Language of history and alerts. Installs from before it existed wrote in Spanish: they
    keep Spanish until changed in Settings → Notifications."""
    lang = events.get_value("notify_lang")
    if lang is None and events.conn.execute("SELECT 1 FROM events LIMIT 1").fetchone():
        lang = "es"
        events.set_value("notify_lang", lang)
    set_notify(lang)


def sync(secrets: SecretStore, events: EventStore, creds: CredentialStore | None = None) -> list[str]:
    """Imports what changed in .env; returns the labels imported (in the notification language)."""
    from .envfile import refresh_environ
    refresh_environ()  # the .env file as it is now, not the container's environment from creation
    creds = creds or CredentialStore(secrets)
    labels =[tn(CREDENTIALS[name][0]) for name in secrets.import_env()]
    labels += [tn(PROVIDER_TOKEN, provider=PROVIDERS[p]) for p in creds.import_env(tn(ENV_LABEL))]
    for label in labels:
        events.add(actor="auto", kind="config", summary=tn("{label} updated from the server's .env", label=label))
        log.info("secrets: %s imported from .env", label)
    return labels
