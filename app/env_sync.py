"""Startup import of the panel's secrets file (config/secrets.env) into the encrypted database.

The database is the only source the panel reads secrets from. At every start (panel, CLI and
runbook, and error reporting before the app exists) the secrets file has priority: each managed
value that differs from the stored one is imported and leaves a history entry, never with the
value. Precedence and the other routes into the environment: see envfile. Changes made in the
panel are written back to the file (envfile.write_back), so both stay equal.
"""

from __future__ import annotations

import logging

from . import envfile
from .credentials import ENV_LABEL, ENV_TOKENS, PROVIDERS, CredentialStore
from .db import EventStore
from .i18n import N_, set_notify, tn
from .secrets_store import CREDENTIALS, SecretStore

log = logging.getLogger("multicdn")
PROVIDER_TOKEN = N_("{provider} token")
FROM_FILE = N_("{label} updated from config/secrets.env")
FROM_ENV = N_("{label} updated from the environment")


def load_notify_lang(events: EventStore) -> None:
    """Language of history and alerts. Installs from before it existed wrote in Spanish: they
    keep Spanish until changed in Settings → Notifications."""
    lang = events.get_value("notify_lang")
    if lang is None and events.conn.execute("SELECT 1 FROM events LIMIT 1").fetchone():
        lang = "es"
        events.set_value("notify_lang", lang)
    set_notify(lang)


def sync(secrets: SecretStore, events: EventStore, creds: CredentialStore | None = None) -> list[str]:
    """Imports what changed; returns the labels imported (in the notification language)."""
    view = envfile.load()
    source = envfile.import_source(secrets)
    if source is None:
        return []  # the secrets file is configured but unreadable: the database wins
    creds = creds or CredentialStore(secrets)
    imported = [(CREDENTIALS[name][0], CREDENTIALS[name][1], {}) for name in secrets.import_env(source)]
    imported += [(PROVIDER_TOKEN, ENV_TOKENS[p], {"provider": PROVIDERS[p]})
                 for p in creds.import_env(tn(ENV_LABEL), source)]
    labels = []
    for label, env, args in imported:
        text = tn(label, **args)
        from_file = view.configured and env in view.values
        events.add(actor="auto", kind="config", summary=tn(FROM_FILE if from_file else FROM_ENV, label=text))
        log.info("secrets: %s imported from %s", env, envfile.DISPLAY if from_file else "the environment")
        labels.append(text)
    return labels
