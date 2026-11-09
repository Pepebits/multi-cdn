"""Interface and message language (English and Spanish).

Source strings are English; `app/locale/<lang>/*.json` map them to other languages. Two
languages are in play at any moment:

- **UI language** (`tr`): per request, from the `lang` cookie (the selector in the footer),
  else the browser's Accept-Language, else MULTICDN_LANG, else English.
- **Notification language** (`tn`): one global setting (Settings → Operation) for what is
  stored or sent: history entries, Telegram/email alerts and terminal output. Stored text
  stays in the language it was written in.

Placeholders use str.format: `tr("Switched {domain}", domain=name)`. Translations must keep
the same placeholders (a test checks it).
"""

from __future__ import annotations

import json
import os
from contextvars import ContextVar
from pathlib import Path

from markupsafe import Markup, escape

LANGS = {"en": "English", "es": "Español"}
LOCALE_DIR = Path(__file__).parent / "locale"
COOKIE = "lang"

_ui: ContextVar[str | None] = ContextVar("ui_lang", default=None)
_notify: str | None = None
_catalogs: dict[str, dict[str, str]] | None = None


def catalogs() -> dict[str, dict[str, str]]:
    global _catalogs
    if _catalogs is None:
        loaded: dict[str, dict[str, str]] = {}
        for lang in LANGS:
            merged: dict[str, str] = {}
            for f in sorted((LOCALE_DIR / lang).glob("*.json")):
                merged |= json.loads(f.read_text(encoding="utf-8"))
            loaded[lang] = merged
        _catalogs = loaded
    return _catalogs


def default_lang() -> str:
    lang = (os.environ.get("MULTICDN_LANG") or "en").lower()
    return lang if lang in LANGS else "en"


def normalize(lang: str | None) -> str | None:
    lang = (lang or "").lower()[:2]
    return lang if lang in LANGS else None


def from_accept_language(header: str | None) -> str | None:
    """First supported language in the browser's preference order (q-values respected)."""
    prefs = []
    for i, part in enumerate((header or "").split(",")):
        tag, _sep, params = part.strip().partition(";")
        q = 1.0
        if params.strip().startswith("q="):
            try:
                q = float(params.strip()[2:])
            except ValueError:
                q = 0.0
        if tag and q > 0:
            prefs.append((-q, i, tag))
    for _q, _i, tag in sorted(prefs):
        if lang := normalize(tag):
            return lang
    return None


def pick(cookie: str | None, accept_language: str | None) -> str:
    return normalize(cookie) or from_accept_language(accept_language) or default_lang()


def set_ui(lang: str) -> None:
    _ui.set(normalize(lang) or default_lang())


def ui_lang() -> str:
    return _ui.get() or default_lang()


def set_notify(lang: str | None) -> None:
    global _notify
    _notify = normalize(lang)


def notify_lang() -> str:
    return _notify or default_lang()


def translate(text: str, lang: str, /, **kw) -> str:
    if lang != "en":
        text = catalogs().get(lang, {}).get(text, text)
    return text.format(**kw) if kw else text


def translate_n(singular: str, plural: str, n: int, lang: str, /, **kw) -> str:
    return translate(singular if n == 1 else plural, lang, n=n, **kw)


def N_(text: str) -> str:
    """Marks a literal for translation without translating it (module-level tables); translate
    it later with tr(value) or tn(value), at use time."""
    return text


def tr(text: str, /, **kw) -> str:
    """Interface text, in the language of the current request."""
    return translate(text, ui_lang(), **kw)


def trn(singular: str, plural: str, n: int, /, **kw) -> str:
    return translate_n(singular, plural, n, ui_lang(), **kw)


def tn(text: str, /, **kw) -> str:
    """Stored or sent text (history, alerts, terminal), in the notification language."""
    return translate(text, notify_lang(), **kw)


def tnn(singular: str, plural: str, n: int, /, **kw) -> str:
    return translate_n(singular, plural, n, notify_lang(), **kw)


def tr_markup(text: str, /, **kw) -> Markup:
    """For a template string that contains trusted markup: the arguments are escaped."""
    return Markup(translate(text, ui_lang())).format(**{k: escape(v) for k, v in kw.items()})


def install(env) -> None:
    """Jinja globals: _(), _n(), _m() and the current language."""
    env.globals.update(_=tr, _n=trn, _m=tr_markup, ui_lang=ui_lang, LANGS=LANGS)
