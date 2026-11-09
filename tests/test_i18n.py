"""Languages: choice per request, catalog coverage and placeholders."""

import ast
import json
import string
from pathlib import Path

from jinja2 import Environment, nodes

from app import i18n

APP = Path(__file__).resolve().parent.parent / "app"
PY_FUNCS = {"tr": 1, "tn": 1, "tr_markup": 1, "trn": 2, "tnn": 2, "N_": 1}
TPL_FUNCS = {"_": 1, "_m": 1, "_n": 2}


def _python_strings():
    for f in APP.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in PY_FUNCS:
                # tr(variable) is fine when the literal was marked with N_() where it is defined.
                args = [a for a in node.args[:PY_FUNCS[node.func.id]]
                        if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                yield from ((f"{f.name}:{node.lineno}", a.value) for a in args)


def _template_strings():
    env = Environment()
    for f in (APP / "web" / "templates").glob("*.html"):
        tree = env.parse(f.read_text(encoding="utf-8"))
        for call in tree.find_all(nodes.Call):
            if isinstance(call.node, nodes.Name) and call.node.name in TPL_FUNCS:
                args = [a for a in call.args[:TPL_FUNCS[call.node.name]]
                        if isinstance(a, nodes.Const) and isinstance(a.value, str)]
                yield from ((f"{f.name}:{call.lineno}", a.value) for a in args)


def _fields(text):
    return {name for _lit, name, _spec, _conv in string.Formatter().parse(text) if name is not None}


def test_every_string_has_a_spanish_translation():
    es = i18n.catalogs()["es"]
    missing = sorted({f"{where}: {s!r}" for where, s in [*_python_strings(), *_template_strings()] if s not in es})
    assert not missing, "missing in app/locale/es:\n" + "\n".join(missing)


def test_translations_keep_the_placeholders():
    wrong = [k for k, v in i18n.catalogs()["es"].items() if _fields(k) != _fields(v)]
    assert not wrong, wrong


def test_no_unused_translations():
    used = {s for _w, s in [*_python_strings(), *_template_strings()]}
    assert not set(i18n.catalogs()["es"]) - used, sorted(set(i18n.catalogs()["es"]) - used)[:20]


def test_catalog_files_agree():
    seen, clashes = {}, []
    for f in sorted((i18n.LOCALE_DIR / "es").glob("*.json")):
        for k, v in json.loads(f.read_text(encoding="utf-8")).items():
            if k in seen and seen[k][1] != v:
                clashes.append(f"{k!r}: {seen[k][0]}={seen[k][1]!r} vs {f.name}={v!r}")
            seen[k] = (f.name, v)
    assert not clashes, clashes


def test_language_choice(monkeypatch):
    monkeypatch.delenv("MULTICDN_LANG", raising=False)
    assert i18n.pick(None, None) == "en"
    assert i18n.pick(None, "es-ES,es;q=0.9,en;q=0.8") == "es"
    assert i18n.pick(None, "fr-FR,en;q=0.5,es;q=0.9") == "es"
    assert i18n.pick(None, "de-DE,fr;q=0.8") == "en"
    assert i18n.pick("en", "es-ES") == "en"            # the selector wins over the browser
    assert i18n.pick("xx", "es") == "es"
    monkeypatch.setenv("MULTICDN_LANG", "es")
    assert i18n.pick(None, None) == "es"


def test_selector_sets_cookie_and_page_follows(anon):
    r = anon.get("/lang/es?next=/login", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "lang=es" in r.headers["set-cookie"]
    assert anon.get("/lang/es?next=//evil.example", follow_redirects=False).headers["location"] == "/"
    anon.cookies.set("lang", "en")
    assert '<html lang="en">' in anon.get("/login").text
    anon.cookies.set("lang", "es")
    assert '<html lang="es">' in anon.get("/login").text


def test_getting_started_checklist(client):
    client.cookies.set("lang", "en")
    page = client.get("/").text
    assert "Getting started" in page and "Connect Cloudflare" in page and "Go live" in page
    assert '<a href="/ajustes/cuentas"><strong>Connect Cloudflare</strong></a>' in page
    client.cookies.set("lang", "es")
    assert "Primeros pasos" in client.get("/").text
