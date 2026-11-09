"""Settings → Operation: language of history and alerts."""

from app import i18n


def test_notify_language_setting(client):
    state = client.app.state.mc
    page = client.get("/ajustes/operacion").text
    assert "Idioma del historial y los avisos" in page and 'action="/ajustes/operacion/idioma"' in page

    r = client.post("/ajustes/operacion/idioma", data={"lang": "en"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("#idioma")
    assert state.events.get_value("notify_lang") == "en" and i18n.notify_lang() == "en"
    assert state.events.list(limit=1)[0].summary == "Language of history and alerts: English"
    # the panel itself stays in the request language (Spanish here)
    assert "Idioma del historial y los avisos guardado: English" in client.get(r.headers["location"]).text

    # a new event written by any route follows the setting
    client.post("/ajustes/operacion/automatico", data={"enabled": "0"})
    assert state.events.list(limit=1)[0].summary == "Automatic CDN switching disabled for all domains"
    page = client.get("/ajustes/operacion").text
    assert '<option value="en" lang="en" selected>' in page

    client.post("/ajustes/operacion/idioma", data={"lang": "es"})
    assert state.events.get_value("notify_lang") == "es" and i18n.notify_lang() == "es"
    assert state.events.list(limit=1)[0].summary == "Idioma del historial y los avisos: Español"
    client.post("/ajustes/operacion/automatico", data={"enabled": "1"})
    assert state.events.list(limit=1)[0].summary == "Cambio automático de CDN activado"


def test_notify_language_rejects_unknown(client):
    r = client.post("/ajustes/operacion/idioma", data={"lang": "fr"}, follow_redirects=True)
    assert "Idioma no disponible" in r.text
    assert client.app.state.mc.events.get_value("notify_lang") != "fr"


def test_settings_pages_in_english(client):
    client.cookies.set("lang", "en")
    for url, text in (("/ajustes/cuentas", "Provider accounts"), ("/ajustes/notificaciones", "Alert if the panel stops working"),
                      ("/ajustes/servidores", "Origin servers"), ("/ajustes/operacion", "Language of history and alerts"),
                      ("/ajustes/cuenta", "Active sessions")):
        assert text in client.get(url).text, url
