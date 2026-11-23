"""Emergency sheet: the manual switch in the Cloudflare dashboard, without the origin IP."""

from datetime import UTC, datetime

from app import cli
from app.emergency import sheet
from app.i18n import tn

ORIGIN = "192.0.2.10"


def prepared(state):
    """example.com prepared on Gcore, its www kept on Cloudflare; example.net not prepared."""
    state.store.set_gcore("example.com", 33, 22, datetime(2027, 2, 1, tzinfo=UTC).isoformat(), "cl-test.gcorecdn.com",
                          ["example.com", "www.example.com"])
    state.store.set_failover("www.example.com", False)
    state.reload()


def test_sheet_says_what_to_change_and_never_shows_the_origin_ip(make_client):
    client = make_client(ORIGIN_VPS1_IPV4=ORIGIN)
    state = client.app.state.mc
    prepared(state)
    text = sheet(state.inventory, tn)
    assert ORIGIN not in text
    assert "CNAME example.com → cl-test.gcorecdn.com, solo DNS (nube gris), TTL 1 min" in text
    assert "curl -sI --connect-to example.com:443:cl-test.gcorecdn.com:443 https://example.com/" in text
    assert "A example.com → tu IP de origen (en tu gestor de contraseñas, nunca aquí), con proxy" in text
    assert "No tocar (se quedan siempre en Cloudflare): www.example.com" in text
    assert "CNAME www.example.com" not in text  # it does not switch: no instructions for it
    example_net = text.split("== example.net")[1]
    assert "No está preparado en Gcore" in example_net


def test_sheet_restores_tunnels_and_cnames_to_their_targets(client):
    state = client.app.state.mc
    prepared(state)
    state.store.set_failover("www.example.com", True)
    state.store.set_cloudflare_record("www.example.com", "rec-www", "cname", None, "example.com")
    state.reload()
    text = sheet(state.inventory, tn)
    assert "CNAME www.example.com → example.com, con proxy (nube naranja)" in text


def test_panel_and_terminal_give_the_same_sheet(make_client, capsys):
    client = make_client(ORIGIN_VPS1_IPV4=ORIGIN)
    prepared(client.app.state.mc)
    r = client.get("/ajustes/ficha-emergencia.txt")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "Ficha de emergencia" in r.text and ORIGIN not in r.text
    assert "/ajustes/ficha-emergencia.txt" in client.get("/ajustes/sistema").text
    assert cli.main(["emergency-sheet"]) == 0
    out = capsys.readouterr().out
    assert "cl-test.gcorecdn.com" in out and ORIGIN not in out
    assert out.split("\n", 1)[1] == r.text.split("\n", 1)[1]  # same content after the dated first line
