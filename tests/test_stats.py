"""Estadísticas reconstruidas del historial del feed y de los cambios DNS registrados."""

from datetime import UTC, datetime, timedelta

from app import stats
from app.signals.hayahora import parse_feed

T = datetime(2026, 11, 1, tzinfo=UTC)


def ts(hours):
    return (T + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%SZ")


def feed_with(entries):
    """entries: (ip, isp, [(horas, bloqueada)])"""
    return parse_feed({"lastUpdate": ts(48), "data": [
        {"ip": ip, "isp": isp, "description": "Cloudflare",
         "stateChanges": [{"timestamp": ts(h), "state": b} for h, b in changes]} for ip, isp, changes in entries]})


def test_mass_series_counts_ips_blocked_in_three_isps():
    entries = [("1.1.1.1", isp, [(2, True), (5, False)]) for isp in ("Movistar", "Vodafone", "Orange")]
    entries += [("2.2.2.2", isp, [(3, True)]) for isp in ("Movistar", "Vodafone")]  # solo 2 operadoras
    series = stats.mass_series(feed_with(entries), T, T + timedelta(hours=8), timedelta(hours=1))
    assert [v for _, v in series] == [0, 0, 1, 1, 1, 0, 0, 0]


def test_block_intervals_merge_isps_and_keep_open_ones():
    f = feed_with([("1.1.1.1", "Movistar", [(2, True), (6, False)]),
                   ("1.1.1.1", "Orange", [(4, True), (8, False)]),
                   ("1.1.1.2", "DIGI", [(20, True)])])
    ivs = stats.block_intervals(f, ["1.1.1.1", "1.1.1.2"], T, T + timedelta(hours=48))
    assert [(iv.start.hour, iv.end and iv.end.hour, iv.max_isps) for iv in ivs] == [(2, 8, 2), (20, None, 1)]
    assert ivs[0].isps == {"Movistar", "Orange"}


class E:
    def __init__(self, hours, diff, simulated=False):
        self.ts, self.kind, self.dns_diff, self.simulated = T + timedelta(hours=hours), "switch", diff, simulated


def test_cdn_segments_follow_each_failover_host():
    to_gcore = [["www.x.com", "Cloudflare proxied", "CNAME → cl-a.gcorecdn.com · TTL 60"],
                ["x.com", "Cloudflare proxied", "CNAME → cl-a.gcorecdn.com · TTL 60"]]
    www_back = [["www.x.com", "CNAME → Gcore", "Cloudflare proxied → x.com"]]  # el www no conmuta: no cuenta
    events = [E(2, to_gcore), E(3, www_back), E(4, [["x.com", "CNAME → Gcore", "Cloudflare proxied"]], simulated=True)]
    segs = stats.cdn_segments(events, ["x.com"], {"x.com": "gcore"}, T, T + timedelta(hours=6))
    assert [(g.start.hour, g.end.hour, g.kind) for g in segs] == [(0, 2, "cloudflare"), (2, 6, "gcore")]


def test_fmt_duration():
    assert stats.fmt_duration(timedelta(minutes=45)) == "45 min"
    assert stats.fmt_duration(timedelta(hours=5, minutes=5)) == "5 h 05 min"
    assert stats.fmt_duration(timedelta(hours=60)) == "2 d 12 h"


def test_page_renders_charts_tables_and_periods(client):
    state = client.app.state.mc
    now = datetime.now(UTC)
    h = lambda d: (now - d).strftime("%Y-%m-%d %H:%M:%SZ")
    state.feed = parse_feed({"lastUpdate": h(timedelta(0)), "data": [
        {"ip": "188.114.96.5", "isp": isp, "description": "Cloudflare",
         "stateChanges": [{"timestamp": h(timedelta(hours=30)), "state": True},
                          {"timestamp": h(timedelta(hours=26)), "state": False}]}
        for isp in ("Movistar", "Vodafone", "Orange")]})
    state.engine.remember_ips("example.com", ["188.114.96.5"])
    state.events.add(actor="auto", kind="switch", domain="example.com", transition="CF → GCORE", summary="x",
                     dns_diff=[[h, "Cloudflare proxied", "CNAME → cl-a.gcorecdn.com · TTL 60"]
                               for h in ("example.com", "www.example.com")])
    state.events.add(actor="admin", kind="switch", domain="example.com", transition="GCORE → CF", summary="solo un hostname que no conmuta",
                     dns_diff=[["other.example.com", "CNAME → Gcore", "Cloudflare proxied"]])
    page = client.get("/estadisticas?dias=30").text
    assert 'aria-current="page">30 días' in page and "IPs de Cloudflare bloqueadas" in page
    assert page.count('class="c-hit"') == 360 and "c-seg--gcore" in page and "c-seg--blocked" in page
    assert "Episodios de bloqueo" in page and "3 de 5" in page and "Ver datos" in page
    assert "1 cambios reales: 1 automáticos" in page
    assert client.get("/estadisticas?dias=999").status_code == 200  # periodo no válido: 7 días


def test_page_without_feed_shows_empty_states(client):
    page = client.get("/estadisticas").text
    assert "feed de bloqueos aún sin leer" in page and "Sin episodios" in page


def test_kind_matches_exact_labels_in_both_languages():
    assert stats._kind("A → origin IP (not proxied)") == "origin"  # contiene «proxied» pero no es Cloudflare
    assert stats._kind("A → IP de origen (sin proxy)") == "origin"
    assert stats._kind("Cloudflare proxied") == "cloudflare"
    assert stats._kind("CNAME → Gcore") == "gcore"
    assert stats._kind("CNAME → cl-a.gcorecdn.com · TTL 60") == "gcore"
    assert stats._kind("otro destino") == "other" and stats._kind("other target") == "other"
    assert stats._kind("sin resolver") == "unresolved" and stats._kind("unresolved") == "unresolved"
    assert stats._kind("desconocido") is None and stats._kind("unknown") is None


def test_cdn_segments_map_other_kinds_to_unknown():
    to_cf = [["x.com", "A → IP de origen (sin proxy)", "Cloudflare proxied"]]
    to_gcore = [["x.com", "Cloudflare proxied", "CNAME → cl-a.gcorecdn.com · TTL 60"]]
    segs = stats.cdn_segments([E(2, to_cf), E(4, to_gcore)], ["x.com"], {"x.com": "gcore"}, T, T + timedelta(hours=6))
    assert [(g.start.hour, g.end.hour, g.kind) for g in segs] == [(0, 2, "unknown"), (2, 4, "cloudflare"), (4, 6, "gcore")]
    for provider in ("unresolved", "other", "origin"):  # sin cambios: el estado actual
        segs = stats.cdn_segments([], ["x.com"], {"x.com": provider}, T, T + timedelta(hours=6))
        assert [g.kind for g in segs] == ["unknown"]


def test_page_survives_hostnames_without_cdn(client):
    state = client.app.state.mc
    from app.signals.dnscheck import Resolution
    state.resolutions = {h: Resolution(h, (), None, "unresolved") for h in ("example.com", "www.example.com")}
    assert client.get("/estadisticas").status_code == 200  # antes: KeyError en CDN_LABEL
    state.events.add(actor="admin", kind="switch", domain="example.com", transition="GCORE → CF", summary="x",
                     dns_diff=[[h, "A → origin IP (not proxied)", "Cloudflare proxied"]
                               for h in ("example.com", "www.example.com")])
    assert client.get("/estadisticas").status_code == 200
