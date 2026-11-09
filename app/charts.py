"""Geometría de las gráficas (SVG dibujado en el servidor; sin librerías ni scripts externos).

Specs: líneas de 2 px, área al 10 %, columnas ≤ 24 px con extremo redondeado de 4 px y
base recta, 2 px de hueco entre marcas que se tocan, rejilla de 1 px recesiva.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

from .i18n import N_, tr

W = 960
LEFT, RIGHT, TOP, BOTTOM = 52, 12, 14, 30
DAYS = [N_("Mon"), N_("Tue"), N_("Wed"), N_("Thu"), N_("Fri"), N_("Sat"), N_("Sun")]


def nice_max(value: float, ticks: int = 4) -> tuple[float, float]:
    """Máximo del eje y paso, redondeados a 1-2-5 × 10^k."""
    if value <= 0:
        return 1.0, 0.25
    raw = value / ticks
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    return step * math.ceil(value / step), step


def fmt_num(v: float) -> str:
    if v >= 10_000:
        return f"{v / 1000:.0f} K"
    return f"{v:,.0f}".replace(",", ".")


class Scale:
    def __init__(self, start: datetime, end: datetime, height: int):
        self.start, self.end, self.height = start, end, height
        self.plot_w = W - LEFT - RIGHT
        self.plot_h = height - TOP - BOTTOM

    def x(self, t: datetime) -> float:
        frac = (t - self.start) / (self.end - self.start)
        return round(LEFT + max(0.0, min(1.0, frac)) * self.plot_w, 1)

    def day_ticks(self) -> list[dict]:
        days = (self.end - self.start).days
        every = 1 if days <= 7 else (5 if days <= 30 else 10)
        first = (self.start + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        out, t, i = [], first, 0
        while t < self.end:
            if i % every == 0:
                label = f"{tr(DAYS[t.weekday()])} {t.day}" if days <= 7 else f"{t.day}/{t.month}"
                out.append({"x": self.x(t), "label": label})
            t += timedelta(days=1)
            i += 1
        return out


def line_chart(points: list[tuple[datetime, int]], start: datetime, end: datetime, step: timedelta,
               bands: list[tuple[datetime, datetime, str]], height: int = 240) -> dict:
    sc = Scale(start, end, height)
    top, ystep = nice_max(max((v for _, v in points), default=0))
    base = TOP + sc.plot_h

    def y(v: float) -> float:
        return round(base - (v / top) * sc.plot_h, 1)

    coords = [(sc.x(t + step / 2), y(v)) for t, v in points]
    line = "M" + " L".join(f"{x},{yy}" for x, yy in coords) if coords else ""
    area = f"{line} L{coords[-1][0]},{base} L{coords[0][0]},{base} Z" if coords else ""
    hits = []
    for t, v in points:
        x0, x1 = sc.x(t), sc.x(t + step)
        match = next((label for b0, b1, label in bands if b0 < t + step and b1 > t), None)
        tip = f"{t:%d/%m %H:%M}–{t + step:%H:%M} UTC · {fmt_num(v)} IPs" + (f" · {match}" if match else "")
        hits.append({"x": x0, "w": max(1.0, round(x1 - x0, 1)), "cx": sc.x(t + step / 2), "cy": y(v), "tip": tip})
    peak = max(points, key=lambda p: p[1]) if points else None
    return {
        "height": height, "base": base, "line": line, "area": area, "hits": hits,
        "yticks": [{"y": y(v), "label": fmt_num(v)} for v in _frange(0, top, ystep)],
        "xticks": sc.day_ticks(),
        "bands": [{"x": sc.x(b0), "w": max(2.0, round(sc.x(b1) - sc.x(b0), 1)), "tip": label}
                  for b0, b1, label in bands if b1 > start and b0 < end],
        "peak": {"x": sc.x(peak[0] + step / 2), "y": y(peak[1]), "label": fmt_num(peak[1])} if peak and peak[1] else None,
        "left": LEFT, "right": W - RIGHT, "width": W,
    }


def _frange(a: float, b: float, step: float):
    v = a
    while v <= b + step / 1000:
        yield v
        v += step


def timeline(rows: list[dict], start: datetime, end: datetime) -> dict:
    """rows: {name, segments [(t0, t1, kind, tip)], blocks [(t0, t1, tip)]}. Una fila por dominio:
    carril «servido por» (14 px) y carril «IPs bloqueadas» (8 px)."""
    row_h = 58
    height = TOP + row_h * len(rows) + BOTTOM
    sc = Scale(start, end, height)
    out = []
    for i, r in enumerate(rows):
        y0 = TOP + i * row_h
        segs = []
        for j, (t0, t1, kind, tip) in enumerate(r["segments"]):
            x0, x1 = sc.x(t0), sc.x(t1)
            if j > 0:
                x0 += 1  # 2 px de hueco entre tramos que se tocan
            if j < len(r["segments"]) - 1:
                x1 -= 1
            segs.append({"x": x0, "w": max(1.0, round(x1 - x0, 1)), "kind": kind, "tip": tip})
        blocks = [{"x": sc.x(t0), "w": max(2.0, round(sc.x(t1) - sc.x(t0), 1)), "tip": tip} for t0, t1, tip in r["blocks"]]
        out.append({"name": r["name"], "label_y": y0 + 12, "cdn_y": y0 + 20, "block_y": y0 + 38, "segments": segs,
                    "blocks": blocks})
    return {"height": height, "rows": out, "xticks": sc.day_ticks(), "base": height - BOTTOM,
            "left": LEFT, "right": W - RIGHT, "width": W}


def _rounded_top(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    r = min(r, w / 2, h)
    return (f"M{x},{y + h} L{x},{y + r} Q{x},{y} {x + r},{y} L{x + w - r},{y} "
            f"Q{x + w},{y} {x + w},{y + r} L{x + w},{y + h} Z")


def columns(days: list[datetime], series: list[dict], start: datetime, end: datetime, height: int = 220,
            fmt=str) -> dict:
    """Columnas apiladas por día. series: {name, slot, values [bytes por día]} en orden fijo."""
    sc = Scale(start, end, height)
    totals = [sum(s["values"][i] for s in series) for i in range(len(days))]
    top, ystep = nice_max(max(totals, default=0))
    base = TOP + sc.plot_h
    slot = sc.plot_w / max(1, len(days))
    bar_w = round(min(24.0, slot * 0.7), 1)
    bars = []
    for i, day in enumerate(days):
        cx = sc.x(day + timedelta(hours=12))
        y_cursor = base
        stacked = [(s, s["values"][i]) for s in series if s["values"][i] > 0]
        for k, (s, v) in enumerate(stacked):
            gap = 2 if k > 0 else 0  # hueco de superficie entre segmentos apilados
            h = max(2.0, v / top * sc.plot_h)  # un valor pequeño sigue siendo visible
            y_top = y_cursor - h - gap
            last = k == len(stacked) - 1
            x = round(cx - bar_w / 2, 1)
            bars.append({"x": x, "y": round(y_top, 1), "w": bar_w, "h": round(h, 1),
                         "path": _rounded_top(x, round(y_top, 1), bar_w, round(h, 1)) if last else None,
                         "slot": s["slot"], "tip": f"{day:%d/%m} · {s['name']}: {fmt(v)}"})
            y_cursor = y_top
    return {"height": height, "base": base, "bars": bars,
            "yticks": [{"y": round(base - v / top * sc.plot_h, 1), "label": fmt(int(v))} for v in _frange(0, top, ystep)],
            "xticks": sc.day_ticks(), "left": LEFT, "right": W - RIGHT, "width": W}
