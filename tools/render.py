# -*- coding: utf-8 -*-
"""Renderiza los diagramas del modelo Threat Dragon a SVG (mismas coordenadas del JSON)."""
import json, math, sys, html

def esc(s): return html.escape(s, quote=True)

def clip(cell, tx, ty):
    x, y = cell["position"]["x"], cell["position"]["y"]
    w, h = cell["size"]["width"], cell["size"]["height"]
    cx, cy = x + w / 2, y + h / 2
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0: return cx, cy
    if cell["shape"] == "process":
        r = min(w, h) / 2; d = math.hypot(dx, dy)
        return cx + dx / d * r, cy + dy / d * r
    sx = (w / 2) / abs(dx) if dx else 1e9
    sy = (h / 2) / abs(dy) if dy else 1e9
    s = min(sx, sy)
    return cx + dx * s, cy + dy * s

def center(cell):
    return (cell["position"]["x"] + cell["size"]["width"] / 2, cell["position"]["y"] + cell["size"]["height"] / 2)

def text_block(cx, cy, text, size=12, weight="normal", color="#222", anchor="middle", lh=1.25):
    lines = text.split("\n")
    y0 = cy - (len(lines) - 1) * size * lh / 2
    out = []
    for i, ln in enumerate(lines):
        out.append(f'<text x="{cx:.1f}" y="{y0 + i * size * lh:.1f}" font-size="{size}" font-weight="{weight}" '
                   f'fill="{color}" text-anchor="{anchor}" dominant-baseline="middle">{esc(ln)}</text>')
    return "\n".join(out)

def render(diagram, title=None, pad=20, labelpos=None):
    labelpos = labelpos or {}
    cells = diagram["cells"]
    by_id = {c["id"]: c for c in cells}
    xs, ys = [], []
    for c in cells:
        if "position" in c:
            xs += [c["position"]["x"], c["position"]["x"] + c["size"]["width"]]
            ys += [c["position"]["y"], c["position"]["y"] + c["size"]["height"]]
        for v in c.get("vertices", []):
            xs.append(v["x"]); ys.append(v["y"])
    minx, miny = min(xs) - pad, min(ys) - pad - (30 if title else 0)
    W, H = max(xs) - minx + pad, max(ys) - miny + pad
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{minx} {miny} {W} {H}" width="{W*1.6:.0f}" height="{H*1.6:.0f}" font-family="Helvetica, Arial, sans-serif">',
         '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
         '<path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker>'
         '<marker id="arrK" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#333"/></marker>'
         '<marker id="arrR" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#d22"/></marker></defs>',
         f'<rect x="{minx}" y="{miny}" width="{W}" height="{H}" fill="#fff"/>']
    if title:
        o.append(f'<text x="{minx + pad}" y="{miny + 22}" font-size="16" font-weight="bold" fill="#111">{esc(title)}</text>')
    # boundaries
    for c in cells:
        if c["shape"] == "trust-boundary-box":
            x, y, w, h = c["position"]["x"], c["position"]["y"], c["size"]["width"], c["size"]["height"]
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fdf6f6" stroke="#c0392b" stroke-width="1.5" stroke-dasharray="8 5" rx="4"/>')
            o.append(f'<text x="{x + 6}" y="{y + 13}" font-size="10.5" font-weight="bold" fill="#c0392b">{esc(c["attrs"]["label"]["text"])}</text>')
    labels = []
    # flows
    for c in cells:
        if c["shape"] != "flow": continue
        s, t = by_id[c["source"]["cell"]], by_id[c["target"]["cell"]]
        verts = [(v["x"], v["y"]) for v in c.get("vertices", [])]
        first = verts[0] if verts else center(t)
        last = verts[-1] if verts else center(s)
        p0 = clip(s, *first); p1 = clip(t, *last)
        pts = [p0] + verts + [p1]
        red = c["data"].get("hasOpenThreats")
        col = "#d22" if red else "#333"
        mk = "arrR" if red else "arrK"
        d = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        start = f' marker-start="url(#{mk})"' if c["data"].get("isBidirectional") else ""
        o.append(f'<path d="{d}" fill="none" stroke="{col}" stroke-width="{1.8 if red else 1.3}" stroke-linejoin="round" marker-end="url(#{mk})"{start}/>')
        # label at mid length
        segs = [(pts[i], pts[i + 1]) for i in range(len(pts) - 1)]
        L = sum(math.dist(a, b) for a, b in segs); acc = 0; mid = pts[0]
        for a, b in segs:
            l = math.dist(a, b)
            if acc + l >= L / 2:
                f = (L / 2 - acc) / l if l else 0
                mid = (a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f); break
            acc += l
        lp = labelpos.get(c["id"])
        if lp: mid = lp
        labels.append((mid, c["data"]["name"], red))
    # nodes
    for c in cells:
        if c["shape"] not in ("process", "store", "actor", "td-text-block"): continue
        x, y, w, h = c["position"]["x"], c["position"]["y"], c["size"]["width"], c["size"]["height"]
        name = c["data"]["name"]
        red = c["data"].get("hasOpenThreats")
        col = "#d22" if red else "#333"; sw = 2.5 if red else 1.5
        if c["shape"] == "process":
            o.append(f'<circle cx="{x + w/2}" cy="{y + h/2}" r="{min(w,h)/2}" fill="#fff" stroke="{col}" stroke-width="{sw}"/>')
        elif c["shape"] == "store":
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fff"/>')
            o.append(f'<line x1="{x}" y1="{y}" x2="{x+w}" y2="{y}" stroke="{col}" stroke-width="{sw}"/>')
            o.append(f'<line x1="{x}" y1="{y+h}" x2="{x+w}" y2="{y+h}" stroke="{col}" stroke-width="{sw}"/>')
        elif c["shape"] == "actor":
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fff" stroke="{col}" stroke-width="{sw}"/>')
        o.append(text_block(x + w / 2, y + h / 2, name, size=12, weight="bold" if c["shape"] == "process" else "normal"))
    for (mx, my), name, red in labels:
        lines = name.split("\n"); fs = 9.5
        wmax = max(len(l) for l in lines) * fs * 0.52 + 6; hh = len(lines) * fs * 1.25 + 4
        o.append(f'<rect x="{mx - wmax/2:.1f}" y="{my - hh/2:.1f}" width="{wmax:.1f}" height="{hh:.1f}" rx="3" fill="#fff" fill-opacity="0.93" stroke="{"#f2b8b8" if red else "#ddd"}" stroke-width="0.6"/>')
        o.append(text_block(mx, my, name, size=fs, color="#7a1010" if red else "#222"))
    o.append("</svg>")
    return "\n".join(o)

if __name__ == "__main__":
    m = json.load(open(sys.argv[1], encoding="utf-8"))
    outdir = sys.argv[2]
    import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dfd import LABEL_POS, uid
    for i, d in enumerate(m["detail"]["diagrams"]):
        lp = {uid("L1", k): v for k, v in LABEL_POS.items()} if i == 1 else {}
        svg = render(d, d["title"], labelpos=lp)
        with open(f"{outdir}/dfd_nivel{i}.svg", "w", encoding="utf-8") as f:
            f.write(svg)
        import re
        w, h = re.search(r'width="(\d+)" height="(\d+)"', svg).groups()
        print(i, w, h)
    print("ok")
