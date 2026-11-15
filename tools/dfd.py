# -*- coding: utf-8 -*-
"""Define los DFD (nivel 0 y nivel 1) y genera el modelo Threat Dragon v2."""
import json, uuid
from data import AMENAZAS, riesgo, TITULO

NS = uuid.UUID("6f1c2a52-6b1e-4d1a-9a1e-2b8c0e5d9a10")
def uid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))

# ------------------------------------------------------------------ Nivel 0
L0_NODES = [
    # key, tipo, nombre, x, y, w, h
    ("EVU", "process", "EventosU", 520, 270, 170, 170),
    ("VIS", "actor", "Visitante", 60, 60, 170, 70),
    ("EST", "actor", "Estudiante o público", 60, 220, 170, 70),
    ("ORG", "actor", "Organizador", 60, 380, 170, 70),
    ("ADM", "actor", "Administrador", 60, 540, 170, 70),
    ("PTA", "actor", "Personal de Puerta", 520, 620, 170, 70),
    ("PAS", "actor", "Pasarela de pagos\n(externo)", 960, 90, 190, 70),
    ("ENT", "actor", "Microsoft Entra ID\n(externo)", 960, 320, 190, 70),
    ("COR", "actor", "Servicio de correo\n(externo)", 960, 540, 190, 70),
]
L0_BOUNDS = [
    ("B0", "Límite del sistema EventosU", 440, 200, 330, 330),
]
L0_FLOWS = [
    # key, origen, destino, nombre, protocolo, bidireccional, vertices
    ("G01", "VIS", "EVU", "Consulta del catálogo\n(HTTPS, HTML/JSON)", "HTTPS", False, []),
    ("G02", "EST", "EVU", "Registro, inscripción y QR\n(HTTPS, JSON)", "HTTPS", True, []),
    ("G03", "ORG", "EVU", "Eventos, afiches y CSV\n(HTTPS, JSON/multipart)", "HTTPS", True, []),
    ("G04", "ADM", "EVU", "Usuarios, roles y reportes\n(HTTPS, JSON)", "HTTPS", True, []),
    ("G05", "PTA", "EVU", "Validación del QR\n(HTTPS, JSON)", "HTTPS", True, []),
    ("G06", "EVU", "PAS", "Orden de pago / webhook\n(HTTPS, JSON firmado)", "HTTPS", True, []),
    ("G07", "EVU", "ENT", "Login institucional\n(HTTPS, OAuth 2.0 / OIDC)", "HTTPS", True, []),
    ("G08", "EVU", "COR", "Envío de QR y reset\n(HTTPS, API REST JSON)", "HTTPS", False, []),
    ("G09", "COR", "EST", "Correo con QR / enlace de reset (SMTP sobre TLS)", "SMTP/TLS", False,
     [(1055, 720), (290, 720), (290, 255)]),
]

# ------------------------------------------------------------------ Nivel 1
L1_NODES = [
    ("VIS", "actor", "Visitante", 20, 40, 160, 60),
    ("EST", "actor", "Estudiante o público", 20, 225, 160, 60),
    ("ORG", "actor", "Organizador", 20, 365, 160, 60),
    ("ADM", "actor", "Administrador", 20, 505, 160, 60),
    ("PTA", "actor", "Personal de Puerta", 20, 770, 160, 60),
    ("CDN", "store", "CDN\n(archivos estáticos React)", 330, 50, 200, 65),
    ("SPA", "process", "Sitio web React\n(SPA + /admin)", 355, 310, 150, 150),
    ("API", "process", "API Node.js\n(contenedor)", 770, 310, 150, 150),
    ("APP", "process", "App de Puerta\n(móvil)", 370, 740, 120, 120),
    ("ENT", "actor", "Microsoft Entra ID", 1220, 60, 200, 65),
    ("COR", "actor", "Servicio de correo", 1220, 262, 200, 65),
    ("PAS", "actor", "Pasarela de pagos", 1220, 450, 200, 65),
    ("DB", "store", "PostgreSQL\n(usuarios, inscripciones, pagos)", 720, 745, 200, 70),
    ("BUCKET", "store", "Bucket de objetos\n(afiches y CSV)", 960, 745, 200, 70),
    ("LOGS", "store", "Logs / bitácora\n(servicio cloud, S6)", 1200, 745, 200, 70),
]
L1_BOUNDS = [
    ("B1", "Límite 1 · Borde CDN", 300, 20, 260, 115),
    ("B2", "Límite 2 · Navegador del usuario (no confiable)", 300, 200, 260, 360),
    ("B3", "Límite 3 · Nube EventosU – aplicación", 700, 200, 290, 360),
    ("B4", "Límite 4 · Servicios de terceros", 1190, 20, 260, 540),
    ("B5", "Límite 5 · Nube EventosU – datos", 700, 705, 750, 140),
    ("B6", "Límite 6 · Dispositivo móvil de puerta", 300, 705, 260, 190),
]
L1_FLOWS = [
    ("F01", "VIS", "SPA", "Consulta del catálogo\n(HTTPS, HTML/JSON)", "HTTPS", False, []),
    ("F02", "EST", "SPA", "Registro, login e inscripción\n(HTTPS, formulario)", "HTTPS", False, []),
    ("F03", "ORG", "SPA", "Datos del evento y afiche\n(HTTPS, multipart)", "HTTPS", False, []),
    ("F04", "ADM", "SPA", "Gestión de usuarios y roles\n(HTTPS, formulario)", "HTTPS", False, []),
    ("F05", "CDN", "SPA", "Bundle React\n(HTTPS, JS/HTML/CSS)", "HTTPS", False, []),
    ("F06", "SPA", "API", "Peticiones autenticadas\n(HTTPS, JSON + JWT Bearer)", "HTTPS", False, [(630, 350)]),
    ("F07", "API", "SPA", "Respuestas y JWT emitido\n(HTTPS, JSON)", "HTTPS", False, [(630, 425)]),
    ("F08", "SPA", "ENT", "Login institucional\n(HTTPS, OAuth 2.0 code + PKCE)", "HTTPS", True, [(490, 168), (1150, 168)]),
    ("F09", "API", "ENT", "Canje de código por tokens\n(HTTPS, OAuth 2.0 token endpoint)", "HTTPS", True, []),
    ("F10", "SPA", "PAS", "Redirección a pago\n(HTTPS, ID de orden + monto)", "HTTPS", False, [(480, 605), (1100, 605)]),
    ("F11", "PAS", "API", "Webhook de pago\n(HTTPS, JSON firmado HMAC)", "HTTPS", False, []),
    ("F12", "API", "COR", "Solicitud de envío de QR / reset\n(HTTPS, REST JSON + API key)", "HTTPS", False, []),
    ("F13", "COR", "EST", "Correo con entrada QR / enlace de reset (SMTP sobre TLS)", "SMTP/TLS", False,
     [(1480, 295), (1480, 0), (240, 0), (240, 255)]),
    ("F14", "API", "DB", "Consultas SQL\n(TLS, protocolo PostgreSQL)", "TLS", True, []),
    ("F15", "API", "BUCKET", "Afiches y CSV generados\n(HTTPS, SDK de almacenamiento)", "HTTPS", False, []),
    ("F16", "BUCKET", "SPA", "Descarga de afiche / CSV\n(HTTPS, URL prefirmada)", "HTTPS", False, [(1000, 668), (530, 668)]),
    ("F17", "PTA", "APP", "Escaneo del QR\n(cámara, imagen QR)", "Cámara", False, []),
    ("F18", "APP", "API", "Validación del QR: válido / ya usado\n(HTTPS, JSON token + JWT)", "HTTPS", True, [(640, 545)]),
    ("F19", "API", "LOGS", "Eventos de auditoría\n(HTTPS, JSON)", "HTTPS", False, []),
]
# Posiciones de etiqueta solo para el render del informe (Threat Dragon ubica las suyas a mitad del flujo)
LABEL_POS = {
    "F01": (250, 150), "F02": (255, 300), "F03": (255, 410), "F04": (255, 500),
    "F05": (430, 165), "F06": (630, 335), "F07": (630, 440), "F08": (820, 168),
    "F09": (1080, 235), "F10": (690, 605), "F11": (1085, 455), "F12": (1080, 330),
    "F13": (860, 0), "F14": (835, 520), "F15": (1010, 640), "F16": (690, 668),
    "F17": (270, 800), "F18": (640, 535), "F19": (1240, 690),
}
CROSSING = {"F05", "F06", "F07", "F08", "F09", "F10", "F11", "F12", "F13", "F14", "F15", "F16", "F18", "F19"}

NODE_PROPS = {
    "SPA": dict(isWebApplication=True, handlesGoodsOrServices=True, privilegeLevel="usuario (navegador)"),
    "API": dict(isWebApplication=True, handlesGoodsOrServices=True, privilegeLevel="servicio"),
    "APP": dict(privilegeLevel="rol Puerta"),
    "DB": dict(storesCredentials=True, isEncrypted=True),
    "BUCKET": dict(),
    "LOGS": dict(isALog=True),
    "ENT": dict(providesAuthentication=True),
}
DESCRIPCIONES = {
    "SPA": "React servido desde CDN. Guarda el JWT en localStorage (S1). Incluye la ruta /admin con el mismo login.",
    "API": "Node.js en contenedor. Emite JWT (S2), canjea códigos OAuth con Entra ID, recibe el webhook de pago, genera QR y CSV.",
    "APP": "App móvil del Personal de Puerta; consulta la API para validar el QR (S8).",
    "DB": "PostgreSQL administrado sin IP pública (S9). Sin datos de tarjeta.",
    "BUCKET": "Afiches (públicos) y CSV exportados en el mismo bucket (S7).",
    "LOGS": "stdout del contenedor recogido por el servicio de logs del proveedor (S6).",
    "PAS": "Proveedor externo con hosted checkout; firma webhooks con HMAC (S4).",
    "ENT": "Proveedor de identidad institucional (OAuth 2.0 / OIDC).",
    "COR": "Proveedor externo de envío de correo (API REST con API key, S10).",
    "CDN": "Distribuye el bundle estático del sitio.",
}

SEV = {"Crítico": "High", "Alto": "High", "Medio": "Medium", "Bajo": "Low"}

def ports(key):
    groups = {}
    for g in ("top", "right", "bottom", "left"):
        groups[g] = {"position": g, "attrs": {"circle": {"r": 4, "magnet": True, "stroke": "#5F95FF",
                     "strokeWidth": 1, "fill": "#fff", "style": {"visibility": "hidden"}}}}
    return {"groups": groups, "items": [{"group": g, "id": uid(key, "port", g)} for g in groups]}

def threats_for(diagram, key):
    if diagram != "L1":
        return []
    out = []
    for n, a in enumerate(AMENAZAS, 1):
        if a["elem"] != key:
            continue
        r = riesgo(a["impacto"], a["prob"])
        out.append({
            "id": uid("threat", a["id"]),
            "number": int(a["id"].split("-")[1]),
            "title": f'{a["id"]} {a["titulo"]}',
            "type": a["stride"],
            "modelType": "STRIDE",
            "status": a["estado"],
            "severity": SEV[r],
            "score": f'{r} (Impacto {a["impacto"]} × Probabilidad {a["prob"]})',
            "description": a["escenario"],
            "mitigation": f'[{a["respuesta"]}] {a["mitigacion"]}',
        })
    return out

def node_cell(diagram, key, tipo, name, x, y, w, h, z):
    thr = threats_for(diagram, key)
    open_ = any(t["status"] == "Open" for t in thr)
    stroke = {"stroke": "red" if open_ else "#333333", "strokeWidth": 2.5 if open_ else 1.5, "strokeDasharray": ""}
    data = {"name": name, "description": DESCRIPCIONES.get(key, ""), "isTrustBoundary": False,
            "outOfScope": False, "reasonOutOfScope": "", "threats": thr, "hasOpenThreats": open_}
    if tipo == "process":
        data.update(type="tm.Process", handlesCardPayment=False, handlesGoodsOrServices=False,
                    isWebApplication=False, privilegeLevel="")
        attrs = {"text": {"text": name}, "body": stroke}
    elif tipo == "store":
        data.update(type="tm.Store", isALog=False, storesCredentials=False, isEncrypted=False, isSigned=False)
        attrs = {"text": {"text": name}, "topLine": stroke, "bottomLine": stroke}
    else:
        data.update(type="tm.Actor", providesAuthentication=False)
        attrs = {"text": {"text": name}, "body": stroke}
    data.update(NODE_PROPS.get(key, {}) if diagram == "L1" else {})
    return {"position": {"x": x, "y": y}, "size": {"width": w, "height": h}, "attrs": attrs,
            "visible": True, "shape": tipo, "zIndex": z, "ports": ports(diagram + key),
            "id": uid(diagram, key), "data": data}

def boundary_cell(diagram, key, name, x, y, w, h):
    return {"position": {"x": x, "y": y}, "size": {"width": w, "height": h},
            "attrs": {"label": {"text": name}}, "visible": True, "shape": "trust-boundary-box",
            "id": uid(diagram, key), "zIndex": -1,
            "data": {"type": "tm.BoundaryBox", "name": name, "description": "", "isTrustBoundary": True,
                     "hasOpenThreats": False}}

def flow_cell(diagram, key, src, dst, name, proto, bidir, verts, z):
    thr = threats_for(diagram, key)
    open_ = any(t["status"] == "Open" for t in thr)
    public = diagram == "L1" and key in CROSSING and key not in {"F14", "F15", "F19"}
    line = {"stroke": "red" if open_ else "#333333", "targetMarker": {"name": "block"},
            "sourceMarker": {"name": "block" if bidir else ""}, "strokeDasharray": ""}
    return {"shape": "flow", "attrs": {"line": line}, "width": 200, "height": 100, "zIndex": z,
            "labels": [{"markup": [{"tagName": "ellipse", "selector": "labelBody"},
                                   {"tagName": "text", "selector": "labelText"}],
                        "attrs": {"labelText": {"text": name, "textAnchor": "middle", "textVerticalAnchor": "middle"},
                                  "labelBody": {"ref": "labelText", "refRx": "50%", "refRy": "60%", "fill": "#fff",
                                                "strokeWidth": 0}},
                        "position": {"distance": 0.5, "args": {"keepGradient": True, "ensureLegibility": True}}}],
            "connector": "smooth",
            "data": {"type": "tm.Flow", "name": name, "description": "", "outOfScope": False,
                     "reasonOutOfScope": "", "hasOpenThreats": open_, "isBidirectional": bidir,
                     "isEncrypted": proto in ("HTTPS", "TLS", "SMTP/TLS"), "isPublicNetwork": public,
                     "protocol": proto, "threats": thr, "isTrustBoundary": False},
            "id": uid(diagram, key), "source": {"cell": uid(diagram, src)}, "target": {"cell": uid(diagram, dst)},
            "vertices": [{"x": vx, "y": vy} for vx, vy in verts]}

def text_cell(diagram, key, text, x, y, w, h):
    return {"position": {"x": x, "y": y}, "size": {"width": w, "height": h}, "attrs": {"text": {"text": text}},
            "visible": True, "shape": "td-text-block", "id": uid(diagram, key), "zIndex": 2,
            "data": {"type": "tm.Text", "name": text, "hasOpenThreats": False}}

def diagram(diag_id, title, desc, nodes, bounds, flows, note=None):
    cells = []
    for b in bounds:
        cells.append(boundary_cell(diag_key(diag_id), *b))
    z = 3
    for n in nodes:
        cells.append(node_cell(diag_key(diag_id), *n, z)); z += 1
    for f in flows:
        cells.append(flow_cell(diag_key(diag_id), *f, z)); z += 1
    if note:
        cells.append(text_cell(diag_key(diag_id), "NOTE", *note))
    return {"version": "2.6.2", "title": title, "description": desc, "diagramType": "STRIDE",
            "placeholder": "", "thumbnail": "./public/content/images/thumbnail.stride.jpg",
            "id": diag_id, "cells": cells}

def diag_key(i):
    return "L0" if i == 0 else "L1"

def build_model():
    max_n = max(int(a["id"].split("-")[1]) for a in AMENAZAS)
    return {
        "version": "2.6.2",
        "summary": {"title": TITULO, "owner": "Estuardo Saban / [Integrante 2]",
                    "description": "Modelo de amenazas de EventosU (sitio de eventos universitarios con inscripción, pago y entrada QR) en fase de diseño. STRIDE por elemento y por flujo. Supuestos S1–S12 en el informe (docs/informe.pdf).",
                    "id": 0},
        "detail": {
            "contributors": [{"name": "Estuardo Saban"}, {"name": "[Integrante 2]"}],
            "diagrams": [
                diagram(0, "Nivel 0 – Contexto",
                        "EventosU como un solo proceso y sus actores externos.",
                        L0_NODES, L0_BOUNDS, L0_FLOWS),
                diagram(1, "Nivel 1 – Componentes",
                        "Todos los componentes del caso, 6 límites de confianza y 19 flujos con dato y protocolo. Las amenazas STRIDE están en los elementos y flujos de este diagrama.",
                        L1_NODES, L1_BOUNDS, L1_FLOWS),
            ],
            "diagramTop": 2,
            "reviewer": "",
            "threatTop": max_n,
        },
    }

if __name__ == "__main__":
    import sys
    out = sys.argv[1]
    m = build_model()
    with open(out, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)
    n = sum(len(c["data"].get("threats", [])) for d in m["detail"]["diagrams"] for c in d["cells"])
    print("amenazas en el modelo:", n)
