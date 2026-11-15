# -*- coding: utf-8 -*-
"""Genera docs/amenazas.csv y docs/informe.html (que luego se imprime a PDF)."""
import csv, html, os, sys
from collections import Counter
from data import *
from dfd import L1_NODES, L1_FLOWS, L1_BOUNDS, CROSSING
from arbol import NODOS, CAMINO_BARATO

REPO = sys.argv[1]
E = lambda s: html.escape(str(s))

NOMBRES = {k: n.replace("\n", " ") for k, _, n, *_ in L1_NODES}
FLUJOS = {k: (o, d, n.replace("\n", " "), p) for k, o, d, n, p, *_ in L1_FLOWS}
def elem_nombre(k):
    if k in FLUJOS:
        return f"{k} · {FLUJOS[k][2].split(' (')[0]}"
    return NOMBRES[k]
def elem_tipo(k):
    return "Flujo" if k in FLUJOS else {"process": "Proceso", "store": "Almacén", "actor": "Entidad externa"}[
        next(t for kk, t, *_ in L1_NODES if kk == k)]
STRIDE_ES = {"Spoofing": "S – Suplantación", "Tampering": "T – Manipulación", "Repudiation": "R – Repudio",
             "Information disclosure": "I – Divulgación", "Denial of service": "D – Denegación de servicio",
             "Elevation of privilege": "E – Elevación de privilegios"}
def estado(a):
    return "Aceptada (Coordinación de Eventos)" if a["respuesta"] == "Aceptar" else "Abierta – requisito de diseño pendiente"
for a in AMENAZAS:
    a["riesgo"] = riesgo(a["impacto"], a["prob"])

# ------------------------------------------------------------------ CSV
os.makedirs(f"{REPO}/docs", exist_ok=True)
with open(f"{REPO}/docs/amenazas.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["ID", "Elemento", "Tipo de elemento", "Cruza límite de confianza", "STRIDE", "Título", "Escenario",
                "Impacto", "Justificación impacto", "Probabilidad", "Justificación probabilidad", "Riesgo",
                "Respuesta", "Mitigación", "Estado"])
    for a in AMENAZAS:
        w.writerow([a["id"], elem_nombre(a["elem"]), elem_tipo(a["elem"]), "Sí" if a["cruza"] else "No",
                    STRIDE_ES[a["stride"]], a["titulo"], a["escenario"], a["impacto"], a["j_imp"], a["prob"],
                    a["j_prob"], a["riesgo"], a["respuesta"], a["mitigacion"], estado(a)])

# ------------------------------------------------------------------ HTML
RCOL = {"Crítico": "#b71c1c", "Alto": "#e65100", "Medio": "#f9a825", "Bajo": "#2e7d32"}
RBG = {"Crítico": "#ffcdd2", "Alto": "#ffe0b2", "Medio": "#fff9c4", "Bajo": "#c8e6c9"}
def badge(r):
    return f'<span class="badge" style="background:{RBG[r]};color:{RCOL[r]}">{r}</span>'

cnt = Counter(a["stride"] for a in AMENAZAS)
cruzan = [a for a in AMENAZAS if a["cruza"]]
riesgos = Counter(a["riesgo"] for a in AMENAZAS)
resp = Counter(a["respuesta"] for a in AMENAZAS)

css = """
@page { size: letter; margin: 18mm 16mm 18mm 16mm; @bottom-right { content: counter(page); font-family: Inter, Helvetica, sans-serif; font-size: 8pt; color: #777; } }
@page land { size: letter landscape; margin: 12mm 12mm 12mm 12mm; }
* { box-sizing: border-box; }
body { font-family: 'Inter', Helvetica, Arial, sans-serif; font-size: 10pt; color: #1d1d1f; line-height: 1.42; }
h1 { font-size: 19pt; color: #8b1a1a; margin: 0 0 6pt; border-bottom: 2px solid #8b1a1a; padding-bottom: 4pt; }
h2 { font-size: 13pt; color: #8b1a1a; margin: 14pt 0 6pt; }
h3 { font-size: 11pt; margin: 10pt 0 4pt; }
p { margin: 4pt 0 6pt; }
table { border-collapse: collapse; width: 100%; margin: 4pt 0 10pt; }
th, td { border: 1px solid #c9ccd1; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #1f3b5c; color: #fff; font-weight: 600; }
tr:nth-child(even) td { background: #f6f7f9; }
.small td, .small th { font-size: 8.4pt; }
.tiny td, .tiny th { font-size: 7.3pt; padding: 2pt 3pt; line-height: 1.28; }
.badge { padding: 1pt 5pt; border-radius: 6pt; font-weight: 700; font-size: 8pt; white-space: nowrap; }
.land { page: land; }
.brk { break-before: page; }
.nobrk { break-inside: avoid; }
tr { break-inside: avoid; }
figure { margin: 6pt 0 10pt; text-align: center; break-inside: avoid; }
figure img { max-width: 100%; border: 1px solid #ddd; }
figcaption { font-size: 8.5pt; color: #555; margin-top: 3pt; }
.cover { height: 235mm; display: flex; flex-direction: column; justify-content: center; text-align: center; }
.cover h1 { border: none; font-size: 28pt; }
.cover .sub { font-size: 14pt; color: #444; margin-bottom: 30pt; }
.cover table { width: 70%; margin: 10pt auto; }
.note { background: #fff8e1; border-left: 4px solid #f9a825; padding: 5pt 8pt; font-size: 9pt; margin: 6pt 0; }
.ok { color: #2e7d32; font-weight: 700; }
.matrix td { text-align: center; vertical-align: middle; height: 62pt; font-weight: 600; font-size: 9pt; }
.matrix th.rh { background: #eceff3; color: #222; width: 16%; }
ul { margin: 2pt 0 6pt 16pt; padding: 0; } li { margin: 1.5pt 0; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 8.5pt; background: #f1f1f1; padding: 0 2pt; }
.kpi { display: flex; gap: 8pt; margin: 6pt 0 10pt; } .kpi div { flex: 1; border: 1px solid #ddd; border-radius: 4pt; padding: 5pt; text-align: center; }
.kpi b { display: block; font-size: 15pt; color: #8b1a1a; }
"""

h = [f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'><title>{E(TITULO)}</title><style>{css}</style></head><body>"]

# 1. Portada
h.append(f"""<section class="cover">
<div style="font-size:12pt;color:#666;letter-spacing:1px">UNIVERSIDAD GALILEO</div>
<h1>Modelado de amenazas de un sitio web</h1>
<div class="sub">Caso EventosU · STRIDE · OWASP Threat Dragon · OWASP ASVS 5.0</div>
<table><tr><th>Integrante</th><th>Carné</th></tr>
{''.join(f'<tr><td>{E(n)}</td><td>{E(c)}</td></tr>' for n, c in INTEGRANTES)}
</table>
<p style="margin-top:20pt">Curso: {E(CURSO)}<br>Catedrático: {E(CATEDRATICO)}<br>{E(FECHA)}</p>
<p style="font-size:9pt;color:#666">Repositorio: github.com/Esaban17/eventosu-threat-model</p>
</section>""")

# 2. Alcance
h.append("<section class='brk'><h1>1. Alcance, activos y supuestos</h1>")
h.append("""<p>EventosU está en fase de diseño: no hay código. El modelo razona únicamente sobre la descripción del caso, siguiendo las cuatro preguntas del Threat Modeling Manifesto: ¿en qué trabajamos? (DFD), ¿qué puede salir mal? (STRIDE y árbol de ataque), ¿qué vamos a hacer al respecto? (respuesta, mitigación y trazabilidad a ASVS) y ¿hicimos un buen trabajo? (controles de verificación en el pipeline).</p>""")
h.append("<h2>1.1 Alcance</h2><h3>Dentro del modelo</h3><ul>" + "".join(f"<li>{E(x)}</li>" for x in ALCANCE_DENTRO) + "</ul>")
h.append("<h3>Fuera del modelo</h3><ul>" + "".join(f"<li>{E(x)}</li>" for x in ALCANCE_FUERA) + "</ul>")
h.append("<h2>1.2 Activos</h2><table class='small'><tr><th style='width:6%'>ID</th><th style='width:34%'>Activo</th><th>Valor para el negocio</th></tr>")
h += [f"<tr><td>{i}</td><td><b>{E(n)}</b></td><td>{E(v)}</td></tr>" for i, n, v in ACTIVOS]
h.append("</table>")
h.append("<h2>1.3 Supuestos</h2><p>El caso no define estos puntos; los declaramos y los usamos de forma consistente en el DFD, las amenazas y las mitigaciones.</p><table class='small'><tr><th style='width:6%'>ID</th><th>Supuesto</th></tr>")
h += [f"<tr><td>{i}</td><td>{E(t)}</td></tr>" for i, t in SUPUESTOS]
h.append("</table></section>")

# 3. DFD
h.append("<section class='brk'><h1>2. Diagramas de flujo de datos</h1>")
h.append("""<p>Los diagramas están en <code>model/eventosu.json</code> (Threat Dragon 2.x, validado contra el esquema oficial <i>threat-dragon-v2.schema.json</i>). Los elementos en rojo tienen amenazas abiertas, igual que en Threat Dragon.</p>""")
h.append("<figure><img src='img/dfd_nivel0.png'><figcaption>Figura 1. DFD nivel 0 (contexto): EventosU como un solo proceso y sus actores externos.</figcaption></figure></section>")
h.append("<section class='brk land'><figure><img src='img/dfd_nivel1.png' style='max-height:170mm'><figcaption>Figura 2. DFD nivel 1: los 10 componentes del caso, 6 límites de confianza y 19 flujos con dato y protocolo.</figcaption></figure></section>")
h.append("<section class='brk'><h2>2.1 Límites de confianza</h2><table class='small'><tr><th style='width:8%'>ID</th><th style='width:32%'>Límite</th><th>Por qué es un límite</th></tr>")
why = {
 "B1": "El CDN es infraestructura de un tercero que entrega el código que se ejecuta en el navegador; si alguien lo altera, cambia lo que corre el cliente.",
 "B2": "El navegador está bajo control total del usuario: todo lo que corre o se guarda ahí (JS, localStorage) se puede leer y manipular.",
 "B3": "La API es el único punto donde se pueden aplicar autenticación, autorización y reglas de negocio de forma confiable.",
 "B4": "Pasarela, Entra ID y correo son de otras organizaciones: confiamos en sus mensajes solo si se autentican (firma, tokens).",
 "B5": "Aquí viven los datos persistentes (PII, pagos, CSV, logs); solo la API debe cruzar este límite, con credenciales de mínimo privilegio.",
 "B6": "El teléfono del personal de puerta puede perderse o ser manipulado; la app es un cliente más, no es confiable.",
}
h += [f"<tr><td>{k}</td><td><b>{E(n)}</b></td><td>{E(why[k])}</td></tr>" for k, n, *_ in L1_BOUNDS]
h.append("</table><h2>2.2 Flujos de datos (nivel 1)</h2><table class='small'><tr><th>ID</th><th>Origen → Destino</th><th>Dato</th><th>Protocolo</th><th>Cruza límite</th></tr>")
for k, o, d, n, p, bidir, _ in L1_FLOWS:
    arrow = "↔" if bidir else "→"
    h.append(f"<tr><td>{k}</td><td>{E(NOMBRES[o])} {arrow} {E(NOMBRES[d])}</td><td>{E(n.replace(chr(10),' '))}</td><td>{E(p)}</td><td>{'Sí' if k in CROSSING else 'No'}</td></tr>")
h.append("</table></section>")

# 4. Amenazas
h.append("<section class='brk land'><h1>3. Tabla de amenazas (STRIDE por elemento y por flujo)</h1>")
h.append(f"""<div class="kpi"><div><b>{len(AMENAZAS)}</b>amenazas</div>
{''.join(f'<div><b>{cnt[s]}</b>{STRIDE_ES[s]}</div>' for s in STRIDE_ES)}
<div><b>{len(cruzan)}</b>en flujos que cruzan límite</div></div>""")
h.append("<table class='tiny'><tr><th style='width:3.5%'>ID</th><th style='width:8%'>Elemento</th><th style='width:6.5%'>STRIDE</th><th style='width:28%'>Escenario (quién, cómo, qué obtiene)</th><th style='width:4%'>Imp.</th><th style='width:4%'>Prob.</th><th style='width:5%'>Riesgo</th><th style='width:5.5%'>Respuesta</th><th style='width:28%'>Mitigación (verificable)</th><th style='width:7.5%'>Estado</th></tr>")
for a in AMENAZAS:
    el = E(elem_nombre(a["elem"])) + ("<br><i>cruza límite</i>" if a["cruza"] else "")
    h.append(f"<tr><td><b>{a['id']}</b></td><td>{el}</td><td>{E(STRIDE_ES[a['stride']])}</td>"
             f"<td><b>{E(a['titulo'])}.</b> {E(a['escenario'])}</td><td>{a['impacto']}</td><td>{a['prob']}</td>"
             f"<td>{badge(a['riesgo'])}</td><td>{a['respuesta']}</td><td>{E(a['mitigacion'])}</td><td>{E(estado(a))}</td></tr>")
h.append("</table>")
h.append("""<h3>Flujos obligatorios cubiertos</h3><table class='small'><tr><th style='width:22%'>Flujo obligatorio</th><th>Amenazas</th></tr>
<tr><td>Webhook de pago (F11)</td><td>AM-01 webhook falsificado (S), AM-11 sin evidencia ni idempotencia (R); relacionada: AM-09 monto manipulado (T, F10)</td></tr>
<tr><td>Validación del QR (F18 / API / App)</td><td>AM-02 QR predecible (S), AM-08 carrera en “ya usado” (T), AM-24 validación sin rol Puerta (E), AM-19 DoS en puerta (D), AM-13 validaciones sin atribución (R), AM-07 reventa de QR (S, aceptada)</td></tr>
<tr><td>Exportación del CSV (API / Bucket / F16)</td><td>AM-14 IDOR en exportación (I), AM-15 CSV expuesto en bucket (I), AM-10 inyección de fórmulas (T)</td></tr></table>
<p class="note">En Threat Dragon cada amenaza tiene el mismo ID en el título, el escenario como descripción, la respuesta entre corchetes al inicio de la mitigación y el riesgo calculado en el campo <i>score</i>. La amenaza aceptada (AM-07) está marcada como <i>N/A</i>, porque Threat Dragon no tiene un estado “Aceptada”.</p></section>""")

# 5. Árbol
h.append("<section class='brk land'><h1>4. Árbol de ataque: “Entrar a un evento sin pagar”</h1>")
h.append("<figure><img src='img/arbol.png' style='max-height:150mm'><figcaption>Figura 3. Árbol de ataque. [O] = basta cualquier hijo; [Y] = se necesitan todos (arco grueso). En rojo, el camino más barato.</figcaption></figure></section>")
h.append("""<section class='brk'><h2>4.1 Camino más barato y justificación</h2>
<p><b>Camino: Raíz → 2. Obtener un QR válido → 2.1 Fabricar QR con ID secuencial (Y) → comprar una entrada barata + generar los siguientes IDs + presentarse antes que el dueño.</b></p>
<table class='small'><tr><th>Rama</th><th>Costo para el atacante</th><th>Habilidad</th><th>Dependencias / limitaciones</th></tr>
<tr><td><b>2.1 QR secuencial (AM-02)</b></td><td>≈Q25 una sola vez</td><td>Ninguna (app lectora y generador de QR gratuitos)</td><td>Sirve para cualquier evento, se repite sin límite y no depende de nadie</td></tr>
<tr><td>1.1 Webhook forjado (AM-01)</td><td>Q0</td><td>Baja: curl y leer documentación</td><td>Solo funciona si la API no verifica la firma; requiere conocer el formato del payload del proveedor</td></tr>
<tr><td>1.2 Pagar menos (AM-09)</td><td>Q1 por entrada</td><td>Media: proxy de interceptación</td><td>La pasarela deja registro de la transacción a nombre del atacante (lo identifica)</td></tr>
<tr><td>2.2 QR de otra persona (AM-07 / AM-08)</td><td>Q0</td><td>Ninguna</td><td>Necesita que otra persona pague y no entre; en neto no genera ingresos perdidos (por eso AM-07 se acepta)</td></tr>
<tr><td>3.1 Escalar privilegios (AM-22/23/24)</td><td>Q0</td><td>Media a alta</td><td>Hay que analizar el bundle JS o la app y encadenar llamadas</td></tr>
<tr><td>3.2 DoS + puerta sin control (AM-19)</td><td>≈Q400</td><td>Media</td><td>Hay que alquilar una botnet y además el personal tiene que ceder; es caro y llama la atención</td></tr>
<tr><td>3.3 Personal cómplice (AM-13)</td><td>Soborno</td><td>Social</td><td>Requiere reclutar a alguien del personal</td></tr></table>
<p>El webhook forjado cuesta Q0 en dinero, pero solo funciona si el equipo olvida verificar la firma y exige algo de conocimiento técnico. El QR secuencial, en cambio, se descubre al ver <i>una</i> entrada, no exige ninguna habilidad y escala a todos los eventos. Por eso es el camino más barato y probable, y AM-02 aparece entre las críticas. Cortarlo exige tokens aleatorios de 128 bits (ASVS 11.5.1); con eso la rama 2.1 desaparece y el atacante tiene que pasar a ramas más caras o que dejan rastro.</p></section>""")

# 6. Matriz
h.append("<section class='brk'><h1>5. Priorización: matriz de impacto × probabilidad</h1><h2>5.1 Criterios</h2>")
h.append("<table class='small'><tr><th style='width:14%'>Impacto</th><th>Criterio</th></tr>" + "".join(f"<tr><td><b>{k}</b></td><td>{E(v)}</td></tr>" for k, v in CRITERIOS_IMPACTO.items()) + "</table>")
h.append("<table class='small'><tr><th style='width:14%'>Probabilidad</th><th>Criterio</th></tr>" + "".join(f"<tr><td><b>{k}</b></td><td>{E(v)}</td></tr>" for k, v in CRITERIOS_PROB.items()) + "</table>")
h.append("<p><b>Riesgo</b> = Impacto (Bajo 1, Medio 2, Alto 3) × Probabilidad (Baja 1, Media 2, Alta 3): <b>9 Crítico</b>, <b>6 Alto</b>, <b>3–4 Medio</b>, <b>1–2 Bajo</b>. Los Críticos se resuelven antes de escribir código; los Altos, antes del primer release.</p>")
h.append("<h2>5.2 Matriz 3 × 3</h2><table class='matrix nobrk'><tr><th class='rh'>Impacto ↓ / Probabilidad →</th><th>Baja</th><th>Media</th><th>Alta</th></tr>")
for imp in ["Alto", "Medio", "Bajo"]:
    h.append(f"<tr><th class='rh'>{imp}</th>")
    for pr in ["Baja", "Media", "Alta"]:
        r = riesgo(imp, pr)
        ids = [a["id"] for a in AMENAZAS if a["impacto"] == imp and a["prob"] == pr]
        h.append(f"<td style='background:{RBG[r]};color:{RCOL[r]}'>{'<br>'.join(ids) or '—'}<div style='font-size:7.5pt;font-weight:400;color:#555'>{r} ({NIVEL[imp]*NIVEL[pr]})</div></td>")
    h.append("</tr>")
h.append("</table>")
h.append(f"<p>Distribución: {', '.join(f'{riesgos[r]} {r}' for r in ['Crítico','Alto','Medio','Bajo'])}. Respuestas: {', '.join(f'{v} {k}' for k, v in resp.items())}.</p>")
h.append("<h2>5.3 Justificación de cada calificación</h2><table class='tiny'><tr><th style='width:6%'>ID</th><th style='width:6%'>Impacto</th><th style='width:38%'>Justificación del impacto</th><th style='width:6%'>Prob.</th><th style='width:36%'>Justificación de la probabilidad</th><th style='width:8%'>Riesgo</th></tr>")
for a in AMENAZAS:
    h.append(f"<tr><td><b>{a['id']}</b></td><td>{a['impacto']}</td><td>{E(a['j_imp'])}</td><td>{a['prob']}</td><td>{E(a['j_prob'])}</td><td>{badge(a['riesgo'])}</td></tr>")
h.append("</table></section>")

# 7. Trazabilidad
h.append("<section class='brk'><h1>6. Respuesta y trazabilidad de las 5 amenazas críticas</h1>")
h.append("<p>Las cinco amenazas con riesgo Crítico (9) se trazan a requisitos de <b>OWASP ASVS 5.0</b>, a una historia de usuario con criterios de aceptación y al control del pipeline que las verifica.</p>")
amap = {a["id"]: a for a in AMENAZAS}
for t in TRAZABILIDAD:
    a = amap[t["id"]]
    h.append(f"""<div class='nobrk'><h3>{a['id']} · {E(a['titulo'])} {badge(a['riesgo'])}</h3>
<table class='small'><tr><th style='width:20%'>Respuesta</th><td>{a['respuesta']}: {E(a['mitigacion'])}</td></tr>
<tr><th>Requisitos ASVS 5.0</th><td><ul>{''.join(f'<li><b>V{r}</b> – {E(d)}</li>' for r, d in t['asvs'])}</ul></td></tr>
<tr><th>Historia de usuario</th><td>{E(t['historia'])}</td></tr>
<tr><th>Criterios de aceptación</th><td>{E(t['criterios'])}</td></tr>
<tr><th>Control que lo verifica</th><td><b>{E(t['control'])}</b>: {E(t['detalle_control'])}</td></tr></table></div>""")
h.append("<h2>6.1 Resumen de trazabilidad</h2><table class='small nobrk'><tr><th>Amenaza</th><th>ASVS 5.0</th><th>Control</th></tr>")
for t in TRAZABILIDAD:
    h.append(f"<tr><td>{t['id']} {E(amap[t['id']]['titulo'])}</td><td>{', '.join('V'+r for r, _ in t['asvs'])}</td><td>{E(t['control'])}</td></tr>")
h.append("</table>")
acc = amap["AM-07"]
h.append(f"""<h2>6.2 Riesgo aceptado</h2><table class='small nobrk'>
<tr><th style='width:20%'>Amenaza</th><td>AM-07 · {E(acc['titulo'])} ({badge(acc['riesgo'])})</td></tr>
<tr><th>Justificación</th><td>Con el control de un solo uso (AM-08), una entrada pagada equivale a un solo ingreso: no hay pérdida económica ni sobrecupo. Exigir carné o documento en todas las puertas añade colas y fricción desproporcionadas para eventos gratuitos o de bajo costo, que son la mayoría.</td></tr>
<tr><th>Responsable</th><td><b>Coordinación de Eventos de la universidad</b> (dueña del producto EventosU).</td></tr>
<tr><th>Condición de revisión</th><td>Se revisa si un evento supera la demanda esperada o si se detecta reventa con sobreprecio. En ese caso, para ese evento se activa la entrada nominal (nombre en la pantalla de validación y verificación del carné).</td></tr></table>
<p>Otras respuestas distintas a mitigar: <b>AM-19</b> se <b>transfiere</b> al servicio anti-DDoS/WAF del proveedor cloud mediante contrato, y <b>AM-25</b> se <b>elimina</b> al no aceptar SVG.</p></section>""")

# 8. Conclusiones
h.append("""<section class='brk'><h1>7. Conclusiones: qué cambiaríamos del diseño antes de programar</h1>
<ol>
<li><b>El pago se confirma en el servidor, no por lo que diga el cliente.</b> La API crea la orden con el precio de la BD, verifica la firma HMAC del webhook, confirma la transacción con la pasarela y procesa cada evento una sola vez. Con esto se cierran AM-01, AM-09 y AM-11, que juntas permiten conseguir entradas sin pagar.</li>
<li><b>QR como token aleatorio de 128 bits ligado al evento</b>, con marca de uso atómica en la BD (AM-02, AM-08). Este es el camino más barato del árbol de ataque y el cambio cuesta casi nada en fase de diseño.</li>
<li><b>La autorización vive en la API y niega por defecto.</b> Control por función (rol) y por objeto (dueño del evento) en cada endpoint; el panel /admin pasa a un subdominio propio con MFA (AM-14, AM-22, AM-24).</li>
<li><b>Sesión en cookie HttpOnly en lugar de localStorage</b> (descartando el supuesto S1), con CSP estricta. Así un XSS ya no sirve para robar sesiones (AM-16), y el JWT se firma con EdDSA/RS256 con algoritmos fijados (AM-23).</li>
<li><b>Login institucional solo con el tenant de la universidad</b>, usando PKCE e identificando al usuario por oid + tid (AM-03, AM-04).</li>
<li><b>Separar los datos según su sensibilidad.</b> Los afiches van a un bucket o dominio de contenido de usuario, y los CSV a un bucket privado con URLs prefirmadas de 5 minutos y borrado a las 24 horas; todo se declara en IaC y se verifica con Checkov (AM-15, AM-25).</li>
<li><b>Bitácora de auditoría de solo-anexado, separada de la operación</b> (AM-12, AM-13, AM-18), con cuentas nominales para el personal de puerta y redacción de secretos en los logs.</li>
<li><b>Resiliencia en la puerta.</b> WAF/anti-DDoS del proveedor, autoescalado y una lista firmada de tokens que la app descarga antes del evento para validar sin conexión (AM-19).</li>
</ol>
<p>El aprendizaje principal es que las amenazas más graves de EventosU no son técnicas sofisticadas sino <b>decisiones de diseño implícitas</b>: confiar en el cliente (monto, rol, ruta /admin), usar identificadores predecibles y no definir quién puede ver qué. Detectarlas ahora cuesta una línea en un documento; detectarlas en producción costaría dinero, datos personales y la confianza de los estudiantes. Este mismo método se aplicará en la Fase 2 del proyecto final.</p>
<h2>Referencias</h2><ul>
<li>OWASP Threat Dragon 2.x – esquema <i>threat-dragon-v2.schema.json</i>.</li>
<li>OWASP Application Security Verification Standard (ASVS) 5.0.</li>
<li>OWASP Threat Modeling Cheat Sheet y Threat Modeling Manifesto.</li>
<li>Shostack, A. <i>Threat Modeling: Designing for Security</i> (STRIDE por elemento).</li>
</ul></section>""")
h.append("</body></html>")
open(f"{REPO}/docs/fuente/informe.html", "w", encoding="utf-8").write("\n".join(h))
print("ok", len(AMENAZAS), dict(cnt), "cruzan", len(cruzan), dict(riesgos), dict(resp))
