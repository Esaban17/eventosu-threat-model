# -*- coding: utf-8 -*-
"""Árbol de ataque: 'Entrar a un evento sin pagar'. Genera DOT y la tabla de costos."""
import sys

# id, padre, texto, tipo de compuerta (O/Y para nodos intermedios, None en hojas), costo, amenaza
NODOS = [
    ("R", None, "Entrar a un evento sin pagar", "O", "", ""),
    ("1", "R", "1. Falsificar la confirmación de pago", "O", "", ""),
    ("1.1", "1", "1.1 Webhook forjado", "Y", "Q0 · habilidad baja (curl)", "AM-01"),
    ("1.1.a", "1.1", "Descubrir la URL del webhook\n(documentación del proveedor / DevTools)", None, "Q0 · minutos", ""),
    ("1.1.b", "1.1", "La API no verifica la firma HMAC\n(condición de diseño)", None, "—", ""),
    ("1.1.c", "1.1", "Enviar POST {estado: aprobado} con curl", None, "Q0 · minutos", ""),
    ("1.2", "1", "1.2 Pagar menos de lo debido", "Y", "Q1 · habilidad media (proxy)", "AM-09"),
    ("1.2.a", "1.2", "Interceptar la redirección a la pasarela\n(Burp Suite Community)", None, "Q0", ""),
    ("1.2.b", "1.2", "Cambiar monto=350 por monto=1 y pagar Q1", None, "Q1", ""),
    ("1.2.c", "1.2", "La API no compara el monto del webhook\n(condición de diseño)", None, "—", ""),
    ("2", "R", "2. Obtener un QR válido ajeno o falso", "O", "", ""),
    ("2.1", "2", "2.1 Fabricar QR con ID secuencial", "Y", "Q25 una sola vez · sin habilidad técnica", "AM-02"),
    ("2.1.a", "2.1", "Comprar UNA entrada barata y leer su QR\n(“INS-1042”)", None, "≈Q25", ""),
    ("2.1.b", "2.1", "Generar INS-1043… con un generador de QR gratuito", None, "Q0", ""),
    ("2.1.c", "2.1", "Presentarse antes que el dueño legítimo", None, "Q0", ""),
    ("2.2", "2", "2.2 Usar el QR de otra persona", "O", "", ""),
    ("2.2.a", "2.2", "Captura de pantalla compartida / reventa\n(riesgo aceptado AM-07)", None, "Q0 · depende de un tercero", "AM-07"),
    ("2.2.b", "2.2", "Carrera en dos puertas a la vez", "Y", "Q0 · coordinación", "AM-08"),
    ("2.2.b1", "2.2.b", "Copia del QR de un cómplice que sí pagó", None, "Q0", ""),
    ("2.2.b2", "2.2.b", "Escanear en el mismo segundo en otra puerta\n(SELECT luego UPDATE no atómico)", None, "Q0", ""),
    ("3", "R", "3. Burlar el control en la puerta", "O", "", ""),
    ("3.1", "3", "3.1 Escalar privilegios en la API", "O", "", ""),
    ("3.1.a", "3.1", "PATCH /usuarios/:id/rol sin control de rol\n(/admin solo oculto en React)", None, "Q0 · habilidad media", "AM-22"),
    ("3.1.b", "3.1", "Forjar JWT (alg none / llave débil)", None, "Q0 · habilidad alta", "AM-23"),
    ("3.1.c", "3.1", "Llamar /qr/validar con cuenta de estudiante\n(sin rol Puerta)", None, "Q0 · habilidad media", "AM-24"),
    ("3.2", "3", "3.2 Dejar la puerta sin validación", "Y", "Alquiler de botnet · motivación alta", "AM-19"),
    ("3.2.a", "3.2", "Saturar /qr/validar el día del evento", None, "≈Q400 (botnet por horas)", ""),
    ("3.2.b", "3.2", "El personal deja pasar sin validar\n(no hay modo offline)", None, "—", ""),
    ("3.3", "3", "3.3 Personal de puerta cómplice\n(cuenta compartida, sin atribución AM-13)", None, "Soborno", "AM-13"),
]

CAMINO_BARATO = {"R", "2", "2.1", "2.1.a", "2.1.b", "2.1.c"}

def dot():
    o = ['digraph G {', 'rankdir=LR; nodesep=0.12; ranksep=0.35;',
         'graph [fontname="Inter", bgcolor="white"]; node [fontname="Inter", fontsize=10, shape=box, style="rounded,filled", fillcolor="#ffffff", color="#555555"]; edge [color="#777777", arrowhead=none];']
    for nid, parent, text, gate, cost, am in NODOS:
        label = text.replace("\n", "\\n")
        extra = []
        if cost: extra.append(cost)
        if am and am not in text: extra.append(am)
        if gate:
            label = f"{label}\\n[{'O' if gate=='O' else 'Y'}]"
        if extra:
            label += "\\n" + " · ".join(extra)
        fill = "#fde2e2" if nid in CAMINO_BARATO else ("#eef2f7" if gate else "#ffffff")
        col = "#c0392b" if nid in CAMINO_BARATO else "#555555"
        pw = "2.4" if nid in CAMINO_BARATO else "1"
        shape = "box"
        if nid == "R":
            fill = "#c0392b"; o.append(f'"{nid}" [label="{label}", fillcolor="{fill}", fontcolor="white", color="#7b1f16", penwidth=2, fontsize=12];'); continue
        o.append(f'"{nid}" [label="{label}", fillcolor="{fill}", color="{col}", penwidth={pw}, shape={shape}];')
    for nid, parent, *_ in NODOS:
        if parent:
            red = nid in CAMINO_BARATO and parent in CAMINO_BARATO
            # compuerta Y: arcos sólidos dobles; O: arcos normales
            pgate = next(g for i, p, t, g, c, a in NODOS if i == parent)
            style = 'style=bold' if pgate == "Y" else 'style=solid'
            col = '#c0392b' if red else '#777777'
            o.append(f'"{parent}" -> "{nid}" [color="{col}", penwidth={2.6 if red else (2.4 if pgate == "Y" else 1)}];')
    o.append('legend [shape=plaintext, fillcolor="white", label=<<table border="0" cellborder="1" cellspacing="0" cellpadding="4">'
             '<tr><td bgcolor="#eef2f7">[O] cualquiera de los hijos basta</td></tr>'
             '<tr><td bgcolor="#eef2f7">[Y] se necesitan todos los hijos (arco grueso)</td></tr>'
             '<tr><td bgcolor="#fde2e2"><font color="#c0392b"><b>Camino más barato para el atacante</b></font></td></tr></table>>];')
    pass
    o.append('}')
    return "\n".join(o)

if __name__ == "__main__":
    open(sys.argv[1], "w", encoding="utf-8").write(dot())
