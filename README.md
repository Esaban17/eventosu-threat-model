# EventosU – Modelo de amenazas

Tarea **Modelado de amenazas de un sitio web** · Universidad Galileo

## Integrantes

| Nombre | Carné |
|---|---|
| Estuardo Saban | [carné] |
| [Nombre integrante 2] | [carné] |

## Alcance

EventosU es un sitio web ficticio donde la universidad publica congresos, talleres y conciertos; los usuarios se inscriben, pagan y reciben un código QR de acceso. Está **en fase de diseño** (no hay código): todo el análisis se razona sobre la descripción del caso.

**Dentro del modelo:** sitio React (CDN + navegador, incluido `/admin`), API Node.js, PostgreSQL, bucket de objetos, app móvil de Puerta, logs de la API y los flujos hacia la pasarela de pagos, el servicio de correo y Microsoft Entra ID.

**Fuera del modelo:** la infraestructura interna de la pasarela, del proveedor de correo, de Entra ID y del CDN (se modelan como entidades externas), los datos de tarjeta (nunca pasan por EventosU), la red física de la universidad y la seguridad física del lugar del evento.

Los supuestos S1–S12 están en la sección 1.3 del informe.

## Resultado en números

- DFD **nivel 0** (contexto) y **nivel 1** (10 componentes, **6 límites de confianza**, 19 flujos con dato y protocolo).
- **25 amenazas STRIDE** (S 7 · T 3 · R 3 · I 5 · D 3 · E 4); **14** sobre flujos que cruzan un límite. Están cubiertos el webhook de pago, la validación del QR y la exportación del CSV.
- Árbol de ataque “Entrar a un evento sin pagar”, con 3 ramas y nodos O/Y; el camino más barato está marcado.
- Matriz 3×3 con criterios escritos: 5 Críticas, 5 Altas, 14 Medias y 1 Baja, cada calificación justificada.
- Las 5 críticas están trazadas a **OWASP ASVS 5.0**, a una historia de usuario y a un control (SAST / DAST / prueba). Hay 1 riesgo aceptado con responsable, 1 transferido y 1 eliminado.

## Estructura

```
eventosu-threat-model/
├── README.md               # este archivo
├── model/eventosu.json     # modelo de OWASP Threat Dragon 2.x (DFD + amenazas)
├── docs/informe.pdf        # informe final
├── docs/amenazas.csv       # tabla de amenazas exportada (UTF-8, abre en Excel)
├── docs/fuente/            # HTML e imágenes con las que se genera el informe
└── tools/                  # scripts que generan modelo, CSV e informe
```

## Cómo abrir el modelo en Threat Dragon

El modelo usa el formato **Threat Dragon v2** y valida sin errores contra el esquema oficial `threat-dragon-v2.schema.json`.

**Aplicación de escritorio** (descárgala desde los [releases de Threat Dragon](https://github.com/OWASP/threat-dragon/releases)):
1. Abre Threat Dragon y elige **Open an existing threat model**.
2. Selecciona `model/eventosu.json`.
3. En la página del modelo abre el diagrama **Nivel 0 – Contexto** o **Nivel 1 – Componentes**. Las amenazas se ven al seleccionar cada elemento o flujo; los que están en rojo tienen amenazas abiertas.

**Versión web:** inicia sesión con **Local Session**, elige **Import a threat model** y pega o carga el contenido de `model/eventosu.json`.

Para buscar una amenaza en Threat Dragon, usa su ID (`AM-01` … `AM-25`), que va en el título. La respuesta (Mitigar, Aceptar, Transferir o Eliminar) va al inicio de la mitigación y el riesgo calculado está en el campo *score*.

## Cómo regenerar los entregables

Todo el contenido (activos, supuestos, amenazas, calificaciones y trazabilidad) vive en `tools/data.py`, y el DFD en `tools/dfd.py`. Después de editarlos:

```bash
./tools/generar.sh     # requiere python3, graphviz (dot) y Google Chrome/Chromium
```

Esto regenera `model/eventosu.json`, `docs/amenazas.csv` y `docs/informe.pdf`, de modo que los tres quedan siempre consistentes entre sí.
