#!/usr/bin/env bash
# Regenera model/eventosu.json, docs/amenazas.csv y docs/informe.pdf a partir de tools/data.py
# Requisitos: python3, graphviz (dot), Google Chrome o Chromium.
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="${CHROME:-$(command -v google-chrome || command -v chromium || command -v chromium-browser || echo "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")}"
IMG=docs/fuente/img; mkdir -p "$IMG"
python3 tools/dfd.py model/eventosu.json
python3 tools/render.py model/eventosu.json "$IMG" | while read -r i w h; do
  [ "$i" = ok ] && continue
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --screenshot="$IMG/dfd_nivel$i.png" --window-size="$w,$h" --default-background-color=ffffffff \
    "file://$PWD/$IMG/dfd_nivel$i.svg" 2>/dev/null
done
python3 tools/arbol.py "$IMG/arbol.dot" && dot -Tpng -Gdpi=170 "$IMG/arbol.dot" -o "$IMG/arbol.png"
python3 tools/build_report.py .
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer --print-to-pdf=docs/informe.pdf "file://$PWD/docs/fuente/informe.html" 2>/dev/null
echo "Listo: model/eventosu.json, docs/amenazas.csv, docs/informe.pdf"
