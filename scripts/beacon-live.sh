#!/usr/bin/env bash
# abre beacon en el navegador. dos modos:
#   scripts/beacon-live.sh [opciones de beacon live]            aplicación live: navegación, histórico y acciones
#                                                                (p. ej. --monitor 60 --profile casa)
#   scripts/beacon-live.sh --report [opciones de beacon watch]  informe html autónomo que `beacon watch -o` regenera
#                                                                (p. ej. -n 30 --target 192.168.1.0/24)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${BEACON_LIVE_OUTPUT:-$ROOT/vivo.html}"
cd "$ROOT"

if command -v uv >/dev/null 2>&1; then
  BEACON=(uv run beacon)
elif command -v beacon >/dev/null 2>&1; then
  BEACON=(beacon)
else
  echo "error: no se encontró 'uv' ni 'beacon'. instala uv (https://docs.astral.sh/uv/) y ejecuta 'uv sync'." >&2
  exit 1
fi

# algunos discos (exfat, ntfs...) no admiten symlinks y uv no puede crear ahí el .venv:
# en ese caso el entorno virtual se guarda fuera del proyecto
if [ -z "${UV_PROJECT_ENVIRONMENT:-}" ]; then
  probe="$ROOT/.symlink-probe"
  if ln -s . "$probe" 2>/dev/null; then
    rm -f "$probe"
  else
    export UV_PROJECT_ENVIRONMENT="${XDG_CACHE_HOME:-$HOME/.cache}/beacon/venv"
    echo "aviso: el disco no admite symlinks, el entorno virtual estará en $UV_PROJECT_ENVIRONMENT"
  fi
fi

if [ "${1:-}" != "--report" ]; then
  echo "beacon live: la aplicación se abrirá en el navegador. ctrl+c para parar."
  exec "${BEACON[@]}" live "$@"
fi
shift

# borra el informe anterior para abrir el navegador solo cuando exista el nuevo
rm -f "$OUTPUT"

open_browser() {
  for _ in $(seq 1 120); do
    if [ -f "$OUTPUT" ]; then
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$OUTPUT" >/dev/null 2>&1 || true
      elif command -v open >/dev/null 2>&1; then
        open "$OUTPUT" || true
      else
        echo "abre manualmente: $OUTPUT"
      fi
      return
    fi
    sleep 1
  done
}

open_browser &
WAITER=$!
trap 'kill "$WAITER" 2>/dev/null || true' EXIT

case "$OUTPUT" in /*) URL="file://$OUTPUT" ;; *) URL="$OUTPUT" ;; esac
echo "informe html en vivo: $URL"
echo "se abrirá en el navegador al terminar el primer escaneo. ctrl+c para parar."
"${BEACON[@]}" watch -o "$OUTPUT" "$@"
