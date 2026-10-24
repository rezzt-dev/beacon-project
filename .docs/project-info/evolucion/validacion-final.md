# Validación final de la evolución · 0.2.0

Fecha: 24 de octubre de 2026. Se ha retomado el trabajo desde el adjunto del agente anterior, conservando los cambios existentes. El registro completo por fases está en [seguimiento.md](seguimiento.md), con validaciones externas separadas de las tareas implementadas.

## Resultado entregado

La aplicación live y la CLI comparten inventario, revisión, riesgo, perfiles, identidad y presencia persistentes. La evolución incluye API local protegida, actualizaciones SSE, trabajos sin solapamiento, análisis histórico, alertas, TLS, escucha pasiva opcional, vecinos IPv6, mantenimiento y ejecución sin terminal. El informe HTML autónomo conserva su modo de solo lectura y sus recursos incluidos.

Esta continuación cierra la optimización y sus flujos:

- La caché utiliza el cursor persistido y una fecha sin segundos ni microsegundos. Comparte evaluaciones entre páginas y órdenes, distingue listas de claves vacías de filtros sin claves e impide mezclar bases en memoria. Las escrituras de otra conexión invalidan los resultados; una transacción sin confirmar no alimenta la caché.
- La revisión permite recorrer toda la cola desde la web con 20 casos por página, conserva el recuento total y hasta 5 evidencias por caso; al agotar la última página vuelve a una página válida. Mantiene el foco al decidir.
- Las aperturas de puertos conservan el evento más reciente por dispositivo/puerto, incluida su marca real de revisión. Los conflictos de IP de una red no aumentan el riesgo de otra red con la misma MAC.
- Confianza y edición condicionan la propia escritura SQL a la versión esperada. Una edición concurrente impide sobrescribir la decisión con datos antiguos.
- El catálogo cuenta cambios en SQL y acota sus listas, con límites visibles y enlace al inventario completo. El resumen evita cargar toda la cola y todas las sesiones para contar.
- La búsqueda espera 75 ms tras la última tecla. La acumulación de cambios de la interfaz es acotada y se solicita una recarga de datos tras retención o desbordamiento.
- Versión, lockfile, changelog, contratos y seguimiento se sincronizan en 0.2.0.

## Arranque y uso

```bash
scripts/beacon-live.sh
# Alternativa con entorno externo para discos sin enlaces simbólicos:
UV_PROJECT_ENVIRONMENT="$HOME/.cache/beacon/venv" uv run beacon live
# Monitor desde el arranque, con perfil existente:
UV_PROJECT_ENVIRONMENT="$HOME/.cache/beacon/venv" uv run beacon live --monitor 60 --profile casa
# Informe portable regenerado:
scripts/beacon-live.sh --report
```

Live sirve en `http://127.0.0.1:8765` y abre el enlace privado de acceso. La pantalla inicial guía el descubrimiento; después se puede editar alias, confiar, revisar y consultar dispositivos, eventos, identidades, presencia y servicios. Para probar sin paquetes hacia la red: `beacon demo /tmp/beacon-demo.db` y `beacon --db /tmp/beacon-demo.db live`.

## Evidencia ejecutada

Entorno: Linux 6.18.56, Python 3.13.13, Chromium de Playwright, Intel i7-10750H, 12 CPU lógicas, 31,2 GB RAM. Los tests usan datos sintéticos y servidores de loopback.

| Comprobación | Resultado |
|---|---|
| `python -m pytest -q` | **392 passed**, 49,22 s; 371 pruebas sin navegador y 21 con Chromium |
| `ruff check app tests scripts` | correcto |
| `git diff --check` | correcto |
| `bash -n scripts/beacon-live.sh` | correcto |
| `uv lock --check --offline` | correcto; versión del proyecto y lockfile 0.2.0 |
| `uv build --offline` | wheel y sdist 0.2.0 construidos; el wheel se construye desde el sdist |
| instalación limpia del wheel fuera del repositorio | CLI `--version`, recursos HTML/CSS/JS, demo, exportación HTML con CSP, servidor HTTP live, rutas directas y parada sin traceback verificados |
| benchmarks | 50/500/5.000 dispositivos, 100.000 eventos en el mayor dataset; API, navegador, SSE, RSS y sentencias SQL medidos |

La línea base previa a la evolución tenía 241 pruebas. El estado recibido pasó 384; esta continuación añade 8 regresiones. Persiste un aviso de deprecación del transporte `httpx` de TestClient; no hay pruebas fallidas ni omitidas en la ejecución final.

Las pruebas de navegador cubren primer uso, rutas directas, filtros persistidos, edición y conflicto, revisión y foco, paginación, identidades, presencia sin observación, exportación, políticas de alerta, reconexión, pausa visual, teclado y diálogos, idioma y semántica. Se comprobaron anchos de 360, 768, 1280 y 1920 px, contraste y nombres accesibles en temas claro y oscuro. Esta evidencia no constituye una auditoría completa de accesibilidad.

## Comparación medida

Los datos brutos y la metodología están en [rendimiento.md](rendimiento.md), [benchmarks.json](benchmarks.json) y [benchmarks-anterior.json](benchmarks-anterior.json). Son mediciones del mismo equipo con datos equivalentes, no una promesa universal.

- Con 500 dispositivos: búsqueda visual p95 **173,7 ms** (antes 259,1 ms); escritura persistida → recepción SSE **512,2 ms**, dentro del objetivo de 2 s.
- Con 5.000 dispositivos: lista paginada p95 **43,9 ms** (antes 728,1); revisión **62,2 ms** (antes 1.044,8); resumen **82,9 ms** (antes 1.832); servicios **224 ms** (antes 792,7).
- La revisión pasa de **9.477.134 a 52.380 bytes** al entregar una página, con el total completo disponible.
- La evaluación completa sin caché todavía tarda **512,2 ms** para 5.000 equipos. Las páginas posteriores utilizan 2 sentencias SQL y la evaluación inicial 7. El coste inicial vuelve a aparecer tras cambios o caducidad temporal; no se garantiza <300 ms en frío.

## Archivos principales

| Ruta | Responsabilidad |
|---|---|
| `app/beacon/services/inventory.py`, `cache.py`, `risk.py`, `review.py`, `catalog.py` | consultas, caché, evaluación y flujos compartidos |
| `app/beacon/storage/devices.py`, `events.py`, `admin.py` | escrituras condicionales, agregaciones e invalidación por retención |
| `app/beacon/web/api.py`, `static/assets/js/views/`, `static/assets/js/main.js` | contratos, paginación, búsqueda, límites y actualización visual |
| `scripts/bench.py` | reproducción de rendimiento, memoria y consultas |
| `tests/test_inventory_cache.py`, `test_api.py`, `test_storage.py`, `test_risk.py`, `test_browser.py` | regresiones de esta continuación |
| `.github/workflows/ci.yml` | lint, matriz de sistemas/Python, Chromium y paquete instalable |
| `pyproject.toml`, `uv.lock`, `app/beacon/__init__.py`, `changelog.md` | distribución y versión |

## Compatibilidad y migraciones

Se conserva Python >=3.11, la CLI existente y los informes JSON/CSV/HTML. La distribución incluye los recursos web y no necesita Node. El esquema sigue en **v5**: se han probado migraciones desde v1, v2, v3 y v4, copia automática previa, integridad y restauración. Los binarios antiguos no pueden abrir una base migrada a v5. Los datos de cobertura heredados se identifican como tales, sin inventar qué puertos se probaron.

Revisión API v1 ahora está paginada por defecto; cualquier consumidor que esperaba toda la cola debe recorrer `page` y `size` hasta `total`. El catálogo devuelve listas limitadas y sus indicadores. El contrato está en [api.md](api.md).

## Límites pendientes reales

- Solo se ha ejecutado localmente Linux/Python 3.13/Chromium. La matriz Linux/macOS/Windows y Python 3.11–3.13 está configurada, sin ejecución remota desde esta sesión.
- Los barridos privilegiados, escucha pasiva real y calibración de heurísticas requieren validación sobre una red física. Aquí se validaron paquetes, sondas y flujos simulados; no se escaneó la red del usuario.
- Se probaron las definiciones del servicio y el proceso sin terminal. No se instaló ni activó ningún servicio del sistema; el escritorio se prueba con transporte sustituido y los webhooks en loopback.
- La primera evaluación de 5.000 dispositivos excede 300 ms. La memoria publicada es RSS muestreada del benchmark, no un pico aislado del servidor.

No se ha publicado, desplegado externamente ni creado un commit. Los cambios previos del usuario permanecen en el árbol de trabajo.
