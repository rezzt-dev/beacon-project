###  BEACON PROJECT  |  EVOLUCION INTEGRAL
> documentación de la evolución que convierte beacon en una aplicación local para descubrir, identificar, comprender y monitorizar la red, sobre la base de la fase cli.
---
####   DOCUMENTOS
| documento | contenido |
|---|---|
| [`seguimiento.md`](seguimiento.md) | estado de cada tarea (pendiente, en curso, verificado, bloqueado). |
| [`decisiones.md`](decisiones.md) | registro de decisiones de arquitectura y riesgos abiertos. |
| [`arquitectura.md`](arquitectura.md) | capas, flujo de un escaneo, concurrencia y estructura de la aplicación live. |
| [`api.md`](api.md) | contrato de la api `/api/v1`, errores, concurrencia y canal en vivo. |
| [`operacion.md`](operacion.md) | arranque, servicio, copias, restauración, retención, alertas y diagnóstico. |
| [`privacidad-y-seguridad.md`](privacidad-y-seguridad.md) | qué datos se guardan, qué sale de la máquina y cómo se protege la aplicación local. |
| [`rendimiento.md`](rendimiento.md) | metodología, equipo, datos sintéticos y resultados medidos frente a la línea base. |
| [`validacion-final.md`](validacion-final.md) | resultado de la continuación, pruebas, distribución, migraciones y límites pendientes. |
| `benchmarks.json` | resultados brutos de `scripts/bench.py`. |
---
####   COMO PROBARLO
```bash
uv sync --group dev --group browser
uv run python -m playwright install chromium     # solo para las pruebas de navegador
uv run pytest -q                                  # todo, incluido el navegador
uv run pytest -q -m "not browser"                 # sin navegador
uv run ruff check app tests scripts
uv run python scripts/bench.py                    # benchmarks sobre datos simulados
```
las pruebas usan red simulada o servicios de loopback y una base temporal: nunca tocan la base real del usuario ni envían paquetes a la red.
