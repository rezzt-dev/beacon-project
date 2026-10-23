###  BEACON PROJECT  |  PRUEBAS Y CALIDAD
> cómo se verifica el proyecto: tests automáticos, lint y pruebas manuales sobre una red real.
---
####   EJECUCION
```bash
uv sync                          # instala también el grupo dev (pytest, ruff)
uv run pytest                    # 227 tests, ~1 segundo, sin acceso a red
uv run ruff check app tests      # lint (pyflakes, pycodestyle, isort, bugbear, pyupgrade, simplify)
```
la configuración está en `pyproject.toml`: `pythonpath = ["app"]` para pytest y sangría de 2 espacios para ruff, igual que el resto del código.
---
####   COBERTURA POR AREA
| fichero | qué cubre |
|---|---|
| `tests/test_mac.py` | normalización de todas las notaciones de mac, multicast/broadcast y detección de macs aleatorizadas. |
| `tests/test_engine.py` | fusión por mac, ip principal, dispositivos sin mac, filtrado de ips, confirmación de caché antigua, conflictos de ip, limpieza de hostnames y banners, estadísticas de latencia. |
| `tests/test_diff.py` | todos los tipos de evento, severidades, periodo de gracia, redes no escaneadas y eventos de puertos solo cuando se escanean; primer escaneo como línea base (avisos, alerta solo con riesgo alto) y `identity-candidate`. |
| `tests/test_risk.py` | cada factor de la puntuación, tope en 100, niveles, exención del equipo local y la puerta de enlace, puertos sin escanear y `events_at_risk`. |
| `tests/test_identity.py` | normalización de hostnames, puntuación por rasgo y combinada con evidencias, nombres genéricos, candidatos únicos frente a ambiguos y pares guardados que nunca coincidieron en el tiempo. |
| `tests/test_presence.py` | rejilla semanal con zonas horarias (incluida una de media hora), historial insuficiente, `unusual-presence` y `routine-broken` en casos positivos y negativos, y celdas de la línea temporal. |
| `tests/test_services.py` | `parse_ptr_records` con compresión y paquetes truncados, saneado de servicios y descubrimiento contra un servidor udp local (respuesta, silencio y basura). |
| `tests/test_pipeline.py` | escaneos completos con la red simulada: primer escaneo sin alertas, móvil que vuelve con otra mac, `--no-identity`, anomalías de presencia con el reloj inyectado, `--no-presence` y `routine-broken` una sola vez. |
| `tests/test_review.py` | `review` en lista, json, `--trust-below` y modo interactivo con teclas simuladas (cada acción solo toca su dispositivo), fin de entrada, sin terminal y `events --pending`. |
| `tests/test_timeline.py` | `timeline` vacío, rangos inválidos, filas con formas, json con fechas iso, filtros, identidad con una sola fila y `prune`. |
| `tests/test_devices_cli.py` | `candidates`, `link` (confianza no heredada), `unlink`, `show` con identidad y presencia, `list --risk` y huella fuera de las exportaciones. |
| `tests/test_vendors.py` | búsqueda oui por prefijo más largo (`/24`, `/28`, `/36`), líneas mal formadas, fallback vacío y estimación de so por ttl. |
| `tests/test_scanners.py` | parsers de `ip neigh`, `/proc/net/arp`, `arp -a` (macos y windows) y `/proc/net/route`; paquetes icmp; dns/mdns con compresión y bucles de punteros; netbios `NBSTAT`; especificación de puertos; escaneo real contra un servidor tcp local con banner. |
| `tests/test_storage.py` | migraciones (incluida la v1 → v4 conservando datos) y rechazo de esquemas futuros, ida y vuelta de dispositivos, sincronización de puertos, conservación de alias y confianza, cambios a offline, búsqueda por referencia, filtros de eventos, estadísticas, eventos revisados, vínculos de identidad, sesiones de presencia (apertura, cierre con `last_seen`, huecos largos, retención) y atomicidad de `save_scan`. |
| `tests/test_export.py` | detección de formato, json válido sin ficheros temporales residuales, protección contra inyección en csv y escape en html. |
| `tests/test_ui.py` | columnas responsive de la tabla de dispositivos (ip y mac nunca truncadas, columna de riesgo opcional), vista de `watch` tras un escaneo fallido, riesgo escrito con texto, marca de identidad, mapa de calor y línea temporal. |
| `tests/test_cli.py` | `--version`, inventario vacío, referencia inexistente, búsqueda de fabricantes, exportación y validación de puertos, con un `BEACON_HOME` temporal. |
---
####   VERIFICACION MANUAL
además de los tests, se validó la cli contra una red doméstica `/24` real en modo sin privilegios (linux, wi-fi):
   - `beacon scan`: 13-15 dispositivos en 5-8 segundos, con fabricantes, dos macs aleatorizadas, un hostname por mdns y la puerta de enlace marcada.
   - `beacon scan -p top`: puertos y banners http (`HTTP/1.0 307 Temporary Redirect | server: ...`).
   - flujo de confianza: `trust-all`, alias, segundo escaneo con alerta solo para el dispositivo que no estaba en la línea base.
   - `beacon watch -o vivo.html`: tabla en vivo, eventos offline/online y html con autorrefresco.
   - `beacon ports`, `beacon ping` (icmp con ttl), `beacon events` con filtros, `export` en los tres formatos y `--json`.
   - python 3.13 y 3.14.
   - funciones únicas (red `/24` real, sin privilegios): el primer `beacon scan --fail-on-alert` termina con `0` y 11 avisos en lugar de 11 alertas; `beacon review --list` ordena por riesgo con motivos; `beacon scan --fail-on-risk 55` termina con `0` al aparecer dos dispositivos medios; `beacon timeline` y `beacon devices list --risk` se renderizan sin truncar ip ni mac. **no verificado en vivo:** el reconocimiento de un móvil que vuelve con otra mac (ningún dispositivo respondió a la consulta de servicios mdns), por lo que está probado con redes simuladas y no con dispositivos reales.

el modo privilegiado (barrido arp con scapy) no se ha probado en vivo en esta fase porque requiere root; su código se limita a la llamada `srp` y comparte todo el procesado posterior con el modo sin privilegios.
---
