###  BEACON PROJECT  |  TRIAGE GUIADO Y PUNTUACION DE RIESGO
> propuesta de funcionalidad (no implementada). convierte el flujo de alertas de beacon en un proceso de revisión explicado, priorizado y accionable desde un único comando: `beacon review`.
---
####   1. IDENTIFICACION
| campo | valor |
|---|---|
| nombre | triage guiado y puntuación de riesgo (`beacon review`) |
| categoría | experiencia de usuario, seguridad, flujo de alertas |
| propósito | pasar de "hay 13 alertas" a "estos 2 dispositivos merecen atención y este es el motivo" |
| prioridad | **1 (alta): implementar primero** |
| complejidad | media (≈ 4-6 días): lógica pura nueva, una migración y un comando interactivo |

**resumen ejecutivo.** hoy cada dispositivo desconocido genera una alerta `new-device` con la misma severidad, y el primer escaneo de una red genera una alerta por cada host (en la verificación de esta auditoría: 13 alertas en un `/24` doméstico). el usuario debe ejecutar `devices trust-all` a ciegas o confiar uno a uno con referencias manuales. esta funcionalidad añade (1) una puntuación de riesgo **explicable** por dispositivo, calculada con datos que beacon ya recoge, y (2) un asistente `beacon review` que recorre los dispositivos pendientes de revisar mostrando el motivo del riesgo, sugiriendo un alias y permitiendo confiar, ignorar u olvidar con una tecla.

---
####   2. PROBLEMA Y OPORTUNIDAD
**problema.** las alertas de beacon son binarias (desconocido / conocido) y no priorizan. un móvil con mac aleatorizada y ningún puerto abierto se trata igual que una cámara con `telnet` abierto.

**limitaciones actuales (verificadas en el código).**
   - `core/diff.py` emite `new-device` siempre con `Severity.ALERT` para cualquier dispositivo no local, sin considerar puertos, fabricante ni tipo de mac.
   - `ScanReport.first_run` solo cambia un mensaje en `cli/commands/scan.py`; el primer escaneo con `--fail-on-alert` termina con código 3 aunque no haya nada anómalo.
   - la única vía para "calmar" alertas es `devices trust` / `trust-all` (`cli/commands/devices.py`). no existe el concepto de **alerta revisada**: la tabla `events` no tiene estado, así que `beacon events` mezcla lo nuevo con lo ya atendido.
   - `devices trust-all` obliga a confiar en todo o en nada.

**necesidades del usuario.** (a) establecer una línea base fiable sin confiar a ciegas, (b) saber *por qué* algo es sospechoso, (c) no volver a ver alertas ya atendidas, (d) poder automatizar el proceso en cron/ci sin falsos positivos del primer día.

**diferencias frente a alternativas.** las herramientas de monitorización de red de código abierto que se consultaron durante la auditoría (netalertx, watchyourlan) y las apps comerciales como fing notifican dispositivos nuevos y cambios, según sus páginas públicas, pero en la información revisada no se documenta una puntuación de riesgo con motivos legibles ni un asistente de revisión por terminal; esta comparación se basó solo en las descripciones públicas de esos proyectos y **no se verificó instalando ni probando** ninguna de ellas. el valor diferencial propuesto es que la explicación se deriva de las mismas observaciones que beacon ya almacena (puertos, mac aleatorizada, fabricante, antigüedad) y funciona offline y sin servicios externos.

---
####   3. CONCEPTO Y FUNCIONAMIENTO
**principios de diseño.**
   - **explicable antes que preciso:** cada punto de riesgo tiene un motivo en texto; no hay "caja negra" ni modelos entrenados.
   - **determinista y pura:** `assess(device)` no toca red ni base de datos, igual que `detect_changes`; se prueba sin sockets.
   - **no cambia la semántica de eventos existente:** la puntuación *enriquece* los eventos, no reemplaza `Severity`.
   - **el usuario decide:** beacon sugiere, nunca confía automáticamente.

**modelo de puntuación (propuesta inicial, ajustable en una tabla constante).** puntuación 0-100, suma acotada de factores:

| factor | puntos | fuente en beacon |
|---|---|---|
| dispositivo sin confianza (`trusted = False`) | +30 | `Device.trusted` |
| fabricante desconocido y mac no aleatorizada | +10 | `Device.vendor`, `randomized_mac` |
| puerto de administración remota expuesto (23, 3389, 5900, 445, 139, 5985/5986) | +25 el más grave, +5 cada extra | `Device.open_ports` |
| puerto de ssh/telnet/ftp/ rtsp/ http sin cifrar (22, 21, 554, 80) | +10 | `Device.open_ports` |
| puerto abierto nuevo desde la línea base | +15 | evento `port-opened` |
| visto por primera vez hace menos de 24 h | +10 | `Device.first_seen` |
| conflicto de ip implicado | +40 | `IpConflict` |
| `is_local` o `is_gateway` | fuerza 0 (no se evalúa) | `Device` |

niveles: `low` (< 25), `medium` (25-54), `high` (≥ 55). la lista de puertos y los pesos viven en un único diccionario en `core/risk.py` para ajustarlos sin tocar la lógica. **estos números son una propuesta de partida; deben calibrarse con redes reales antes de darlos por buenos.**

**flujo de `beacon review`.**
   1. carga los eventos `alert` y `warning` sin revisar (`acked_at IS NULL`) y los agrupa por dispositivo.
   2. ordena por riesgo descendente y muestra una tarjeta por dispositivo: ip, mac, fabricante, puertos, motivos del riesgo y un alias sugerido (hostname limpio, o `fabricante-últimoctetoip`).
   3. acciones de una tecla: `t` confiar, `a` confiar con alias (pregunta el alias con el sugerido por defecto), `i` ignorar (marca revisado sin confiar), `f` olvidar, `s` saltar, `q` salir.
   4. al terminar, resume: confiados, ignorados, pendientes.

**modos no interactivos.**
   - `beacon review --list [--json]`: tabla de pendientes con riesgo y motivos.
   - `beacon review --trust-below low --yes`: confía en los dispositivos de riesgo `low` (ver limitaciones); pide confirmación salvo `--yes`.
   - `beacon scan --fail-on-risk <n>`: variante de `--fail-on-alert` que solo falla si algún evento afecta a un dispositivo con riesgo ≥ n. `--fail-on-alert` conserva su comportamiento.

**casos de uso.**
   - *primer escaneo:* 14 dispositivos, 13 sin confianza. `review` muestra 11 de riesgo `low` (móviles aleatorizados, tv, impresora sin servicios) y 2 `medium`; el usuario confía en bloque los `low` y revisa los otros dos con calma.
   - *intruso:* aparece un host sin fabricante con `3389` abierto: riesgo `high`, motivos "no es de confianza · fabricante desconocido · escritorio remoto expuesto (3389) · visto hace 3 min".
   - *cron:* `beacon scan --fail-on-risk 55` falla solo ante dispositivos de riesgo alto.

**limitaciones y casos especiales.**
   - sin `--ports` no hay datos de puertos: el riesgo se calcula con lo disponible y la tarjeta indica "puertos no escaneados" en lugar de asumir cero.
   - la confianza masiva por riesgo bajo reduce la seguridad si la red ya estaba comprometida en el primer escaneo; por eso `--trust-below` exige confirmación y no existe como opción de `scan`.
   - un dispositivo "olvidado" reaparece como nuevo (comportamiento actual de `forget`).

---
####   4. EXPERIENCIA DE USUARIO
**ubicación.** nuevo comando de primer nivel `review` en el panel `inventory` de la ayuda (`cli/main.py`). el aviso del primer escaneo en `cli/commands/scan.py` pasa de sugerir `trust-all` a sugerir `beacon review`.

**componentes visuales (todos con `rich`, estilos del tema actual en `ui/console.py`).**
   - tarjeta de dispositivo: `Panel` con la rejilla de `device_detail` reutilizada y una línea `riesgo` coloreada con los estilos existentes (`ok` / `warning` / `alert`).
   - indicador de riesgo: `●` con el mismo criterio cromático que `status_marker`, más el valor numérico.
   - barra de progreso `n/total` en el título de la tarjeta.
   - la tabla de dispositivos (`ui/render.py`) añade una columna `risk` opcional dentro del sistema de columnas responsive ya existente (`visible_columns`), la primera en desaparecer en terminales estrechas tras `last seen`.

**estados.**
   - *vacío:* "nada pendiente de revisar" en estilo `muted` y código de salida 0.
   - *carga:* ninguna operación de red; la revisión es instantánea.
   - *error:* si la entrada no es un terminal (no tty) y no se pasó `--list`, error claro con la sugerencia `use --list or --json`, código 2.
   - *éxito:* línea `✓` con `success()` por cada acción y resumen final.
   - *deshabilitado:* la acción `a` queda sin efecto si el alias introducido está vacío (se trata como `t`).

**interacción y accesibilidad.** lectura de teclas con `click.getchar()` (`click` ya es dependencia transitiva de `typer`); cada opción se muestra como texto (`[t]rust`), no solo por color; `ctrl+c` sale limpiamente sin perder lo ya aplicado porque cada acción se confirma en base de datos al momento.

---
####   5. ARQUITECTURA E IMPLEMENTACION
**dependencias.** ninguna nueva.

**archivos nuevos.**
   - `app/beacon/core/risk.py`: `RiskLevel` (`StrEnum`), `RiskReason` y `RiskAssessment` (`dataclass(slots=True)`), `assess(device, events=()) -> RiskAssessment`, `suggest_alias(device) -> str`. sin imports de red, sqlite ni rich (misma regla que el resto de `core/`).
   - `app/beacon/cli/commands/review.py`: comando `review`.
   - `tests/test_risk.py`, `tests/test_review.py`.

**archivos existentes a modificar.**
   - `app/beacon/storage/database.py`: añadir una segunda entrada a `MIGRATIONS` con `ALTER TABLE events ADD COLUMN acked_at TEXT;` y un índice parcial `idx_events_pending ON events (severity) WHERE acked_at IS NULL`. el mecanismo `PRAGMA user_version` ya aplica la migración de forma transaccional.
   - `app/beacon/storage/repository.py`: `list_pending_events()`, `ack_events(device_key)`, y que `list_events` acepte `pending_only`. `Event` necesita un campo opcional `id`/`acked` o se devuelve una estructura aparte para no romper el `dataclass` frozen actual.
   - `app/beacon/cli/main.py`: registrar `review.review` con `rich_help_panel="inventory"`.
   - `app/beacon/cli/commands/scan.py`: nueva opción `--fail-on-risk`; mensaje del primer escaneo.
   - `app/beacon/cli/commands/inventory.py`: `events --pending`.
   - `app/beacon/ui/render.py`: `risk_text(assessment)`, columna opcional y línea de riesgo en `device_detail`.
   - `app/beacon/export/*`: incluir `risk` y `risk_reasons` en `Device.to_dict()` solo si se calcula (no almacenar el riesgo: se deriva siempre del estado actual, así no queda obsoleto).

**modelo de datos.** el riesgo **no se persiste**; se calcula al vuelo desde `Device`. solo se persiste `events.acked_at`. esto evita estados inconsistentes cuando cambia la confianza o los puertos.

**flujo de datos.** `Repository.list_pending_events()` → agrupar por `device_key` → `Repository.load_devices()` → `assess()` → tarjeta → acción → `set_trusted` / `set_alias` / `delete_device` + `ack_events(device_key)`.

**seguridad.** el alias introducido se limpia con `strip()` como en `devices alias`; nunca se interpreta como markup de rich (usar `Text`, no f-strings con corchetes). las acciones masivas piden confirmación.

**rendimiento.** `load_devices()` ya carga todo el inventario; para cientos de dispositivos el coste es despreciable. si creciera, filtrar por las claves pendientes.

**compatibilidad.** la migración es aditiva; versiones antiguas de beacon se niegan a abrir una base más nueva (comportamiento ya implementado), lo que se debe anotar en `changelog.md`.

---
####   6. PLAN DE DESARROLLO
| fase | tareas | depende de |
|---|---|---|
| 1. núcleo | `core/risk.py` con tabla de pesos y `suggest_alias`; tests unitarios | — |
| 2. persistencia | migración 2, métodos del repositorio, tests de migración y de ack | — |
| 3. presentación | `risk_text`, línea en `device_detail`, columna opcional en `devices_table` | 1 |
| 4. comando | `review` interactivo, `--list`, `--json`, `--trust-below` | 1, 2, 3 |
| 5. integración | `--fail-on-risk`, mensaje del primer escaneo, `events --pending` | 1, 2 |
| 6. documentación | `comandos.md`, `persistencia-y-eventos.md`, `changelog.md`, readme | todas |

**riesgos y mitigación.**
   - *pesos arbitrarios:* tabla única y documentada; los tests fijan casos de referencia, no valores exactos de cada peso.
   - *falsa sensación de seguridad con riesgo `low`:* texto de la tarjeta indica que es una heurística; `--trust-below` pide confirmación.
   - *interactividad difícil de probar:* aislar la lógica de decisión en una función pura `apply_action(repo, device, action)` y probar el bucle con `CliRunner(input=...)`.

**pruebas necesarias.** puntuación por factor y combinada, acotado a 100, dispositivo local y gateway exentos, puertos no escaneados; migración 1→2 sobre una base con datos; `ack_events` idempotente; `review --list --json` válido; flujo interactivo con entrada simulada para `t`, `a`, `i`, `f`, `s`, `q`; no-tty sin `--list`.

**criterios de aceptación verificables.**
   1. con una base de 14 dispositivos sin confianza, `beacon review --list` los ordena por riesgo y muestra al menos un motivo por cada uno de riesgo > 0.
   2. tras confiar o ignorar un dispositivo, `beacon review --list` ya no lo muestra y `beacon events --pending` tampoco.
   3. `beacon scan --fail-on-risk 55` devuelve 3 solo cuando hay un evento sobre un dispositivo de riesgo alto.
   4. `uv run pytest` y `uv run ruff check app tests` pasan; la migración desde una base v1 real conserva todos los datos.
   5. ninguna acción de `review` modifica dispositivos que el usuario no eligió.

**terminada cuando** los criterios anteriores pasan, la documentación de `.docs/project-info/cli-base/` y `changelog.md` está actualizada y la tabla de pesos está documentada.

---
####   7. EVOLUCION FUTURA
   - pesos configurables en `beacon.toml` (ya previsto en `estado-y-siguientes-pasos.md`).
   - la misma tarjeta como panel de detalle en la futura tui con `textual`.
   - reglas de riesgo por clase de dispositivo cuando exista la identidad continua (ver `continuous-device-identity.md`).
   - notificaciones filtradas por nivel de riesgo como suscriptores del `EventBus`.
   - factor de "hora inusual" aprovechando `presence-rhythm-anomalies.md`.
