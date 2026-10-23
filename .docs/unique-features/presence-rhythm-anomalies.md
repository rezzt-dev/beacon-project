###  BEACON PROJECT  |  RITMO DE PRESENCIA Y ANOMALIAS
> propuesta de funcionalidad (no implementada). beacon aprende el patrón de presencia de cada dispositivo y avisa de lo que rompe su rutina: un dispositivo que aparece a una hora inusual o uno que siempre está y desaparece.
---
####   1. IDENTIFICACION
| campo | valor |
|---|---|
| nombre | ritmo de presencia y anomalías |
| categoría | monitorización, historial, detección de comportamiento |
| propósito | detectar anomalías por comportamiento temporal, no solo por "desconocido / conocido" |
| prioridad | 3 (media-alta) |
| complejidad | media-alta (≈ 6-9 días): modelo de sesiones, estadística simple, comando de línea temporal |

**resumen ejecutivo.** beacon guarda hoy `first_seen`, `last_seen` y un `status` por dispositivo, y eventos `device-online` / `device-offline`; pero el historial de presencia **no se puede consultar** (no hay forma de saber cuándo estuvo cada dispositivo conectado) y todas las alertas dependen de la confianza. esta funcionalidad convierte los escaneos en **sesiones de presencia**, calcula para cada dispositivo un perfil horario (qué horas y días suele estar) y genera dos nuevas señales: `unusual-presence` (un dispositivo de confianza aparece fuera de su patrón, o uno desconocido aparece de madrugada) y `routine-broken` (un dispositivo casi siempre presente desaparece). añade además `beacon timeline`, una vista de línea temporal en terminal con la presencia de cada dispositivo.

---
####   2. PROBLEMA Y OPORTUNIDAD
**problema.** un dispositivo ya marcado como de confianza puede comportarse de forma anómala (un portátil de oficina que conecta a las 3:00, una cámara que se desconecta durante horas) y beacon no lo notará: la confianza apaga toda la vigilancia sobre él. además, el usuario no puede responder preguntas básicas como "¿cuándo se conectó este equipo la semana pasada?".

**limitaciones actuales (verificadas en el código).**
   - la tabla `devices` guarda solo `first_seen` y `last_seen`; la tabla `scans` guarda contadores, no qué dispositivos se vieron en cada escaneo; la tabla `events` registra transiciones, de las que se podría reconstruir presencia solo de forma aproximada y rota por el periodo de gracia (`--offline-grace`) y por el filtrado de eventos.
   - `WatchView` (`ui/live.py`) muestra el estado actual y los últimos 10 eventos; no hay histórico.
   - `detect_changes` (`core/diff.py`) es una función de comparación entre dos instantes; no tiene memoria.
   - `Repository.stats()` solo ofrece totales.

**necesidades del usuario.** (a) historial consultable de presencia, (b) avisos por comportamiento y no solo por desconocimiento, (c) distinguir lo "raro" de lo habitual sin configurar reglas.

**diferencias frente a alternativas.** las herramientas consultadas durante la auditoría (netalertx y similares) describen alertas de "siempre conectado cae", nuevos dispositivos, reconexiones y cambios de ip, según sus páginas públicas. la propuesta añade **aprendizaje automático del patrón horario sin configuración** y la señal de *aparición fuera de patrón*; esta diferencia se basa solo en la documentación pública revisada, no en pruebas de esas herramientas. la ventaja es una detección útil sin que el usuario defina qué dispositivos "deben estar siempre".

---
####   3. CONCEPTO Y FUNCIONAMIENTO
**principios de diseño.**
   - **sin configuración:** el perfil se deriva de los datos; no se piden listas de horarios.
   - **estadística simple y explicable:** frecuencias por franja horaria, no modelos opacos.
   - **honesto con la falta de datos:** no se generan anomalías hasta tener historial suficiente (periodo de aprendizaje).
   - **barato:** las sesiones se actualizan en la misma transacción de `save_scan`.
   - **respeta la ventana de gracia:** una sesión se cierra con el mismo criterio de offline que ya usa `detect_changes`.

**sesiones de presencia.** una sesión es un intervalo `[start, end)` en el que un dispositivo estuvo online. al guardar un escaneo: si el dispositivo está presente y tiene sesión abierta → se actualiza `last_seen`; si está presente y no tiene sesión → se abre; si pasa a offline (mismo evento `device-offline`) → se cierra con `end = last_seen` del dispositivo, no con la hora del escaneo.

**perfil de presencia.** para cada dispositivo, una rejilla de 7 días × 24 horas con la fracción de semanas observadas en las que estuvo presente en esa celda (o conteo suavizado). se calcula bajo demanda a partir de las sesiones de las últimas N semanas (por defecto 4); no se persiste en una tabla separada.

**señales.**

| señal | cuándo se emite | severidad |
|---|---|---|
| `unusual-presence` | un dispositivo aparece en una celda día/hora donde su frecuencia histórica es < 10 % y el perfil tiene al menos 14 días de datos y 6 sesiones. para dispositivos sin perfil suficiente no se emite. | `warning` (de confianza) / sube a `alert` si además no es de confianza |
| `routine-broken` | un dispositivo con presencia ≥ 90 % en las últimas 2 semanas lleva offline más de `max(3 × su hueco típico, 30 min)` | `warning` |

(**los umbrales son una propuesta inicial**; deben calibrarse con datos reales de varias redes antes de fijarse. el hueco típico es la mediana de duración de las pausas entre sesiones.)

**casos de uso.**
   - *portátil de oficina que conecta a las 3:00 de la madrugada de un domingo:* `unusual-presence` con el texto "`<alias>` suele conectarse entre lunes y viernes de 8 a 19 h; ahora es domingo 03:12".
   - *cámara o nas que dejan de responder:* `routine-broken` tras unos minutos en lugar de esperar a revisar la tabla.
   - *auditoría:* `beacon timeline --since 7d` para ver qué estuvo conectado durante un incidente.

**limitaciones y casos especiales.**
   - la resolución temporal es la del intervalo de `watch` (por defecto 60 s) o de los escaneos manuales; con escaneos esporádicos el perfil es poco fiable, por lo que se exige un mínimo de sesiones.
   - dispositivos con mac aleatorizada rotatoria producen sesiones fragmentadas: depende de `continuous-device-identity.md` para agruparlas por `identity_id`; sin ella, esos dispositivos quedan fuera del análisis (se indica "perfil insuficiente").
   - cambios de hora (dst): las celdas se calculan en la zona horaria local almacenada como utc y convertida al consultar.
   - un dispositivo nuevo no tiene perfil: para él solo aplica la regla de horario inusual de desconocidos (solo si se define una ventana nocturna configurable; ver evolución).

---
####   4. EXPERIENCIA DE USUARIO
**ubicación.** comando nuevo `beacon timeline` (panel `inventory`); sección "presencia" en `beacon devices show`; los nuevos eventos aparecen en `scan`, `watch` y `events` con el mismo formato.

**componentes visuales.**
   - **línea temporal:** una fila por dispositivo y una columna por intervalo de tiempo (24 h en pasos de 30 min por defecto, ajustable), usando caracteres de bloque (`█` presente, `·` ausente, `▒` parcial) coloreados con los estilos `ok` / `muted`. se dibuja con `rich.table.Table`, como el resto de tablas de `ui/render.py`.
   - **mapa de calor semanal** en `devices show`: 7 filas × 24 columnas con la intensidad del perfil, para ver el patrón del dispositivo.
   - los eventos nuevos usan `SEVERITY_STYLE` existente, sin estilos nuevos.

**estados.**
   - *vacío:* "aún no hay suficiente historial (necesita 14 días y 6 sesiones)" en `muted`, con el avance actual.
   - *carga:* consulta local en sqlite; sin progreso.
   - *error:* argumentos de rango inválidos (`--since 99x`) devuelven `typer.BadParameter` con el formato esperado.
   - *éxito:* tabla o mapa renderizados; `--json` devuelve las sesiones.
   - *deshabilitado:* `--no-presence` en `scan`/`watch` evita escribir sesiones y emitir señales.

**accesibilidad.** la presencia se codifica con forma (`█` / `·`) además de color, de modo que es legible sin color; el ancho se adapta al terminal usando la misma idea que `visible_columns` (reducir franjas por columna si el terminal es estrecho).

**interacción.** `beacon timeline [--since 24h|7d] [--device REF] [--online-only] [--json]`.

---
####   5. ARQUITECTURA E IMPLEMENTACION
**dependencias.** ninguna nueva; la estadística usa la librería estándar (`statistics`, ya importada en `core/models.py`).

**archivos nuevos.**
   - `app/beacon/core/presence.py`: `Session` (`dataclass(slots=True)`), `PresenceProfile`, `build_profile(sessions, now)`, `detect_anomalies(profiles, current, now) -> list[Event]`. puro y sin acceso a red ni base de datos.
   - `app/beacon/cli/commands/timeline.py`: comando `timeline`.
   - `tests/test_presence.py`, `tests/test_timeline.py`.

**archivos existentes a modificar.**
   - `app/beacon/storage/database.py`: migración con la tabla `sessions` (ver abajo).
   - `app/beacon/storage/repository.py`: `save_scan` abre/actualiza/cierra sesiones dentro de la **misma transacción** existente; `list_sessions(device_key, since)`, y borrado en cascada con el dispositivo.
   - `app/beacon/core/events.py`: `EventType.UNUSUAL_PRESENCE`, `EventType.ROUTINE_BROKEN`.
   - `app/beacon/pipeline.py`: tras `detect_changes`, cargar perfiles del repositorio, llamar a `detect_anomalies` y añadir sus eventos a `report.events` antes de `save_scan`.
   - `app/beacon/cli/main.py`: registrar `timeline`.
   - `app/beacon/ui/render.py`: `timeline_table()` y `presence_heatmap()`.
   - `app/beacon/cli/commands/devices.py`: sección de presencia en `show`.

**modelo de datos (migración propuesta).**
```sql
CREATE TABLE sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_key TEXT NOT NULL REFERENCES devices (key) ON DELETE CASCADE,
  started_at TEXT NOT NULL,
  ended_at   TEXT,            -- NULL = sesión abierta
  last_seen  TEXT NOT NULL
);
CREATE INDEX idx_sessions_device ON sessions (device_key, started_at);
```
volumen: un dispositivo con 10 conexiones al día genera ~3.600 filas al año; no hay problema para sqlite. política de retención: `beacon prune --sessions-older-than 365d` (propuesto) o un límite configurable.

**flujo de datos.** `ScanPipeline.run` → `detect_changes` (eventos de transición) → `Repository.list_sessions` → `build_profile` → `detect_anomalies` → eventos añadidos al informe → `save_scan` persiste devices + sessions + events atómicamente → `EventBus`.

**gestión del estado.** el estado vive en sqlite; `watch` no mantiene perfiles en memoria entre ciclos para evitar divergencias.

**seguridad.** solo metadatos locales de presencia; la exportación de sesiones se hace con `--json`/`export` y se documenta como dato personal (revela hábitos de personas): no se incluye en exportaciones por defecto.

**rendimiento.** los perfiles se calculan solo para dispositivos presentes o que cambian de estado, con índice por `(device_key, started_at)`; cada escaneo hace O(dispositivos) consultas acotadas a 4 semanas.

**compatibilidad.** aditiva; sin sesiones previas, el sistema funciona como hoy y entra en periodo de aprendizaje.

---
####   6. PLAN DE DESARROLLO
| fase | tareas | depende de |
|---|---|---|
| 1. sesiones | migración, apertura/cierre en `save_scan`, tests de atomicidad y de gracia | — |
| 2. consulta | `list_sessions`, `beacon timeline`, `--json` | 1 |
| 3. perfil | `core/presence.py` (`build_profile`) con tests de rejilla, zonas horarias y dst | 1 |
| 4. señales | `detect_anomalies`, integración en `pipeline.py`, eventos | 3 |
| 5. ui | mapa de calor en `devices show` | 3 |
| 6. documentación | `persistencia-y-eventos.md`, `comandos.md`, `changelog.md` | todas |

**recomendación de calendario:** la fase 1 puede adelantarse a las demás funcionalidades, porque **los datos no se pueden reconstruir hacia atrás**: cuanto antes empiece a guardar sesiones, antes habrá perfil útil.

**riesgos y mitigación.**
   - *falsas anomalías por escaneos irregulares:* umbral mínimo de sesiones, cierre de sesión coherente con la gracia, y desactivación por `--no-presence`.
   - *crecimiento de la tabla:* índice y política de retención.
   - *dependencia de identidad estable:* los dispositivos aleatorizados sin vínculo se excluyen explícitamente.
   - *privacidad:* datos de hábitos solo locales y excluidos de exportaciones por defecto.

**pruebas necesarias.** apertura/cierre de sesión en escaneos consecutivos; cierre con `last_seen` y no con el instante del escaneo; no se abre sesión dos veces; perfil con datos sintéticos de 4 semanas; sin anomalías con historial insuficiente; `unusual-presence` y `routine-broken` con casos positivos y negativos; zona horaria y dst; consulta `timeline --json`; migración sobre base existente.

**criterios de aceptación verificables.**
   1. tras simular con `now` inyectado 5 semanas de presencia diaria de 9 a 18 h, un escaneo un domingo a las 3:00 emite `unusual-presence` y el mismo escaneo en horario normal no.
   2. con menos de 14 días de datos no se emite ninguna anomalía y `timeline` informa del avance del aprendizaje.
   3. `save_scan` sigue siendo atómico: un fallo a mitad no deja sesiones a medio crear (se amplía la prueba de atomicidad de `tests/test_storage.py`).
   4. `beacon timeline --since 24h --json` devuelve las sesiones con fechas iso.
   5. `uv run pytest` y `uv run ruff check app tests` pasan.

**terminada cuando** los criterios pasan, se documentan los umbrales y la retención, y el comportamiento de privacidad queda reflejado en el readme.

---
####   7. EVOLUCION FUTURA
   - ventana nocturna configurable para desconocidos (`beacon.toml`) y perfiles por grupo de dispositivos.
   - correlación entre dispositivos: "el móvil de ana llega y el portátil de oficina se enciende" para inferir presencia de personas, apoyada en `continuous-device-identity.md`.
   - panel de línea temporal en la futura tui con `textual`.
   - exportación de la línea temporal al informe html (`export/html_export.py`) como mapa de calor autocontenido.
   - integración con `guided-triage-and-risk-score.md`: la anomalía de horario como factor del riesgo.
