###  BEACON PROJECT  |  PERSISTENCIA Y EVENTOS
> cómo se guarda el estado en sqlite, qué eventos se generan y cómo se detectan los cambios entre escaneos.
---
####   BASE DE DATOS
ficheros: `storage/database.py` (conexión y migraciones) y `storage/repository.py` (todo el sql).
   - sqlite con `foreign_keys` activado y modo `WAL` (lecturas concurrentes mientras `watch` escribe).
   - **migraciones versionadas** con `PRAGMA user_version`: cada entrada de `MIGRATIONS` sube una versión y se aplica en una transacción junto con el cambio de versión. si la base es más nueva que el programa, beacon se niega a abrirla. una base creada con esta versión no se puede abrir con builds anteriores.
   - `save_scan` guarda escaneo, dispositivos, puertos, sesiones de presencia, cambios a offline y eventos en **una única transacción**: o se guarda todo o nada.

| versión | cambio |
|---|---|
| 1 | tablas `devices`, `ports`, `scans` y `events`. |
| 2 | `events.acked_at` (evento revisado) e índice parcial de pendientes. |
| 3 | `devices.services`, `devices.identity_id` y tabla `identities`. |
| 4 | tabla `sessions` (presencia). |

| tabla | contenido |
|---|---|
| `devices` | un registro por dispositivo (clave = mac o `ip:<dirección>`): ips, hostname y su fuente, fabricante, mac aleatorizada, ttl, so estimado, alias, confianza, estado, latencia (json), servicios mdns (json), `identity_id`, `first_seen` y `last_seen`. |
| `identities` | una fila por dispositivo físico que usó varias macs aleatorizadas. se borra sola cuando le queda una única mac. |
| `sessions` | una fila por estancia continua de un dispositivo: `started_at`, `last_seen` y `ended_at` (vacío mientras sigue abierta). se borran con el dispositivo. |
| `ports` | puertos abiertos por dispositivo con servicio, banner, `first_seen` y `last_seen`. se borran en cascada con el dispositivo. |
| `scans` | un registro por escaneo: red, interfaz, modo, si se escanearon puertos y contadores. |
| `events` | historial de eventos con severidad, mensaje y detalles (json). se conservan aunque se olvide el dispositivo. `acked_at` marca los ya revisados. |

al actualizar un dispositivo existente, los campos que el escaneo no consiguió (hostname, ttl, fabricante, latencia) conservan su valor anterior; el alias y la confianza solo los cambia la cli. los puertos solo se sincronizan cuando el escaneo incluyó `--ports`.
---
####   TIPOS DE EVENTO
fichero: `core/events.py`.

| evento | severidad | cuándo |
|---|---|---|
| `new-device` | `alert` / `warning` | aparece un dispositivo que nunca se había visto. en el **primer escaneo** (inventario vacío) es `warning` y solo `alert` si el dispositivo sale con riesgo alto. el propio equipo se registra como `info` y como de confianza. |
| `device-online` | `info` / `warning` | vuelve un dispositivo que estaba offline (`warning` si no es de confianza). |
| `device-offline` | `info` | un dispositivo que estaba online deja de verse durante más tiempo que el periodo de gracia. |
| `ip-changed` | `info` | un dispositivo conocido aparece con otra ip. |
| `port-opened` | `warning` | aparece un puerto abierto nuevo en un dispositivo conocido. |
| `port-closed` | `info` | un puerto que estaba abierto deja de estarlo. |
| `ip-conflict` | `alert` | una ip responde desde varias macs (posible arp spoofing). |
| `identity-candidate` | `warning` | una mac aleatorizada nueva parece un dispositivo conocido que acaba de desaparecer. sustituye al `new-device` de ese dispositivo (ver identidad). |
| `unusual-presence` | `warning` / `alert` | un dispositivo vuelve a una hora en la que casi nunca está (`alert` si no es de confianza). |
| `routine-broken` | `warning` | un dispositivo casi siempre presente lleva ausente demasiado tiempo. |
---
####   DETECCION DE CAMBIOS
fichero: `core/diff.py` (`detect_changes`), función pura y probada sin red.
   - compara el inventario guardado con el resultado limpio del escaneo actual.
   - los eventos de puertos solo se generan si el escaneo incluyó puertos, para no confundir "no escaneado" con "cerrado".
   - un dispositivo fuera de la red escaneada nunca se marca offline: escanear otra subred no altera el resto del inventario.
   - **periodo de gracia (`--offline-grace`):** un dispositivo ausente durante menos tiempo que la gracia sigue considerándose online. evita eventos que "parpadean" con móviles en ahorro de energía, que ignoran sondas de vez en cuando. en `watch` vale por defecto dos intervalos; en `scan`, cero.
---
####   CONFIANZA Y ALERTAS
   - un dispositivo es "conocido" cuando está marcado como de confianza (`trusted`). los nuevos nunca lo están, salvo el propio equipo.
   - el flujo recomendado es: primer escaneo → `beacon review` (o `beacon devices trust-all` si se conoce toda la red) → a partir de ahí, cada desconocido genera una alerta.
   - en la tabla, ● verde indica de confianza online, ● rojo sin confianza online y ○ offline.
---
####   REVISION DE EVENTOS Y RIESGO
ficheros: `core/risk.py`, `cli/commands/review.py` y la columna `events.acked_at`.
   - un evento está **pendiente** si es `warning` o `alert`, pertenece a un dispositivo y no tiene `acked_at`. los `ip-conflict` no tienen dispositivo y quedan solo en el historial.
   - confiar en un dispositivo (`trust`, `trust-all`, `review`), olvidarlo o ignorarlo en `review` marca sus eventos como revisados. `ack_events` es idempotente y nunca borra eventos.
   - **puntuación de riesgo** (0-100, `assess`): función pura que suma factores con motivo en texto. no se guarda: se calcula siempre del estado actual. el local y la puerta de enlace quedan exentos (0).

| factor | puntos |
|---|---|
| sin confianza | 30 |
| fabricante desconocido y mac no aleatorizada | 10 |
| puerto de administración remota expuesto (23, 3389, 5900, 445, 139, 5985, 5986) | 25 el más grave, +5 cada extra |
| ssh, ftp, rtsp o http sin cifrar (22, 21, 554, 80) | 10 |
| puerto abierto nuevo sin revisar | 15 |
| visto por primera vez hace menos de 24 h | 10 |
| implicado en un conflicto de ip | 40 |

   - niveles: `low` (< 25), `medium` (25-54), `high` (≥ 55). los pesos viven en un único diccionario (`POINTS`) y son una propuesta de partida: calibrar con redes reales.
   - si ningún escaneo incluyó puertos (`--ports`) el riesgo se calcula con lo disponible y se indica "ports not scanned" en lugar de asumir que no hay puertos abiertos.
---
####   IDENTIDAD CONTINUA
ficheros: `core/identity.py`, `scanners/services.py` y las tablas `identities`/`devices`.
   - la mac sigue siendo la clave; la identidad (`identity_id`) agrupa varias claves del mismo dispositivo físico.
   - **huella:** hostname normalizado (sin dominio ni sufijos `-2`, `(2)`; los genéricos como `android` no cuentan), servicios mdns anunciados (`_services._dns-sd._udp.local`, consulta unicast y sin privilegios), puertos abiertos, familia de ttl y red `/24`.
   - **puntuación:** hostname 0,55 · servicios hasta 0,25 (jaccard) · puertos idénticos 0,10 · ttl 0,05 · red 0,05. `≥ 0,80` es vínculo **probable**, `0,50-0,79` **posible**. ttl y red nunca bastan por sí solos.
   - solo se compara una mac aleatorizada nueva con las aleatorizadas que **desaparecen en ese mismo escaneo**: dos dispositivos online a la vez no pueden ser el mismo. si el mejor candidato no supera al segundo en 0,15 o dos nuevos apuntan al mismo, no se propone nada y se mantiene el `new-device` de siempre.
   - `devices candidates` recalcula sobre el inventario guardado (la nueva mac debe haber aparecido después de la última vez que se vio la antigua) y también lista los vínculos *posibles*.
   - `devices link` copia el alias a la mac sin alias, marca revisados sus eventos y **no hereda la confianza**: un hostname se puede suplantar. `devices unlink` lo deshace.
   - las respuestas mdns no son de fiar: se limitan a 32 servicios con formato `_nombre._tcp|udp`. la huella solo se exporta con `--include-fingerprint`.
   - los pesos y umbrales son una hipótesis inicial. no se han calibrado con capturas reales de varios móviles (ver `estado-y-siguientes-pasos.md`).
---
####   PRESENCIA
ficheros: `core/presence.py`, `Repository._record_sessions` y `cli/commands/timeline.py`.
   - **sesiones:** en cada `save_scan`, un dispositivo presente extiende su sesión abierta o abre una; un `device-offline` la cierra con `ended_at = last_seen` (la última vez visto, no la hora del escaneo), de modo que respeta el periodo de gracia. si pasa más de `SESSION_GAP` (15 min; `3 × interval` en `watch`) entre dos escaneos, se cierra la sesión y se abre otra en vez de dar por buena una estancia que nadie vigiló.
   - **perfil:** rejilla de 7 días × 24 horas con la fracción de semanas en que el dispositivo estuvo presente en cada celda, sobre las últimas 4 semanas, en hora local (convertida desde utc al consultar). se calcula bajo demanda, no se guarda.
   - **`unusual-presence`:** un dispositivo vuelve en una celda con frecuencia histórica < 10 %. exige perfil *listo*: ≥ 14 días de historia y ≥ 6 sesiones.
   - **`routine-broken`:** un dispositivo presente ≥ 90 % de los últimos 14 días lleva ausente más de `max(3 × hueco típico, 30 min)` y menos de 7 días. basta con 14 días de historia (un dispositivo que nunca se va tiene una sola sesión). se emite una vez por ausencia.
   - los dispositivos con mac aleatorizada sin identidad quedan fuera del análisis (sus sesiones están fragmentadas); los vinculados comparten historial.
   - **privacidad:** las sesiones revelan hábitos de personas. se guardan solo en la base local, no se incluyen en las exportaciones y se pueden borrar con `beacon prune --sessions-older-than`. `--no-presence` evita guardarlas. volumen aproximado: unas 3.600 filas al año para un dispositivo con 10 conexiones al día.
   - los umbrales son una propuesta inicial: calibrar con datos reales de varias redes.
---
####   BUS DE EVENTOS
   - `EventBus` es un pub/sub síncrono mínimo. el pipeline publica los eventos al final de cada escaneo, después de guardarlos.
   - `watch` se suscribe para actualizar la vista en vivo y, con `--bell`, para hacer sonar la campana en cada alerta.
   - un suscriptor que falla no interrumpe el escaneo: el error se registra y se sigue con el resto. es el punto de extensión para futuras notificaciones (escritorio, webhooks, correo).
---
