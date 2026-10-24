# CHANGELOG

## SIN PUBLICAR / UNRELEASED

### CASTELLANO

#### NUEVO
- añadir la cli `beacon` con `typer` y `rich`: comandos `scan`, `watch`, `devices`, `events`, `export`, `status`, `ports`, `ping`, `interfaces` y `vendors`
- añadir descubrimiento en modo privilegiado (barrido arp con `scapy`) y sin privilegios (barrido icmp, tabla arp del sistema y confirmación tcp)
- añadir pinger icmp asíncrono propio con sockets `SOCK_DGRAM`/`SOCK_RAW`, pool de sockets y lectura de ttl
- añadir escaneo de puertos tcp concurrente con presets, lectura de banners y resumen de respuestas http
- añadir medición de latencia con media, mínimo, máximo, jitter y pérdida, con fallback a handshake tcp
- añadir resolución de hostnames por dns inverso, mdns y netbios con parsers propios en `scanners/protocols/`
- añadir motor de limpieza de datos en `core/engine.py`: normalización y fusión por mac, filtrado de ips, descarte de caché arp antigua, macs aleatorizadas y conflictos de ip
- añadir base de fabricantes oui offline (fichero `manuf` de wireshark) con búsqueda por prefijo más largo
- añadir persistencia en sqlite con migraciones versionadas e inventario con alias y dispositivos de confianza
- añadir eventos de cambio (`new-device`, `device-online`, `device-offline`, `ip-changed`, `port-opened`, `port-closed`, `ip-conflict`) con periodo de gracia para offline
- añadir exportación a json, csv y html autocontenido, con exportación en vivo desde `watch`
- añadir los scripts `scripts/beacon-live.sh` y `scripts/beacon-live.bat`, que lanzan `beacon watch -o` y abren la web en vivo en el navegador por defecto al terminar el primer escaneo
- añadir batería de 76 tests con `pytest` y configuración de `ruff`
- añadir documentación de la fase en `.docs/project-info/cli-base/`
- añadir tres propuestas de funcionalidades en `.docs/unique-features/`: triage guiado con puntuación de riesgo, identidad continua de dispositivos y ritmo de presencia
- implementar el triage guiado: puntuación de riesgo explicable en `core/risk.py`, comando `beacon review` (interactivo, `--list`, `--json` y `--trust-below`), `events --pending`, `devices list --risk` y `scan --fail-on-risk`
- implementar la identidad continua: huella por hostname, servicios mdns, puertos y ttl en `core/identity.py`, sondeo de servicios en `scanners/services.py`, evento `identity-candidate` y comandos `devices candidates`, `link` y `unlink`, con `--no-identity`
- implementar el ritmo de presencia: sesiones guardadas en cada escaneo, perfil semanal en `core/presence.py`, eventos `unusual-presence` y `routine-broken`, comandos `beacon timeline` y `beacon prune`, mapa de calor en `devices show` y `--no-presence`
- añadir migraciones 2, 3 y 4 del esquema sqlite (`events.acked_at`, identidades y servicios, sesiones de presencia); una base migrada ya no se abre con builds anteriores
- añadir `export --include-fingerprint`: la huella de identidad ya no sale en las exportaciones por defecto
- añadir `parse_ptr_records` en `scanners/protocols/dns.py` para leer todos los ptr de una respuesta
- añadir 151 tests para las tres funcionalidades (227 en total)

#### CAMBIOS
- rediseñar la web en vivo (`export/html_export.py`): barra de estado con cuenta atrás, pausa y aviso de datos obsoletos, recarga que conserva scroll, filtros y búsqueda, bloque de dispositivos sin confianza con su riesgo, tabla con filtros, búsqueda y orden, resaltado de lo nuevo desde que se abrió la página, eventos filtrables, diseño adaptable a móvil y modo oscuro
- proteger la web con una `Content-Security-Policy` basada en hashes y sin recursos externos; los datos viajan en atributos escapados, nunca como json en un `<script>`
- rediseñar la vista de `watch`: panel de estado con contadores y barra de etapa o cuenta atrás, filas que caben en la terminal, marca `new`, eventos en tiempo relativo y resumen al parar
- mejorar la salida de `scan`: progreso por etapas con ✓, resumen en una línea con símbolo y siguiente comando recomendado
- mejorar los mensajes de error con una pista de qué probar (`✗ error:` + `→`) y la severidad de los eventos con símbolo (`✗ alert`, `! warning`, `· info`)
- añadir a las exportaciones de `scan` y `watch` la interfaz, el modo y la duración del escaneo
- mostrar el hostname en una columna propia en la tabla de consola (`scan`, `watch`, `devices list`) y en la web, con la fuente de la que se obtuvo
- añadir 14 tests para la web en vivo, la consola y la resolución de hostnames (241 en total)
- cambiar `app/app.py` para lanzar la cli de `beacon`
- actualizar `readme.md` con el stack definitivo, la estructura real y la instalación
- añadir `pyproject.toml` y `uv.lock` con dependencias, script `beacon` y configuración de `pytest` y `ruff`
- mover las guías de `.docs/` a `.docs/guidelines/` y la documentación del proyecto a `.docs/project-info/`
- actualizar `.gitignore` para ignorar caché de python, entornos virtuales y artefactos de empaquetado
- cambiar el primer escaneo: los dispositivos descubiertos con el inventario vacío son avisos (`warning`) y solo son alertas si su riesgo es alto; el mensaje de `scan` sugiere `beacon review` en lugar de `trust-all`
- cambiar `devices trust`, `trust-all` y `forget` para que marquen como revisados los eventos pendientes del dispositivo
- actualizar la documentación de `.docs/project-info/cli-base/` y marcar las tres propuestas de `.docs/unique-features/` como implementadas
- añadir los skills de terceros de `fullstack-dev-skills` en `.docs/skills/` para su uso como herramientas de desarrollo del proyecto

#### CORREGIDO
- corregir la tabla de dispositivos, que truncaba ip y mac en terminales estrechas: ahora oculta columnas opcionales según el ancho (`visible_columns`)
- corregir `watch`, que terminaba ante un fallo puntual de red: ahora muestra el error y reintenta en el siguiente ciclo
- corregir la columna de puertos vacía en la tabla de `watch` cuando no hay puertos abiertos
- corregir la cabecera del informe html (`os (ttl)` mostraba solo el so)
- corregir el tipado de `datagram_received` en `scanners/hostname.py` (pyright)
- corregir el primer escaneo, que lanzaba una alerta por cada host y hacía que `--fail-on-alert` terminara con código 3
- corregir que una mac aleatorizada que cambia apareciera como un dispositivo nuevo y alertara como intruso: ahora se propone el vínculo con el dispositivo conocido
- corregir que la presencia histórica no se guardara ni se pudiera consultar: ahora hay sesiones consultables con `beacon timeline`
- corregir el título del panel de `devices show`, que interpretaba como marcado `rich` los corchetes de un alias
- corregir que casi ningún dispositivo tuviera hostname cuando el dns del sistema es público (8.8.8.8): ahora también se pregunta el ptr al dns del router, que conoce los nombres de sus clientes dhcp (fuente `router`)

### ENGLISH

#### ADDED
- add the `beacon` cli built with `typer` and `rich`: `scan`, `watch`, `devices`, `events`, `export`, `status`, `ports`, `ping`, `interfaces` and `vendors` commands
- add privileged discovery (arp sweep with `scapy`) and unprivileged discovery (icmp sweep, system arp table and tcp confirmation)
- add a custom asynchronous icmp pinger with `SOCK_DGRAM`/`SOCK_RAW` sockets, a socket pool and ttl reading
- add concurrent tcp port scanning with presets, banner grabbing and http response summaries
- add latency measurement with average, minimum, maximum, jitter and loss, falling back to tcp handshakes
- add hostname resolution through reverse dns, mdns and netbios with custom parsers in `scanners/protocols/`
- add the data cleaning engine in `core/engine.py`: mac normalization and merging, ip filtering, stale arp cache removal, randomized macs and ip conflicts
- add an offline oui vendor database (wireshark `manuf` file) with longest prefix lookup
- add sqlite persistence with versioned migrations and an inventory with aliases and trusted devices
- add change events (`new-device`, `device-online`, `device-offline`, `ip-changed`, `port-opened`, `port-closed`, `ip-conflict`) with an offline grace period
- add json, csv and standalone html export, including live export from `watch`
- add the `scripts/beacon-live.sh` and `scripts/beacon-live.bat` scripts, which launch `beacon watch -o` and open the live web in the default browser once the first scan finishes
- add a 76 test `pytest` suite and `ruff` configuration
- add phase documentation in `.docs/project-info/cli-base/`
- add three feature proposals in `.docs/unique-features/`: guided triage with risk score, continuous device identity and presence rhythm
- implement guided triage: explainable risk score in `core/risk.py`, the `beacon review` command (interactive, `--list`, `--json` and `--trust-below`), `events --pending`, `devices list --risk` and `scan --fail-on-risk`
- implement continuous identity: fingerprint from hostname, mdns services, ports and ttl in `core/identity.py`, service probing in `scanners/services.py`, the `identity-candidate` event and the `devices candidates`, `link` and `unlink` commands, with `--no-identity`
- implement presence rhythm: sessions stored on every scan, weekly profile in `core/presence.py`, `unusual-presence` and `routine-broken` events, the `beacon timeline` and `beacon prune` commands, a heatmap in `devices show` and `--no-presence`
- add sqlite schema migrations 2, 3 and 4 (`events.acked_at`, identities and services, presence sessions); a migrated database can no longer be opened by earlier builds
- add `export --include-fingerprint`: the identity fingerprint is no longer part of exports by default
- add `parse_ptr_records` in `scanners/protocols/dns.py` to read every ptr of a response
- add 151 tests for the three features (227 in total)

#### CHANGED
- redesign the live web (`export/html_export.py`): status bar with countdown, pause and a stale data warning, reloads that keep scroll, filters and search, a block of untrusted devices with their risk, a table with filters, search and sorting, highlighting of what is new since the page was opened, filterable events, a mobile layout and dark mode
- protect the web with a hash based `Content-Security-Policy` and no external resources; data travels in escaped attributes, never as json inside a `<script>`
- redesign the `watch` view: status panel with counters and a stage or countdown bar, rows that fit the terminal, a `new` mark, relative event times and a summary on exit
- improve the `scan` output: stage checklist with ✓, a one line summary with a symbol and the recommended next command
- improve error messages with a hint of what to try (`✗ error:` + `→`) and show event severity with a symbol (`✗ alert`, `! warning`, `· info`)
- add the interface, mode and scan duration to the `scan` and `watch` exports
- show the hostname in its own column in the console table (`scan`, `watch`, `devices list`) and in the web page, with the source it came from
- add 14 tests for the live web, the console and hostname resolution (241 in total)
- change `app/app.py` to launch the `beacon` cli
- update `readme.md` with the final stack, the real layout and installation steps
- add `pyproject.toml` and `uv.lock` with dependencies, the `beacon` script and `pytest` and `ruff` configuration
- move the guidelines from `.docs/` to `.docs/guidelines/` and the project documentation to `.docs/project-info/`
- update `.gitignore` to ignore python cache, virtual environments and packaging artifacts
- change the first scan: devices found with an empty inventory are warnings and only become alerts when their risk is high; the `scan` message suggests `beacon review` instead of `trust-all`
- change `devices trust`, `trust-all` and `forget` so they mark the device's pending events as reviewed
- update the documentation in `.docs/project-info/cli-base/` and mark the three proposals in `.docs/unique-features/` as implemented
- add the third-party `fullstack-dev-skills` skills in `.docs/skills/` for use as development tooling for the project

#### FIXED
- fix the device table truncating ips and macs on narrow terminals: optional columns are now hidden by terminal width (`visible_columns`)
- fix `watch` exiting on a transient network failure: it now shows the error and retries on the next cycle
- fix the empty open ports column in the `watch` table when no ports are open
- fix the html report header (`os (ttl)` only showed the os)
- fix the `datagram_received` signature typing in `scanners/hostname.py` (pyright)
- fix the first scan raising one alert per host and making `--fail-on-alert` exit with code 3
- fix a randomized mac that changes showing up as a new device and alerting as an intruder: the link to the known device is now proposed
- fix historical presence not being stored or queryable: there are now sessions available through `beacon timeline`
- fix the `devices show` panel title, which rendered the brackets of an alias as `rich` markup
- fix that almost no device got a hostname when the system dns is a public one (8.8.8.8): the router's dns is now asked for the ptr too, since it knows the names of its dhcp clients (source `router`)
