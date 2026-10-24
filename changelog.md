# CHANGELOG

## 0.2.0 · SIN PUBLICAR / UNRELEASED

### CASTELLANO

#### NUEVO
- añadir las capturas reales `.docs/assets/beacon-overview.png` y `.docs/assets/beacon-devices.png` con datos simulados para presentar el resumen y el inventario sin exponer una red personal
- anadir la cli `beacon` con `typer` y `rich`: comandos `scan`, `watch`, `devices`, `events`, `export`, `status`, `ports`, `ping`, `interfaces` y `vendors`
- anadir descubrimiento en modo privilegiado (barrido arp con `scapy`) y sin privilegios (barrido icmp, tabla arp del sistema y confirmacion tcp)
- anadir pinger icmp asincrono propio con sockets `SOCK_DGRAM`/`SOCK_RAW`, pool de sockets y lectura de ttl
- anadir escaneo de puertos tcp concurrente con presets, lectura de banners y resumen de respuestas http
- anadir medicion de latencia con media, minimo, maximo, jitter y perdida, con fallback a handshake tcp
- anadir resolucion de hostnames por dns inverso, mdns y netbios con parsers propios en `scanners/protocols/`
- anadir motor de limpieza de datos en `core/engine.py`: normalizacion y fusion por mac, filtrado de ips, descarte de cache arp antigua, macs aleatorizadas y conflictos de ip
- anadir base de fabricantes oui offline (fichero `manuf` de wireshark) con busqueda por prefijo mas largo
- anadir persistencia en sqlite con migraciones versionadas e inventario con alias y dispositivos de confianza
- anadir eventos de cambio (`new-device`, `device-online`, `device-offline`, `ip-changed`, `port-opened`, `port-closed`, `ip-conflict`) con periodo de gracia para offline
- anadir exportacion a json, csv y html autocontenido, con exportacion en vivo desde `watch`
- anadir los scripts `scripts/beacon-live.sh` y `scripts/beacon-live.bat`, que lanzan `beacon watch -o` y abren la web en vivo en el navegador por defecto al terminar el primer escaneo
- anadir bateria de 76 tests con `pytest` y configuracion de `ruff`
- anadir documentacion de la fase en `.docs/project-info/cli-base/`
- anadir tres propuestas de funcionalidades en `.docs/unique-features/`: triage guiado con puntuacion de riesgo, identidad continua de dispositivos y ritmo de presencia
- implementar el triage guiado: puntuacion de riesgo explicable en `core/risk.py`, comando `beacon review` (interactivo, `--list`, `--json` y `--trust-below`), `events --pending`, `devices list --risk` y `scan --fail-on-risk`
- implementar la identidad continua: huella por hostname, servicios mdns, puertos y ttl en `core/identity.py`, sondeo de servicios en `scanners/services.py`, evento `identity-candidate` y comandos `devices candidates`, `link` y `unlink`, con `--no-identity`
- implementar el ritmo de presencia: sesiones guardadas en cada escaneo, perfil semanal en `core/presence.py`, eventos `unusual-presence` y `routine-broken`, comandos `beacon timeline` y `beacon prune`, mapa de calor en `devices show` y `--no-presence`
- anadir migraciones 2, 3 y 4 del esquema sqlite (`events.acked_at`, identidades y servicios, sesiones de presencia); una base migrada ya no se abre con builds anteriores
- anadir `export --include-fingerprint`: la huella de identidad ya no sale en las exportaciones por defecto
- anadir `parse_ptr_records` en `scanners/protocols/dns.py` para leer todos los ptr de una respuesta
- anadir 151 tests para las tres funcionalidades (227 en total)
- anadir la aplicacion local `beacon live` (starlette + uvicorn, javascript sin compilacion): navegacion agrupada con rutas estables, resumen, dispositivos, detalle, revision, eventos, presencia, identidades, servicios, redes, escaneos, alertas, informes y configuracion, en espanol e ingles, con temas claro, oscuro y sistema
- anadir la api local `/api/v1` con validacion, paginacion, filtros, errores uniformes y control de versiones en las ediciones, documentada en `.docs/project-info/evolucion/api.md`
- anadir actualizaciones en vivo por sse sobre un registro de cambios en la base (`changes`), con reanudacion por `Last-Event-ID`, `reset` cuando el historico no alcanza, latido y reconexion con espera creciente; tambien llegan los cambios hechos desde la cli
- anadir el gestor de escaneos de live: un hilo propietario, cola acotada, cancelacion, monitor sin solapamientos y arrendamiento por red (`leases`) que respetan `scan`, `watch` y la web
- anadir la capa de servicios `app/beacon/services/` compartida por cli y api (inventario, revision, riesgo, identidades, presencia, catalogo de servicios, escaneos, perfiles, ajustes, informes y alertas)
- anadir estados de puerto (abierto, cerrado, sin respuesta, error) con fechas, cobertura por dispositivo y escaneo (`port_coverage`) y fusion que no inventa cierres (`core/ports.py`)
- anadir el protocolo observado en banners y handshakes tls (`core/exposure.py`) y la lectura de certificados tls sin dependencias nuevas (`scanners/tls.py`)
- anadir el ambito de red (`networks`): el mismo rango detras de otro router es otra red con su propio inventario
- anadir el estado de cada escaneo (completo, incompleto, fallido, cancelado, interrumpido), con etapas, incidencias por host, direcciones no sondeadas y eventos `scan-failed` y `scan-partial`
- anadir vecinos ipv6 desde la tabla ndp del sistema, sin recorrer rangos
- anadir el historico de latencia y perdida por escaneo (`measurements`) y su grafica sin interpolar
- anadir perfiles de escaneo persistentes con objetivo privado, exclusiones, puertos, tiempos e intervalo (`beacon profiles`)
- anadir etiquetas, categoria, notas, responsable y equipos esenciales, acciones masivas con resultado por dispositivo y posponer revisiones con vencimiento
- anadir rechazo persistente de propuestas de identidad y su historial con evidencias
- anadir comparacion entre escaneos con advertencias de alcance
- anadir politicas de alerta con umbral en ventana, enfriamiento, silencios y ventanas de mantenimiento, y entrega por escritorio o webhook firmado con reintentos e idempotencia
- anadir escucha pasiva opcional de arp, dhcp y mdns (`beacon listen` y ajuste `passive`)
- anadir `beacon service` (servicio de usuario systemd o launchagent), `beacon live --log-file`, `beacon backup`, `beacon restore`, `beacon retention`, `beacon networks` y `beacon demo` (red simulada)
- anadir migracion de esquema v5 con copia de seguridad automatica previa, verificacion de integridad y restauracion
- anadir pruebas de migracion desde cada version, de api, de navegador con chromium (primer uso, navegacion, filtros, edicion con conflicto, revision, identidades, presencia, reconexion, exportacion, teclado, movil, contraste y nombres accesibles), de alertas, tls, ipv6, escucha pasiva y servicio
- anadir `scripts/bench.py` con datos sinteticos de 50, 500 y 5.000 dispositivos y 100.000 eventos, y comparacion con el codigo de partida
- anadir integracion continua en `.github/workflows/ci.yml` (lint, matriz de sistemas y versiones, navegador y paquete)
- anadir informes configurables desde la web con vista previa, seleccion de campos, filtros de red y eventos, riesgo compartido e inclusion opcional de presencia y huella de identidad
- anadir seudonimizacion por informe en `export/anonymize.py` para ocultar direcciones y nombres y retirar notas, responsables, banners y certificados, sin prometer anonimato
- anadir 151 pruebas de regresion sobre la base anterior de 241, hasta 392 pruebas, incluidas 21 de navegador con chromium
- anadir la documentacion de la evolucion en `.docs/project-info/evolucion/` y el diagnostico y plan en `PROMPT-MEJORA-INTEGRAL.md`

#### CAMBIOS
- reorganizar `readme.md` en castellano e inglés con navegación interna, insignias, tarjetas html compatibles con markdown y secciones desplegables para facilitar la lectura
- completar la guía de instalación con `uv` y `pip`, el inicio de `beacon live`, la demostración aislada y ejemplos de descubrimiento, revisión, perfiles, monitorización, exportación y automatización
- documentar en `readme.md` las rutas de datos, la privacidad, el acceso, las copias y la restauración, la retención, los servicios, los problemas habituales, la validación y los límites de compatibilidad y licencia
- redisenar la web en vivo (`export/html_export.py`): barra de estado con cuenta atras, pausa y aviso de datos obsoletos, recarga que conserva scroll, filtros y busqueda, bloque de dispositivos sin confianza con su riesgo, tabla con filtros, busqueda y orden, resaltado de lo nuevo desde que se abrio la pagina, eventos filtrables, diseno adaptable a movil y modo oscuro
- proteger la web con una `Content-Security-Policy` basada en hashes y sin recursos externos; los datos viajan en atributos escapados, nunca como json en un `<script>`
- redisenar la vista de `watch`: panel de estado con contadores y barra de etapa o cuenta atras, filas que caben en la terminal, marca `new`, eventos en tiempo relativo y resumen al parar
- mejorar la salida de `scan`: progreso por etapas con ✓, resumen en una linea con simbolo y siguiente comando recomendado
- mejorar los mensajes de error con una pista de que probar (`✗ error:` + `→`) y la severidad de los eventos con simbolo (`✗ alert`, `! warning`, `· info`)
- anadir a las exportaciones de `scan` y `watch` la interfaz, el modo y la duracion del escaneo
- mostrar el hostname en una columna propia en la tabla de consola (`scan`, `watch`, `devices list`) y en la web, con la fuente de la que se obtuvo
- anadir 14 tests para la web en vivo, la consola y la resolucion de hostnames (241 en total)
- cambiar `app/app.py` para lanzar la cli de `beacon`
- actualizar `readme.md` con el stack definitivo, la estructura real y la instalacion
- anadir `pyproject.toml` y `uv.lock` con dependencias, script `beacon` y configuracion de `pytest` y `ruff`
- mover las guias de `.docs/` a `.docs/guidelines/` y la documentacion del proyecto a `.docs/project-info/`
- actualizar `.gitignore` para ignorar cache de python, entornos virtuales y artefactos de empaquetado
- cambiar el primer escaneo: los dispositivos descubiertos con el inventario vacio son avisos (`warning`) y solo son alertas si su riesgo es alto; el mensaje de `scan` sugiere `beacon review` en lugar de `trust-all`
- cambiar `devices trust`, `trust-all` y `forget` para que marquen como revisados los eventos pendientes del dispositivo
- actualizar la documentacion de `.docs/project-info/cli-base/` y marcar las tres propuestas de `.docs/unique-features/` como implementadas
- anadir los skills de terceros de `fullstack-dev-skills` en `.docs/skills/` para su uso como herramientas de desarrollo del proyecto
- cambiar el modelo de riesgo a las reglas v2: ssh es administracion cifrada y no un protocolo en claro, el gateway y el propio equipo ya no estan exentos, los eventos cuentan dentro de su ventana aunque esten revisados, cada razon lleva base y fecha, y sin puertos examinados el riesgo es incompleto en lugar de seguro
- cambiar la presencia para contar solo las horas en que beacon observaba la red; una hora sin vigilar ya no es una ausencia
- cambiar el informe html para separar estilos y script en `export/assets/`, usar el riesgo compartido y marcar el riesgo incompleto
- cambiar `scripts/beacon-live.sh` y `.bat` para abrir la aplicacion live; `--report` mantiene el informe regenerado por `watch`
- cambiar el repositorio en almacenes por area y las busquedas de dispositivos a consultas sql sin cargar todo el inventario
- cambiar `readme.md` para separar lo disponible de lo previsto (syn scan, tui con textual, rust)
- actualizar la version a `0.2.0` en `pyproject.toml`, `uv.lock` y `app/beacon/__init__.py`, incorporar `starlette`, `uvicorn`, `httpx` y el grupo opcional `browser` con `playwright`, y distribuir los recursos web y de informes en el paquete

#### CORREGIDO
- corregir la cache de inventario: reutilizacion entre paginas y ordenaciones, caducidad por minuto sin microsegundos, invalidacion tras escrituras externas y aislamiento de bases en memoria
- completar la paginacion de revision en api y web, con recuento total, evidencia acotada y recuperacion al agotar la ultima pagina
- conservar el evento de apertura mas reciente y su estado real de revision en la agregacion del riesgo
- aislar los conflictos de ip por red y comprobar la version de confianza/edicion en la propia escritura sql
- acotar la acumulacion de cambios en la interfaz y refrescar tras aplicar retencion
- reducir la espera de busqueda a 75 ms y agregar los recuentos del catalogo en sql; indicar sus listas limitadas y enlazar el inventario completo
- corregir la tabla de dispositivos, que truncaba ip y mac en terminales estrechas: ahora oculta columnas opcionales segun el ancho (`visible_columns`)
- corregir `watch`, que terminaba ante un fallo puntual de red: ahora muestra el error y reintenta en el siguiente ciclo
- corregir la columna de puertos vacia en la tabla de `watch` cuando no hay puertos abiertos
- corregir la cabecera del informe html (`os (ttl)` mostraba solo el so)
- corregir el tipado de `datagram_received` en `scanners/hostname.py` (pyright)
- corregir el primer escaneo, que lanzaba una alerta por cada host y hacia que `--fail-on-alert` terminara con codigo 3
- corregir que una mac aleatorizada que cambia apareciera como un dispositivo nuevo y alertara como intruso: ahora se propone el vinculo con el dispositivo conocido
- corregir que la presencia historica no se guardara ni se pudiera consultar: ahora hay sesiones consultables con `beacon timeline`
- corregir el titulo del panel de `devices show`, que interpretaba como marcado `rich` los corchetes de un alias
- corregir que casi ningun dispositivo tuviera hostname cuando el dns del sistema es publico (8.8.8.8): ahora tambien se pregunta el ptr al dns del router, que conoce los nombres de sus clientes dhcp (fuente `router`)
- corregir que escanear un subconjunto de puertos cerrara y borrara puertos no examinados, y que un timeout contara como cierre
- corregir que un fallo de interfaz o de un host pudiera presentarse como escaneo completo o marcar dispositivos como desconectados
- corregir la fusion de inventarios de redes distintas con el mismo rango privado
- corregir la creacion de todas las tareas de un barrido icmp a la vez; ahora usa un pool acotado
- corregir que confiar en un dispositivo borrara la evidencia de un puerto nuevo en el riesgo

#### ELIMINADO

- eliminar `PROMPT-MEJORA-INTEGRAL.md` de la raíz del repositorio

#### SEGURIDAD
- proteger la aplicacion local con escucha en loopback por defecto, lista de `Host`, comprobacion de origen, sesion firmada, csrf, limites de tamano y frecuencia y csp sin codigo en linea
- limitar los escaneos de la web a rangos privados de hasta /16 en perfiles
- permitir acceso lan solo con `--allow-lan` explicito, ofrecer https con `--tls-cert` y `--tls-key` y rotar el acceso con `--rotate-token`
- no devolver nunca los secretos de los canales y guardar los ficheros de acceso con permisos 600

### ENGLISH

#### ADDED
- add real screenshots at `.docs/assets/beacon-overview.png` and `.docs/assets/beacon-devices.png` using simulated data to present the overview and inventory without exposing a personal network
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
- add the local `beacon live` app (starlette + uvicorn, javascript without a build step): grouped navigation with stable urls, overview, devices, detail, review, events, presence, identities, services, networks, scans, alerts, reports and settings, in spanish and english, with light, dark and system themes
- add the local `/api/v1` api with validation, pagination, filters, uniform errors and version checks on edits, documented in `.docs/project-info/evolucion/api.md`
- add live updates over sse on a change feed stored in the database (`changes`), with `Last-Event-ID` resume, `reset` when the history is gone, heartbeat and growing reconnection backoff; changes made from the cli arrive too
- add the live scan manager: one owner thread, bounded queue, cancellation, a monitor that never overlaps and a per-network lease (`leases`) honoured by `scan`, `watch` and the web
- add the service layer `app/beacon/services/` shared by the cli and the api (inventory, review, risk, identities, presence, service catalog, scans, profiles, settings, reports and alerts)
- add port states (open, closed, no answer, error) with dates, coverage per device and scan (`port_coverage`) and a merge that never invents a close (`core/ports.py`)
- add the protocol observed in banners and tls handshakes (`core/exposure.py`) and tls certificate reading without new dependencies (`scanners/tls.py`)
- add network scope (`networks`): the same range behind another router is another network with its own inventory
- add the status of each scan (complete, partial, failed, cancelled, aborted), with stages, per-host issues, unprobed addresses and `scan-failed` and `scan-partial` events
- add ipv6 neighbours from the system ndp table, without sweeping ranges
- add latency and loss history per scan (`measurements`) and its chart without interpolation
- add persistent scan profiles with a private target, exclusions, ports, timeouts and interval (`beacon profiles`)
- add tags, category, notes, owner and essential devices, bulk actions with a result per device and review snoozing with an end date
- add persistent rejection of identity proposals and their history with evidence
- add scan comparison with scope caveats
- add alert policies with a threshold in a window, cooldown, silences and maintenance windows, delivered as desktop notifications or signed webhooks with retries and idempotency
- add optional passive listening to arp, dhcp and mdns (`beacon listen` and the `passive` setting)
- add `beacon service` (systemd or launchagent user service), `beacon live --log-file`, `beacon backup`, `beacon restore`, `beacon retention`, `beacon networks` and `beacon demo` (simulated network)
- add schema migration v5 with an automatic backup first, integrity checks and restore
- add tests for migrations from every version, the api, the browser with chromium (first use, navigation, filters, editing with conflicts, review, identities, presence, reconnection, export, keyboard, mobile, contrast and accessible names), alerts, tls, ipv6, passive listening and the service
- add `scripts/bench.py` with synthetic data of 50, 500 and 5,000 devices and 100,000 events, compared with the starting code
- add continuous integration in `.github/workflows/ci.yml` (lint, os and python matrix, browser and package)
- add configurable web reports with previews, field selection, network and event filters, shared risk and optional presence and identity fingerprints
- add per-report pseudonymization in `export/anonymize.py` to hide addresses and names and strip notes, owners, banners and certificates, without promising anonymity
- add 151 regression tests on top of the previous 241, bringing the suite to 392 tests, including 21 chromium browser tests
- add the evolution documentation in `.docs/project-info/evolucion/` and the diagnosis and plan in `PROMPT-MEJORA-INTEGRAL.md`

#### CHANGED
- reorganize `readme.md` in spanish and english with internal navigation, badges, markdown-compatible html cards and collapsible sections to improve readability
- expand installation instructions with `uv` and `pip`, `beacon live` startup, an isolated demo and examples of discovery, review, profiles, monitoring, export and automation
- document data paths, privacy, access, backup and restore, retention, services, troubleshooting, validation, compatibility limits and licensing in `readme.md`
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
- change the risk model to rules v2: ssh is encrypted administration, not a cleartext protocol, the gateway and this host are no longer exempt, events count within their window even when reviewed, every reason carries its basis and date, and without examined ports the risk is incomplete instead of safe
- change presence to count only the hours beacon was watching the network; an unwatched hour is no longer an absence
- change the html report to move styles and script into `export/assets/`, use the shared risk and mark incomplete risk
- change `scripts/beacon-live.sh` and `.bat` to open the live app; `--report` keeps the report regenerated by `watch`
- change the repository into per-area stores and device lookups into sql queries that do not load the whole inventory
- change `readme.md` to separate what is available from what is planned (syn scan, textual tui, rust)
- update the version to `0.2.0` in `pyproject.toml`, `uv.lock` and `app/beacon/__init__.py`, add `starlette`, `uvicorn`, `httpx` and the optional `browser` group with `playwright`, and ship web and report assets in the package

#### FIXED
- fix inventory caching across pages and sort orders, minute expiry, external-write invalidation and independent in-memory databases
- complete api and browser review pagination with total counts, bounded evidence and recovery after emptying the last page
- preserve the latest port opening and its actual review state in risk queries
- scope ip conflicts to their network and enforce device edit/trust versions in the sql write
- bound queued ui changes and refresh after retention
- reduce search debounce to 75 ms and aggregate service counts in sql; expose list limits with a link to the complete filtered inventory
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
- fix scanning a subset of ports closing and deleting ports that were not examined, and a timeout counting as a close
- fix an interface or host failure being reported as a complete scan or marking devices offline
- fix inventories of different networks with the same private range being merged
- fix the icmp sweep creating every task at once; it now uses a bounded pool
- fix trusting a device erasing the evidence of a new port from its risk

#### REMOVED

- remove `PROMPT-MEJORA-INTEGRAL.md` from the repository root

#### SECURITY
- protect the local app with a loopback listener by default, a `Host` allowlist, origin checks, a signed session, csrf, size and rate limits and a csp without inline code
- restrict web scans to private ranges of at most /16 in profiles
- allow lan access only with explicit `--allow-lan`, offer https with `--tls-cert` and `--tls-key` and rotate access with `--rotate-token`
- never return channel secrets and store the sign-in files with 600 permissions
