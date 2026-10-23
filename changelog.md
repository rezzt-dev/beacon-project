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
- añadir batería de 76 tests con `pytest` y configuración de `ruff`
- añadir documentación de la fase en `.docs/project-info/cli-base/`
- añadir tres propuestas de funcionalidades en `.docs/unique-features/`: triage guiado con puntuación de riesgo, identidad continua de dispositivos y ritmo de presencia

#### CAMBIOS
- cambiar `app/app.py` para lanzar la cli de `beacon`
- actualizar `readme.md` con el stack definitivo, la estructura real y la instalación
- añadir `pyproject.toml` y `uv.lock` con dependencias, script `beacon` y configuración de `pytest` y `ruff`
- mover las guías de `.docs/` a `.docs/guidelines/` y la documentación del proyecto a `.docs/project-info/`
- actualizar `.gitignore` para ignorar caché de python, entornos virtuales y artefactos de empaquetado

#### CORREGIDO
- corregir la tabla de dispositivos, que truncaba ip y mac en terminales estrechas: ahora oculta columnas opcionales según el ancho (`visible_columns`)
- corregir `watch`, que terminaba ante un fallo puntual de red: ahora muestra el error y reintenta en el siguiente ciclo
- corregir la columna de puertos vacía en la tabla de `watch` cuando no hay puertos abiertos
- corregir la cabecera del informe html (`os (ttl)` mostraba solo el so)
- corregir el tipado de `datagram_received` en `scanners/hostname.py` (pyright)

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
- add a 76 test `pytest` suite and `ruff` configuration
- add phase documentation in `.docs/project-info/cli-base/`
- add three feature proposals in `.docs/unique-features/`: guided triage with risk score, continuous device identity and presence rhythm

#### CHANGED
- change `app/app.py` to launch the `beacon` cli
- update `readme.md` with the final stack, the real layout and installation steps
- add `pyproject.toml` and `uv.lock` with dependencies, the `beacon` script and `pytest` and `ruff` configuration
- move the guidelines from `.docs/` to `.docs/guidelines/` and the project documentation to `.docs/project-info/`
- update `.gitignore` to ignore python cache, virtual environments and packaging artifacts

#### FIXED
- fix the device table truncating ips and macs on narrow terminals: optional columns are now hidden by terminal width (`visible_columns`)
- fix `watch` exiting on a transient network failure: it now shows the error and retries on the next cycle
- fix the empty open ports column in the `watch` table when no ports are open
- fix the html report header (`os (ttl)` only showed the os)
- fix the `datagram_received` signature typing in `scanners/hostname.py` (pyright)
