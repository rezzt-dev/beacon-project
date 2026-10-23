###  BEACON PROJECT  |  FASE CLI BASE
> base sólida de la versión cli de beacon: descubrimiento de red, motor de limpieza, persistencia, eventos, exportación y monitorización en vivo desde la terminal.
---
####   RESUMEN
esta carpeta documenta la primera fase de desarrollo de beacon, centrada únicamente en la versión de línea de comandos. el objetivo de la fase es dejar una base estable, probada y preparada para crecer: cada capa del proyecto (`scanners/`, `core/`, `storage/`, `ui/`, `export/`) existe, tiene responsabilidades claras y se comunica con las demás a través de modelos de datos y eventos.

estado al cierre de la fase:
   - **versión:** `0.1.0`.
   - **python:** 3.11 o superior (verificado en 3.13 y 3.14).
   - **tests:** 227 pruebas automáticas en verde, sin acceso a red.
   - **verificación real:** escaneo completo de una red `/24` doméstica en modo sin privilegios en 5-8 segundos, con fabricantes, latencia, hostnames, puertos y banners.
---
####   INDICE
| fichero | contenido |
|---|---|
| [`arquitectura.md`](arquitectura.md) | capas, flujo de un escaneo, árbol de directorios y decisiones de diseño. |
| [`instalacion-y-uso.md`](instalacion-y-uso.md) | requisitos, instalación, privilegios y primeros pasos. |
| [`comandos.md`](comandos.md) | referencia completa de la cli: comandos, opciones y códigos de salida. |
| [`descubrimiento-y-scanners.md`](descubrimiento-y-scanners.md) | modos de descubrimiento, icmp, arp, puertos, latencia y resolución de nombres. |
| [`motor-de-limpieza.md`](motor-de-limpieza.md) | reglas del motor de limpieza de datos y deduplicación. |
| [`persistencia-y-eventos.md`](persistencia-y-eventos.md) | esquema sqlite, tipos de evento, detección de cambios y bus de eventos. |
| [`exportacion.md`](exportacion.md) | formatos json, csv y html, exportación en vivo y medidas de seguridad. |
| [`pruebas-y-calidad.md`](pruebas-y-calidad.md) | batería de tests, lint y verificación manual. |
| [`estado-y-siguientes-pasos.md`](estado-y-siguientes-pasos.md) | limitaciones conocidas y hoja de ruta de las siguientes fases. |
---
####   FUNCIONALIDADES IMPLEMENTADAS
   - **descubrimiento de dispositivos** con dos modos: privilegiado (barrido arp con `scapy`) y sin privilegios (barrido icmp + tabla arp del sistema + confirmación tcp).
   - **fabricante por mac** offline con la base oui del ieee (fichero `manuf` de wireshark), con soporte de bloques `/24`, `/28` y `/36`.
   - **detección de macs aleatorizadas** (bit "locally administered") para no marcarlas como fabricante desconocido.
   - **escaneo de puertos tcp** concurrente con `asyncio`, presets (`top`, `web`, `admin`, `iot`, `all`) y lectura de banners.
   - **latencia** con media, mínimo, máximo, jitter y pérdida, por icmp con fallback a tiempo de handshake tcp.
   - **hostnames** por dns inverso, mdns y netbios, con parsers propios de los protocolos.
   - **estimación de sistema operativo** por ttl.
   - **inventario persistente** en sqlite con alias, dispositivos de confianza e historial.
   - **eventos de cambio:** dispositivo nuevo, online, offline, cambio de ip, puerto abierto, puerto cerrado, conflicto de ip (posible arp spoofing), identidad candidata, presencia inusual y rutina rota.
   - **triage guiado** (`beacon review`): puntuación de riesgo explicable por dispositivo, revisión de avisos con una tecla y primer escaneo sin una alerta por host.
   - **identidad continua:** una mac aleatorizada que vuelve con otra mac se propone como el mismo dispositivo, con evidencias, y se confirma con `beacon devices link`; la confianza nunca se hereda.
   - **ritmo de presencia:** sesiones de conexión consultables (`beacon timeline`), mapa de calor semanal en `devices show` y avisos `unusual-presence` y `routine-broken`. los datos de presencia son personales: solo locales y fuera de las exportaciones.
   - **monitorización en vivo** (`beacon watch`) con tabla `rich` que se refresca y alertas.
   - **exportación** a json, csv y html autocontenido, incluida una exportación que se actualiza en cada ciclo de `watch`.
---
