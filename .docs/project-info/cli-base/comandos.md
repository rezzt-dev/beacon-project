###  BEACON PROJECT  |  REFERENCIA DE COMANDOS
> todos los comandos de la cli, sus opciones principales y los códigos de salida. `beacon <comando> --help` muestra la ayuda completa.
---
####   OPCIONES GLOBALES
| opción | descripción |
|---|---|
| `--db PATH` | ruta de la base de datos sqlite (también `BEACON_DB`). |
| `-v`, `--verbose` | logs de depuración por la salida de error. |
| `--version` | muestra la versión y termina. |
| `-h`, `--help` | ayuda. |
---
####   ESCANEO
**`beacon scan [RED]`** — un escaneo completo. `RED` en notación cidr; por defecto, la red de la interfaz.

| opción | por defecto | descripción |
|---|---|---|
| `-i`, `--iface` | interfaz de la ruta por defecto | interfaz de red a usar. |
| `-p`, `--ports` | sin escaneo de puertos | `top`, `web`, `admin`, `iot`, `all`, `22,80` o `1-1024`, combinables con comas. |
| `-m`, `--mode` | `auto` | `auto`, `privileged` o `unprivileged`. |
| `-s`, `--samples` | `3` | muestras de latencia por host (`0` lo desactiva). |
| `-t`, `--timeout` | `1.5` | timeout de descubrimiento por host, en segundos. |
| `--port-timeout` | `1.0` | timeout de conexión tcp, en segundos. |
| `--no-resolve` | — | no resolver hostnames. |
| `--no-banners` | — | no leer banners de los puertos abiertos. |
| `--offline-grace` | `0` | segundos que un dispositivo puede faltar antes de marcarse offline. |
| `-o`, `--output` | — | exporta el resultado (`.json`, `.csv`, `.html`). |
| `-f`, `--format` | extensión del fichero | fuerza el formato de exportación. |
| `--json` | — | imprime el informe completo en json por la salida estándar (el progreso va a stderr). |
| `--no-save` | — | no guarda nada en la base de datos. |
| `--fail-on-alert` | — | termina con código `3` si hubo alertas. el primer escaneo no genera alertas por cada host (son avisos para revisar), salvo que un dispositivo ya salga con riesgo alto. |
| `--fail-on-risk N` | — | termina con código `3` si un aviso o alerta afecta a un dispositivo con puntuación de riesgo ≥ `N` (0-100). los eventos informativos no cuentan. |
| `--no-identity` | — | no sondea servicios mdns ni intenta reconocer macs aleatorizadas. |
| `--no-presence` | — | no guarda sesiones de presencia ni emite anomalías de presencia. |

**`beacon watch [RED]`** — escanea en bucle con una tabla en vivo y alertas. acepta `--iface`, `--ports`, `--mode`, `--samples`, `--timeout` y `--no-resolve`, además de:

| opción | por defecto | descripción |
|---|---|---|
| `-n`, `--interval` | `60` | segundos entre escaneos (mínimo 10). |
| `-o`, `--output` | — | exportación que se reescribe tras cada escaneo; en `.html` se autorrefresca en el navegador. |
| `--bell` | — | campana de la terminal en cada alerta. |
| `--offline-grace` | `2 × interval` | gracia antes de marcar un dispositivo como offline. |
| `--no-identity`, `--no-presence` | — | igual que en `scan`. en `watch` una sesión de presencia solo se corta tras perder `3 × interval` (mínimo 15 min). |
---
####   INVENTARIO
| comando | descripción |
|---|---|
| `beacon review [--list] [--json] [--trust-below NIVEL] [-y]` | recorre los dispositivos con avisos sin revisar, del más al menos arriesgado, con el motivo del riesgo. teclas: `t` confiar, `a` confiar con alias, `i` ignorar, `f` olvidar, `s` saltar, `q` salir. `--list` y `--json` lo hacen sin terminal; `--trust-below low\|medium\|high` confía de golpe en los pendientes de ese riesgo o menor (pide confirmación). |
| `beacon timeline [--since 24h] [-d REF] [--online-only] [--step MIN] [--json]` | línea temporal de presencia: una fila por dispositivo, `█` presente, `▒` parcial, `·` ausente. `--since` acepta `30m`, `24h`, `7d`, `2w`. `--json` devuelve las sesiones con fechas iso. |
| `beacon prune --sessions-older-than 365d` | borra sesiones de presencia que terminaron hace más de ese tiempo (las abiertas no se tocan). |
| `beacon devices list [--online] [--untrusted] [--risk] [--json]` | lista todos los dispositivos conocidos. ● verde = de confianza, ● rojo = sin confianza, ○ = offline, ⛓ = mac vinculada a una identidad. `--risk` añade la puntuación. |
| `beacon devices show REF [--json]` | ficha completa con riesgo y motivos, identidad (otras macs), puertos, mapa de calor de presencia y eventos recientes. |
| `beacon devices candidates [--json]` | macs aleatorizadas que podrían ser un dispositivo ya conocido, con puntuación y evidencias. |
| `beacon devices link NUEVA ANTIGUA [--trust\|--no-trust]` | declara que dos macs son el mismo dispositivo: comparten identidad y alias. pregunta si se confía en la mac nueva; la confianza nunca se hereda sola. |
| `beacon devices unlink REF` | saca una mac de su identidad. |
| `beacon devices trust REF [--alias NOMBRE]` | marca un dispositivo como conocido. |
| `beacon devices untrust REF` | quita la marca de confianza. |
| `beacon devices trust-all [-y]` | marca todo el inventario como de confianza (línea base). |
| `beacon devices alias REF NOMBRE` | asigna un alias (cadena vacía para borrarlo). |
| `beacon devices forget REF [-y]` | elimina un dispositivo; si vuelve, se notificará como nuevo. |
| `beacon events [-l N] [--type T] [--severity S] [-d REF] [--pending] [--json]` | historial de eventos con filtros. `--type` se puede repetir. `--pending` muestra solo avisos y alertas sin revisar. |
| `beacon export PATH [-f FMT] [--online] [--events N] [--include-fingerprint]` | exporta el inventario guardado. la huella de identidad (servicios mdns) solo se incluye en json con `--include-fingerprint`; las sesiones de presencia nunca se exportan. |
| `beacon status` | rutas de datos, contadores, último escaneo y capacidades (sockets raw, scapy). |

`REF` acepta una mac en cualquier notación, una ip, un alias o un hostname.
---
####   HERRAMIENTAS
| comando | descripción |
|---|---|
| `beacon ports HOST [-p SPEC] [-c N] [--port-timeout S] [--no-banners] [--json]` | escaneo tcp connect de un único host, sin privilegios. |
| `beacon ping HOST [-c N] [--interval S] [-t S] [--json]` | latencia, jitter y pérdida (icmp con fallback tcp). termina con `1` si no hubo respuesta. |
| `beacon interfaces [--json]` | interfaces ipv4; la marcada con ★ es la usada por defecto. |
| `beacon vendors update [--url URL]` | descarga la base oui en formato `manuf`. |
| `beacon vendors lookup MAC...` | resuelve el fabricante de una o varias macs. |
---
####   CODIGOS DE SALIDA
| código | significado |
|---|---|
| `0` | correcto. |
| `1` | error de ejecución (red inválida, interfaz inexistente, falta de privilegios, dispositivo no encontrado...). |
| `2` | error de uso (opción o valor inválido, o `review` interactivo sin terminal). |
| `3` | `scan --fail-on-alert` y se generó al menos una alerta, o `scan --fail-on-risk N` y un aviso afecta a un dispositivo con riesgo ≥ `N`. |
| `130` | interrumpido con ctrl+c. |
---
