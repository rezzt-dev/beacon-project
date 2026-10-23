###  BEACON PROJECT  |  PERSISTENCIA Y EVENTOS
> cómo se guarda el estado en sqlite, qué eventos se generan y cómo se detectan los cambios entre escaneos.
---
####   BASE DE DATOS
ficheros: `storage/database.py` (conexión y migraciones) y `storage/repository.py` (todo el sql).
   - sqlite con `foreign_keys` activado y modo `WAL` (lecturas concurrentes mientras `watch` escribe).
   - **migraciones versionadas** con `PRAGMA user_version`: cada entrada de `MIGRATIONS` sube una versión y se aplica en una transacción junto con el cambio de versión. si la base es más nueva que el programa, beacon se niega a abrirla.
   - `save_scan` guarda escaneo, dispositivos, puertos, cambios a offline y eventos en **una única transacción**: o se guarda todo o nada.

| tabla | contenido |
|---|---|
| `devices` | un registro por dispositivo (clave = mac o `ip:<dirección>`): ips, hostname y su fuente, fabricante, mac aleatorizada, ttl, so estimado, alias, confianza, estado, latencia (json), `first_seen` y `last_seen`. |
| `ports` | puertos abiertos por dispositivo con servicio, banner, `first_seen` y `last_seen`. se borran en cascada con el dispositivo. |
| `scans` | un registro por escaneo: red, interfaz, modo, si se escanearon puertos y contadores. |
| `events` | historial de eventos con severidad, mensaje y detalles (json). se conservan aunque se olvide el dispositivo. |

al actualizar un dispositivo existente, los campos que el escaneo no consiguió (hostname, ttl, fabricante, latencia) conservan su valor anterior; el alias y la confianza solo los cambia la cli. los puertos solo se sincronizan cuando el escaneo incluyó `--ports`.
---
####   TIPOS DE EVENTO
fichero: `core/events.py`.

| evento | severidad | cuándo |
|---|---|---|
| `new-device` | `alert` | aparece un dispositivo que nunca se había visto (el propio equipo se registra como `info` y como de confianza). |
| `device-online` | `info` / `warning` | vuelve un dispositivo que estaba offline (`warning` si no es de confianza). |
| `device-offline` | `info` | un dispositivo que estaba online deja de verse durante más tiempo que el periodo de gracia. |
| `ip-changed` | `info` | un dispositivo conocido aparece con otra ip. |
| `port-opened` | `warning` | aparece un puerto abierto nuevo en un dispositivo conocido. |
| `port-closed` | `info` | un puerto que estaba abierto deja de estarlo. |
| `ip-conflict` | `alert` | una ip responde desde varias macs (posible arp spoofing). |
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
   - el flujo recomendado es: primer escaneo → revisar → `beacon devices trust-all` como línea base → a partir de ahí, cada desconocido genera una alerta.
   - en la tabla, ● verde indica de confianza online, ● rojo sin confianza online y ○ offline.
---
####   BUS DE EVENTOS
   - `EventBus` es un pub/sub síncrono mínimo. el pipeline publica los eventos al final de cada escaneo, después de guardarlos.
   - `watch` se suscribe para actualizar la vista en vivo y, con `--bell`, para hacer sonar la campana en cada alerta.
   - un suscriptor que falla no interrumpe el escaneo: el error se registra y se sigue con el resto. es el punto de extensión para futuras notificaciones (escritorio, webhooks, correo).
---
