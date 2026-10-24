###  BEACON PROJECT  |  API LOCAL V1
> contrato de la api que usa la aplicación live. es local: escucha en loopback y exige sesión. la versión está en la ruta (`/api/v1`).
---
####   CONVENCIONES
   - **formato:** json en ambos sentidos (`content-type: application/json`); fechas iso 8601 en utc; duraciones en segundos salvo que el campo diga `_ms`.
   - **errores:** siempre `{"error": {"code": "…", "message": "…", "field": "…"}}`. códigos http: 400 json inválido, 401 sin sesión, 403 origen o csrf, 404 no existe, 409 conflicto de versión o recurso ocupado, 413 cuerpo de más de 64 kb, 415 sin json, 421 host no permitido, 422 validación (con `field`), 429 límite de frecuencia, 503 demasiados streams.
   - **escrituras:** cabecera `x-beacon-csrf` (la devuelve `GET /api/v1/session`) y mismo origen.
   - **concurrencia:** dispositivos, perfiles y políticas tienen `version`. una edición manda `If-Match: "<version>"` o `"version": n`; si el registro cambió, responde 409 con `current_version` y no aplica nada.
   - **paginación:** `page` (desde 1) y `size` (máx. 500) en listas; los eventos usan cursor `before=<id>` y devuelven `next_before`.
   - **compatibilidad:** dentro de v1 solo se añaden campos y rutas; quitar o cambiar el significado de un campo exige `/api/v2`.
---
####   SESION Y ESTADO
| método y ruta | descripción |
|---|---|
| `GET /api/v1/health` | público: `{"ok": true, "version"}`. |
| `POST /api/v1/session` `{"token"}` | canjea el token del enlace por la cookie de sesión; devuelve `csrf`. |
| `GET /api/v1/session` · `DELETE` | sesión actual y su `csrf` · cerrar sesión. |
| `GET /api/v1/status` | salud del monitor (`ok`, `scanning`, `idle`, `empty`, `stale`, `failing`, `blocked`), último resultado válido, trabajo en curso, cola, procesos externos que escanean, redes, cursor del registro, pendientes de revisión y capacidades del equipo. |
| `GET /api/v1/summary?network=` | recuento de dispositivos y riesgo, pendientes de revisión, cambios recientes, calidad de observación y próxima acción. |
---
####   INVENTARIO Y REVISION
| método y ruta | descripción |
|---|---|
| `GET /api/v1/devices` | filtros `network`, `q`, `status`, `trusted`, `tag`, `category`, `essential`, `has_ports`, `port`, `risk` (mínimo), `incomplete`; orden `sort` (`ip`, `name`, `risk`, `last_seen`, `first_seen`, `vendor`, `latency`, `status`) y `order=desc`; `keys_only=true` devuelve todas las claves del filtro (máx. 1.000) para seleccionar entre páginas. incluye `facets`. |
| `GET /api/v1/devices/{clave}` | ficha completa: puertos con estado, base y certificado, riesgo con razones, cobertura e historial, identidad, eventos, auditoría. cabecera `etag` con la versión. |
| `PATCH /api/v1/devices/{clave}` | `alias`, `category`, `tags`, `notes`, `owner`, `essential`. |
| `DELETE /api/v1/devices/{clave}` | olvidar (los eventos se conservan). |
| `POST …/trust` `{"trusted"}` · `POST …/review` `{"action": "ack"\|"snooze"\|"unsnooze", "until"}` · `POST …/recheck` | confianza, revisión y nueva comprobación (encola un escaneo de ese host). |
| `GET …/measurements?since&bucket=<min>` · `GET …/presence?weeks` | serie de latencia y pérdida (sin interpolar) · ritmo semanal con horas vigiladas. |
| `POST /api/v1/devices/bulk` `{"keys", "action", "tag"?, "until"?}` | acciones `trust`, `untrust`, `ack`, `snooze`, `unsnooze`, `tag`, `untag`, `essential`, `not-essential`; resultado por dispositivo. |
| `GET /api/v1/review?network&snoozed&page&size` | cola por riesgo; `page` desde 1, `size` 1–200 (20 por defecto). Devuelve `items`, `total`, `page`, `size`; cada caso incluye el total `pending` y hasta 5 eventos recientes. |
| `GET /api/v1/events` · `POST /api/v1/events/{id}/ack` | filtros `network`, `device`, `type` (repetible), `severity`, `acked`, `pending`, `since`, `until`, `q`, `before`, `size`. |
---
####   ANALISIS
| método y ruta | descripción |
|---|---|
| `GET /api/v1/identities` | identidades, candidatos con evidencias y ambigüedad, rechazos e historial. |
| `POST /api/v1/identities/link` `{"new","old","trust"}` · `unlink` `{"key"}` · `reject` `{"new","candidate"}` | decisiones de identidad; la confianza solo se concede si se pide. |
| `GET /api/v1/presence?network&hours` | sesiones por identidad y ventanas de observación. |
| `GET /api/v1/services?network&q` | puertos de la red con cobertura, protocolos, certificados y cambios de 7 días. Hasta 50 dispositivos y certificados por puerto; `open` conserva el recuento completo, `devices_truncated` indica el límite y `certificates_total` el número total. El inventario filtrado por `port` permite consultar todos los equipos. |
| `GET /api/v1/networks` · `PATCH /api/v1/networks/{id}` `{"name"}` · `GET /api/v1/interfaces` | redes, renombrar, interfaces locales. |
| `GET /api/v1/scans` · `GET /api/v1/scans/{id}` · `GET /api/v1/scans/compare?before&after` | historial, detalle con etapas e incidencias, comparación con advertencias de alcance. |
---
####   OPERACION
| método y ruta | descripción |
|---|---|
| `GET /api/v1/jobs` · `POST /api/v1/jobs` `{"profile_id"?}` · `GET/DELETE /api/v1/jobs/{id}` | trabajos de escaneo (202), con estado `queued`, `running`, `completed`, `failed`, `cancelled` o `blocked` (otro proceso tiene la red). |
| `GET /api/v1/monitor` · `POST` `{"action": "start"\|"stop", "profile_id", "interval"}` | monitor sin solapamientos. |
| `/api/v1/profiles[/{id}]` | perfiles: `name`, `target` (privado, máx. /16), `interface`, `exclude`, `ports`, `options`, `interval_seconds`, `enabled`. |
| `/api/v1/alerts/policies[/{id}]` · `/silences[/{id}]` · `/channels[/{id}]` · `POST /channels/{id}/test` · `GET /deliveries` | alertas; el secreto de un canal nunca se devuelve (`has_secret`). |
| `GET/PATCH /api/v1/settings` | idioma, tema, densidad, zona horaria, intervalo, presencia, escucha pasiva, retención. se valida todo antes de guardar nada. |
| `GET /api/v1/diagnostics` · `GET /api/v1/audit` | rutas, capacidades, tamaños, arrendamientos, fallos recientes · auditoría de acciones. |
| `POST /api/v1/maintenance/retention` `{"preview"}` · `POST /api/v1/maintenance/backup` | retención con vista previa · copia coherente. |
| `GET /api/v1/reports/preview` · `GET /api/v1/reports/export` | `format`, `network`, `online`, `events`, `since`, `fields`, `include_presence`, `include_fingerprint`, `anonymize`. |
---
####   CANAL EN VIVO
`GET /api/v1/stream` (sse). tramas:
   - `hello` con el cursor y el estado inicial; `change` con `{id, at, kind, entity, entity_id, network_id, data}` y `id:` igual al del registro; `status` cada 2 s; comentario de latido cada 15 s; `retry: 3000`.
   - reanudación con `Last-Event-ID` o `?after=<id>`; si ese id ya no existe o faltan más de 2.000 cambios, llega `reset` y el cliente recarga los datos por la api.
   - tipos de cambio: `scan.started`, `scan.progress`, `scan.finished`, `device.updated`, `device.deleted`, `event.created`, `event.acked`, `identity.linked`, `identity.unlinked`, `identity.rejected`, `network.created`, `network.updated`, `profile.*`, `policy.*`, `silence.*`, `channel.*`, `delivery.*`, `settings.updated`, `retention.applied`.
