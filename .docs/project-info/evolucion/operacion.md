###  BEACON PROJECT  |  OPERACION
> arrancar, dejar en marcha, respaldar, limpiar y diagnosticar beacon.
---
####   ARRANQUE
| comando | efecto |
|---|---|
| `beacon live` | aplicación en `http://127.0.0.1:8765`, abre el navegador con el enlace de acceso. |
| `beacon live --monitor 60 --profile casa` | además monitoriza desde el arranque con un perfil. |
| `beacon live --url` · `--rotate-token` | muestra el enlace · invalida enlaces y sesiones anteriores. |
| `beacon live --host 0.0.0.0 --allow-lan --tls-cert c.pem --tls-key k.pem` | acceso desde la red local con https. sin `--allow-lan` se niega a arrancar. |
| `beacon live --log-file <ruta>` | registro rotativo (5 × 2 mb) de escaneos, fallos y avisos; nunca escribe el token. |
| `scripts/beacon-live.sh` · `--report` | lanzador de la aplicación · informe html regenerado por `watch`. |
---
####   SIN TERMINAL
`beacon service show` imprime la definición para la plataforma sin instalar nada; `beacon service install [--interval 300] [--profile x] [--enable]` la escribe como servicio de usuario (systemd en linux, launchagent en macos; en windows imprime la tarea programada para crearla a mano); `beacon service uninstall` la detiene y la borra. sin `--enable` solo escribe el fichero y muestra los comandos para activarlo. el servicio corre sin privilegios, así que usa el descubrimiento sin privilegios; para barrido arp o escucha pasiva hace falta ejecutarlo con privilegios de forma explícita.

al recibir sigterm el servidor termina los streams, cancela el escaneo en curso (queda `cancelled`) y libera los arrendamientos; uvicorn reenvía la señal al salir, así que el código de salida es el de sigterm, que systemd considera una parada limpia.
---
####   VARIOS PROCESOS A LA VEZ
un único proceso escanea cada red: `beacon scan` falla con código 4 y dice quién la tiene, `beacon watch` reintenta en el siguiente ciclo y la web marca el trabajo como `blocked`. un arrendamiento caduca solo si su proceso deja de renovarlo (3 × intervalo + margen), así que un proceso caído no bloquea para siempre. al arrancar, `beacon live` marca como `aborted` los escaneos `running` de procesos que ya no existen.
---
####   COPIAS Y RESTAURACION
   - `beacon backup [fichero]` copia la base con la api de copia de sqlite (coherente con wal y con escrituras en curso) y verifica la copia con `integrity_check` y `foreign_key_check`. por defecto va a `<datos>/backups/`.
   - antes de una migración estructural se guarda automáticamente `beacon.db.v<versión>-<fecha>.bak` (se conservan las 3 últimas).
   - `beacon restore <copia>` se niega si algún proceso escanea, verifica la copia, guarda la base actual como `beacon.db.before-restore` y la sustituye. restaurar con beacon detenido.
---
####   RETENCION
`beacon retention` muestra lo que se borraría y `beacon retention --apply` lo borra en una transacción (también desde configuración en la web). periodos por defecto: eventos 365 días, presencia 180, mediciones 90, escaneos y cobertura 180, auditoría y registro de avisos 730, registro de cambios en vivo 7. siempre se conservan las alertas sin revisar, las sesiones abiertas y la cobertura de puertos más reciente de cada dispositivo. `beacon prune --sessions-older-than` sigue disponible para la presencia.
---
####   ALERTAS
las políticas solo encolan avisos; el envío ocurre aparte (cada 5 s en live, en un hilo al terminar un escaneo de cli), así que un webhook lento nunca frena un escaneo. cada aviso tiene una clave de idempotencia, se reintenta con espera creciente hasta 5 veces y queda en el registro de entregas. el webhook recibe tipo, gravedad, mensaje, nombre y dirección del dispositivo, firmado con `x-beacon-signature: sha256=<hmac>` si el canal tiene secreto.
---
####   DIAGNOSTICO
`beacon status` (rutas, inventario, redes, quién escanea), configuración y diagnóstico en la web (capacidades, tamaños por tabla, arrendamientos, fallos recientes, problemas habituales) y `beacon live --log-file`. los escaneos fallidos e incompletos guardan su etapa y su error en el historial.
