###  BEACON PROJECT  |  ARQUITECTURA DE LA EVOLUCION
> cómo se reparten las responsabilidades después de la evolución y cómo cooperan la cli, la aplicación live y el informe html sobre las mismas reglas.
---
####   CAPAS
```
app/beacon/
├── core/          # dominio puro, sin red ni base de datos
│   ├── ports.py       # PortSet (conjuntos de puertos compactos) y merge_ports (estados sin falsos cierres)
│   ├── exposure.py    # servicio inferido, protocolo observado y categoría de exposición
│   ├── risk.py        # reglas de riesgo v2, razones con base y fecha, evaluación incompleta
│   ├── diff.py        # eventos de cambio sobre lo medido de verdad
│   ├── presence.py    # perfiles con ventanas de observación y cambios de hora
│   ├── alerts.py      # políticas, silencios y decisión de notificar
│   └── …              # modelos, limpieza, identidad, fabricantes
├── scanners/      # red: arp, icmp, puertos (estados), tls, ipv6 ndp, escucha pasiva, hostnames, mdns
├── pipeline.py    # un escaneo: descubrir → limpiar → enriquecer → comparar → guardar → publicar
├── storage/       # sqlite: un Repository compuesto por stores (devices, scans, events, identities,
│                  # presence, measurements, profiles, alerts, admin) y migraciones con copia previa
├── services/      # reglas de aplicación compartidas por cli y api: inventario, revisión, riesgo,
│                  # identidades, presencia, catálogo de servicios, escaneos, perfiles, ajustes,
│                  # informes y alertas
├── web/           # aplicación live: api, seguridad, sse, trabajos de escaneo y estáticos
│   └── static/        # html, css y módulos js servidos tal cual (sin compilación)
├── export/        # json, csv e informe html autónomo (assets en export/assets/)
├── ui/            # consola rich
└── cli/           # comandos typer
```
la regla de dependencias es la de la fase cli ampliada: `core` no depende de nada; `scanners` solo de `core`; `storage` de `core`; `services` de `core` y `storage`; `cli` y `web` de `services` (y del pipeline). no hay sql fuera de `storage` ni reglas de negocio en `cli` o `web`.
---
####   FLUJO DE UN ESCANEO
   1. `resolve_target` elige interfaz y rango; si falla, el escaneo queda registrado como `failed` y genera un único evento `scan-failed` por racha.
   2. `begin_scan` crea la fila `running` (con pid y latido) antes de tocar la red.
   3. descubrimiento con pools acotados (`run_pool`): nunca se crean todas las tareas de un /16 a la vez. las direcciones cuyo envío falló quedan como "no observadas".
   4. la red se resuelve por rango y mac del gateway (`resolve_network`); las claves de dispositivo se acotan a esa red.
   5. enriquecimiento por host en un pool; un fallo de un host se anota como incidencia y el escaneo pasa a `partial`. el escaneo de puertos rastrea los puertos ya conocidos del host para notar cierres reales.
   6. `detect_changes` compara con lo guardado de esa red y `_carry_history` fusiona puertos con `merge_ports`.
   7. `save_scan` guarda en una transacción dispositivos, puertos, cobertura, presencia, eventos, mediciones y el registro de cambios.
   8. los ganchos `after_save` evalúan las políticas de alerta (solo encolan); el envío ocurre aparte.
   9. una cancelación deja el escaneo `cancelled` sin cambiar el inventario y libera sockets, pinger y resolver.
---
####   CONCURRENCIA Y PROCESOS
| pieza | hilos y bucles | base de datos |
|---|---|---|
| cli (`scan`, `watch`) | hilo principal con `asyncio.run`; notificaciones en un hilo propio | una conexión; arrendamiento `net:<rango>` por escaneo o por sesión de watch |
| `beacon live` | uvicorn (bucle principal) + hilos de starlette para la api | una conexión por hilo (`Workspace`) |
| escáner de live | un único hilo `beacon-scanner` con su bucle: cola acotada (4), monitor y envío de avisos | su propia conexión; arrendamiento del monitor renovado cada ciclo |
| sse | generadores asíncronos que leen `changes` cada 0,5 s desde el pool de hilos | lecturas breves |
wal permite leer mientras el escáner escribe; `busy_timeout` de 5 s cubre las escrituras simultáneas de cli y web.
---
####   APLICACION LIVE
   - **rutas estables:** `/`, `/devices`, `/devices/<clave>`, `/review`, `/events`, `/presence`, `/identities`, `/services`, `/networks`, `/scans`, `/scans/<id>`, `/alerts`, `/reports`, `/settings`, `/welcome`. los filtros viven en la query string; recargar conserva la vista.
   - **módulos:** `main.js` (arranque, cabecera, navegación, atajos), `router.js`, `live.js` (sse con reintento creciente y vigilancia de bloqueos), `api.js`, `i18n.js` + `strings.js` (español e inglés), `components.js`, `charts.js` y una vista por sección en `views/`.
   - **actualizaciones:** cada cambio del registro llega a la vista activa, que recarga solo sus datos con un retardo de 300 ms; nunca se repinta un formulario con cambios sin guardar, ni se mueve una lista bajo el lector (los eventos nuevos se ofrecen con un botón). pausar las actualizaciones solo deja de repintar; el monitor sigue.
   - **seguridad del dom:** todos los valores se insertan como texto (`h()`), nunca con `innerHTML`; una prueba lo comprueba en todos los ficheros.
