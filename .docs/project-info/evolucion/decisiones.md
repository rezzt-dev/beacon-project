###  BEACON PROJECT  |  REGISTRO DE DECISIONES
> decisiones de arquitectura tomadas durante la evolución integral, con su motivo, las alternativas descartadas y sus consecuencias. cada entrada es estable: si una decisión cambia, se añade otra que la sustituye.
---
####   ADR-01 · PILA DE LA APLICACION LIVE
   - **decisión:** servidor asgi con `starlette` y `uvicorn`; interfaz en javascript con módulos es nativos, sin paso de compilación. los ficheros estáticos viven en `app/beacon/web/static/` y se distribuyen dentro del paquete.
   - **motivo:** el escáner ya es `asyncio`; starlette aporta rutas, ciclo de vida, `StreamingResponse` para sse y un cliente de pruebas, con dos dependencias puras de python. sin compilación, el usuario final nunca necesita node y el código servido es exactamente el del repositorio.
   - **descartado:** `http.server` de la biblioteca estándar (sse, ciclo de vida y validación a mano); fastapi (pydantic y su binario no aportan lo suficiente para una api local); react/vite (exige node para construir y un proceso de publicación de assets sin una necesidad medida).
   - **consecuencia:** la validación de entradas es explícita en `services/` y `web/api.py`; los componentes de la interfaz se escriben con un helper de dom propio que nunca usa `innerHTML` con datos.
---
####   ADR-02 · ACTUALIZACIONES EN VIVO CON SSE SOBRE UN REGISTRO DE CAMBIOS
   - **decisión:** tabla `changes` con id autoincremental escrita en la misma transacción que cada cambio (escaneos, ediciones, revisiones, identidades, ajustes). el endpoint `/api/v1/stream` emite esos cambios por sse con su id; el cliente reanuda con `Last-Event-ID` o `?after=`.
   - **motivo:** el registro está en la base de datos, así que también llegan los cambios hechos desde la cli o desde otro proceso, y una reconexión no pierde ni duplica eventos. si el id pedido ya se purgó, o el cliente va muy atrasado (más de 2.000 cambios), recibe `reset` y recarga un snapshot por la api normal.
   - **descartado:** websockets (no hace falta canal bidireccional); un bus en memoria (no ve los cambios de otros procesos ni sobrevive a un reinicio).
   - **límites:** 32 conexiones simultáneas, lotes de 200 cambios, heartbeat cada 15 s, estado del monitor cada 2 s.
---
####   ADR-03 · CONCURRENCIA CON SQLITE
   - **decisión:** una conexión por hilo (`Workspace.repository`), wal, `busy_timeout` de 5 s, `synchronous=NORMAL` y transacciones breves. todos los escaneos del servidor corren en un único hilo propietario (`ScanWorker`) con su propio bucle de eventos.
   - **motivo:** sqlite no permite compartir una conexión entre hilos; wal deja leer mientras el escáner escribe. con un solo hilo de escaneo no hay escaneos solapados dentro del proceso y los clientes lentos nunca bloquean al escáner.
---
####   ADR-04 · UN PROPIETARIO DE ESCANEO POR RED ENTRE PROCESOS
   - **decisión:** tabla `leases` con un arrendamiento por ámbito (`net:<cidr>`), adquirido con un único upsert atómico que solo gana si el arrendamiento caducó o ya era propio. `beacon scan`, `beacon watch`, el monitor de `beacon live` y los trabajos web lo respetan.
   - **comportamiento:** `scan` sale con código 4 y dice quién escanea; `watch` reintenta en el siguiente ciclo; un trabajo web queda `blocked` con el titular; el monitor web muestra `blocked`. el arrendamiento se renueva en cada ciclo y caduca solo si el proceso muere.
---
####   ADR-05 · AMBITO DE RED Y CLAVES DE DISPOSITIVO
   - **decisión:** tabla `networks`; una red es un rango más la mac de su gateway, así que el mismo `192.168.1.0/24` detrás de otro router es otra red. la primera red conserva las claves históricas (`mac` o `ip:<ip>`); las demás usan `n<id>:<clave>`.
   - **motivo:** evita fusionar inventarios por direcciones privadas repetidas o macs locales repetidas (máquinas virtuales) sin reescribir ninguna clave existente: la migración no toca puertos, sesiones, identidades ni eventos.
   - **consecuencia:** una misma mac en dos redes son dos entradas de inventario; si son el mismo equipo, se vinculan como identidad de forma explícita. no se vinculan dispositivos de redes distintas automáticamente.
---
####   ADR-06 · ESTADOS Y COBERTURA DE PUERTOS
   - **decisión:** cada puerto conocido guarda estado (`open`, `closed`, `filtered`), resultado de la última sonda (también `error`), fecha de comprobación y de última vez abierto. cada escaneo guarda en `port_coverage` el conjunto examinado por dispositivo (rangos compactos). los resultados se fusionan con `merge_ports`.
   - **reglas:** un puerto fuera del conjunto examinado no cambia; solo una conexión rechazada confirma un cierre; un timeout deja un puerto abierto como abierto con la última sonda `filtered`; un error de la sonda no cuenta como comprobación; nunca se borran filas de puertos. un puerto abierto en un puerto nunca examinado es una "primera comprobación" (informativa), no un "puerto nuevo".
   - **migración:** los escaneos antiguos con puertos quedan como cobertura `legacy` (conjunto desconocido), que cuenta como "examinado" sin inventar qué puertos.
---
####   ADR-07 · REGLAS DE RIESGO VERSION 2
   - **decisión:** `RULES_VERSION = "2"`. se separan servicio inferido por número de puerto, protocolo observado en el banner (o handshake tls) y categoría de exposición. ssh es administración remota cifrada (10 puntos), no un protocolo en claro; telnet, vnc y winrm http son administración sin cifrar (25); bases de datos (20), compartición de ficheros (15); servicios en claro cuentan una vez (10).
   - **sin inmunidades:** el gateway y el propio equipo se evalúan como cualquier otro; su rol solo cambia la confianza inicial.
   - **ventanas:** un puerto nuevo cuenta 7 días si sigue abierto, un conflicto de ip 24 horas; revisar o confiar no borra la evidencia (se marca "reviewed").
   - **incompleto, no seguro:** sin puertos examinados la evaluación es incompleta (`low ?` en consola, `?` en informes, `complete=false` en la api) y lleva notas sobre datos antiguos o sondas sin respuesta.
---
####   ADR-08 · ESTADO HONESTO DE CADA ESCANEO
   - **decisión:** cada escaneo deja una fila con estado `running`, `complete`, `partial`, `failed`, `cancelled` o `aborted` (proceso muerto, detectado al arrancar). un fallo de un host lo convierte en `partial` con la incidencia; las direcciones que no se pudieron sondear no se marcan desconectadas. un fallo de interfaz se registra y genera un único evento `scan-failed` por racha.
   - **presencia:** los perfiles solo cuentan las horas en que el monitor realmente observó (ventanas de escaneos válidos); una hora no observada no es ausencia y una rutina rota no se evalúa con menos del 50 % del tiempo vigilado.
---
####   ADR-09 · ACCESO A LA APLICACION LOCAL
   - **decisión:** escucha en `127.0.0.1` por defecto; la red local exige `--allow-lan` (y se recomienda `--tls-cert`/`--tls-key`). lista blanca de cabeceras `Host` (defensa frente a dns rebinding), comprobación de `Origin` y `Sec-Fetch-Site` en escrituras, enlace de acceso con el token en el fragmento de la url, cookie de sesión firmada con hmac (`HttpOnly`, `SameSite=Strict`), token csrf derivado de la sesión, límites de tamaño (64 kb) y de frecuencia, y csp sin código en línea ni recursos remotos.
   - **ámbito de escaneo:** la api solo escanea perfiles con rangos privados de como máximo /16; nunca recibe un objetivo arbitrario ni construye comandos de shell con datos del navegador.
---
####   ADR-10 · COMPARACION DE ESCANEOS POR EVENTOS
   - **decisión:** la comparación entre dos escaneos usa los eventos registrados por los escaneos válidos intermedios y enumera las diferencias de alcance (objetivo, modo, conjunto de puertos, estado, direcciones no sondeadas).
   - **descartado:** guardar una instantánea de todos los dispositivos por escaneo, que con un monitor por minuto y miles de dispositivos crece millones de filas al día sin aportar más que los eventos.
---
####   ADR-11 · CERTIFICADOS TLS SIN DEPENDENCIAS NUEVAS
   - **decisión:** el handshake usa `ssl` sin validar y un lector der propio extrae sujeto, emisor, nombres alternativos y validez, con límite de 64 kb y comprobación de límites en cada campo. el resultado lleva siempre `trusted: false`: beacon registra lo observado y nunca afirma que una cadena sea válida.
---
####   RIESGOS ABIERTOS
   - los pesos de riesgo, identidad y presencia siguen sin calibrar con capturas reales; las versiones de reglas permiten recalibrar sin ambigüedad.
   - la escucha pasiva y el modo privilegiado no se han podido verificar en vivo sin privilegios de root en este entorno.
   - el cliente de pruebas de starlette emite un aviso de deprecación por `httpx`; las pruebas funcionan. La migración del transporte de pruebas queda pendiente, sin incorporar otra dependencia en esta entrega.

---
####   ADR-12 · CONSULTAS ACOTADAS Y CACHE DEL INVENTARIO
   - **decisión:** caché LRU en memoria (32 entradas) de coincidencias y evaluaciones, por base y cursor persistido de `changes`. Páginas y ordenaciones reutilizan la evaluación; la ordenación trabaja sobre una copia. Las bases `:memory:` se distinguen por instancia y las transacciones abiertas no publican resultados en la caché.
   - **caducidad temporal:** cambio de minuto (sin segundos ni microsegundos), porque las reglas dependen del tiempo. Un límite temporal puede reflejarse con hasta un minuto de retraso sin escrituras; las ediciones, escaneos y retención invalidan por cursor inmediatamente. Las consultas con fecha explícita no usan caché.
   - **consultas:** aperturas reducidas al evento más reciente por dispositivo/puerto, preservando su revisión real; conteos de pendientes y cambios de puerto agregados en SQL. Revisión: 20 dispositivos y 5 evidencias por caso por defecto. Servicios: 50 equipos/certificados por puerto, con límites visibles y acceso al inventario completo por filtro.
   - **evidencia:** `rendimiento.md` separa la consulta inicial sin caché de las peticiones repetidas. La primera evaluación de 5.000 equipos todavía supera 300 ms; las lecturas paginadas repetidas cumplen el p95 objetivo.
