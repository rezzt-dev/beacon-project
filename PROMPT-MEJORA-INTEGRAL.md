# BEACON: ANALISIS Y PROMPT DE MEJORA INTEGRAL

análisis del repositorio realizado el 24 de octubre de 2026. este documento contiene un diagnóstico y, a continuación, un prompt autocontenido para encargar la implementación. no modifica el funcionamiento de la aplicación.

## DIAGNOSTICO DEL PROYECTO ACTUAL

beacon es una herramienta local de descubrimiento, inventario y monitorización de redes, construida con python, typer, rich, scapy, asyncio y sqlite. su oportunidad de producto consiste en explicar qué hay en la red, qué ha cambiado, qué merece atención y qué puede hacer el usuario al respecto.

la base ya incorpora descubrimiento arp/icmp/tcp, resolución de nombres, fabricantes, puertos, latencia, eventos, confianza y alias, revisión guiada, identidad entre mac aleatorias y sesiones de presencia. también dispone de exportaciones autónomas, escrituras atómicas, migraciones de base de datos y protecciones contra contenido malicioso en los informes. conviene ampliar estas capacidades, no sustituirlas sin necesidad.

| área | evidencia revisada | oportunidad o problema |
|---|---|---|
| live | `app/beacon/export/html_export.py`, `app/beacon/cli/commands/scan.py`, `scripts/beacon-live.sh` | html autónomo regenerado por `watch`, con recarga del documento; no es todavía una aplicación web con servidor y acciones persistentes. |
| navegación | `render_html()` reúne resumen, atención, dispositivos y eventos | faltan vistas propias para detalle, revisión, identidades, presencia, servicios y configuración. |
| mantenibilidad visual | `html_export.py` tiene 746 líneas | estilos, comportamiento javascript y generación de vistas conviven en un módulo. |
| riesgo | `app/beacon/core/risk.py` | `CLEARTEXT_PORTS` incluye el puerto 22 de ssh; `assess()` devuelve inmediatamente riesgo cero para el equipo local y el gateway. |
| exactitud de puertos | `scanners/ports.py`, `core/diff.py`, `storage/repository.py` | el scanner devuelve solo puertos abiertos y el informe usa un booleano para indicar que hubo escaneo; no preserva qué puertos se comprobaron. cambiar de perfil puede convertir un puerto no examinado en un falso cierre y eliminarlo del estado actual. |
| cobertura de medición | `ports_ever_scanned()`, `render_html()` | se utiliza conocimiento global sobre escaneos de puertos; falta expresar cobertura y frescura por dispositivo y puerto. |
| identidad y varias redes | `Device.key`, esquema de `devices` | identidad por mac o `ip:<dirección>`, sin ámbito de red en la clave; exige diseño adicional para redes con rangos repetidos. |
| históricos | esquema de `scans`, `devices`, `ports`, `events`, `sessions` | existen escaneos, eventos y presencia; no hay una serie histórica completa de todas las mediciones ni snapshots suficientes para reconstruir cualquier estado anterior. |
| escala | `Repository.load_devices()`, `_icmp_sweep()` | se carga todo el inventario para ciertas consultas y se crean tareas por todos los hosts del barrido icmp; conviene medir y acotar recursos. el scanner de puertos ya utiliza un pool de workers. |
| configuración | `app/beacon/config.py` | configuración centrada en rutas y variables de entorno; faltan perfiles persistentes, exclusiones y políticas administrables. |
| alcance declarado | `.docs/project-info/cli-base/estado-y-siguientes-pasos.md` | ipv6, escucha pasiva, tls, notificaciones y servicio en segundo plano figuran como pendientes; las heurísticas de riesgo, identidad y presencia están sin calibrar con datos reales. |
| documentación | `readme.md` y documentación interna | hay posibilidades previstas, como textual o syn scan, mezcladas con la descripción del producto; hace falta distinguir lo implementado de lo planificado. |

validación ejecutada: **241 pruebas superadas** mediante `python -m pytest -q` y **ruff correcto** sobre `app` y `tests`, utilizando el entorno existente en `/home/rezzt/.cache/beacon/venv`. el entorno `.venv` del repositorio no disponía de ejecutables funcionales para estas comprobaciones. no se ha realizado un escaneo de red real, una evaluación visual en navegador ni una validación en macos/windows. pasar las pruebas existentes no demuestra la ausencia de los problemas de diseño anteriores.

“mejorar un 200 %” se interpreta como una transformación ambiciosa con resultados medibles. no existe una métrica única que permita garantizar ese porcentaje ni afirmar que será la mejor aplicación del mercado. el objetivo operativo es hacer de beacon una aplicación de referencia para administrar y comprender una red local.

## PROMPT COMPLETO PARA IMPLEMENTAR LA EVOLUCION

el texto desde aquí hasta el final está preparado para copiarlo en un agente de desarrollo con acceso al repositorio.

### MISION Y FORMA DE TRABAJAR

actúa como responsable técnico y de producto de beacon, con criterio de arquitectura, experiencia de usuario, redes, seguridad, accesibilidad y calidad. analiza el código actual y ejecuta una evolución integral para convertirlo en una aplicación local de referencia para descubrir, identificar, comprender y monitorizar dispositivos de red.

el usuario solicita una mejora muy ambiciosa del proyecto completo, con especial atención a completar funcionalidades y reorganizar la web de live. traduce esa ambición en funcionalidades terminadas, datos correctos, flujos comprensibles, estabilidad y mediciones reproducibles. no te limites a generar un plan, cambiar colores o añadir pantallas de demostración: implementa las fases y valida sus resultados.

trabaja sobre lo existente. lee las instrucciones aplicables del repositorio y revisa `pyproject.toml`, `readme.md`, `.docs/project-info/`, `.docs/unique-features/`, `app/beacon/`, `tests/` y los scripts de arranque. comprueba el estado de git y conserva los cambios del usuario. las tecnologías o habilidades presentes en `.docs/skills/` no obligan a incorporar sus stacks al producto.

crea un seguimiento persistente de tareas con estados pendiente, en curso, verificado y bloqueado. ejecuta decisiones rutinarias sin pedir confirmación repetidamente. pregunta únicamente cuando falte una decisión imprescindible que no puedas resolver con el código y el objetivo. ante una limitación, completa el trabajo independiente y explica con precisión qué no se ha podido verificar. no declares terminado un componente que solo tiene interfaz o mocks.

### 1. CONTEXTO Y CAPACIDADES QUE DEBES CONSERVAR

beacon utiliza python 3.11+, typer, rich, scapy, asyncio y sqlite. ya tiene separación entre scanners, dominio, persistencia, cli, interfaz y exportación. conserva esta separación y mantén una única implementación de las reglas de negocio para cli y web.

conserva los comandos existentes, descubrimiento con y sin privilegios, alias y confianza, riesgo explicable, revisión guiada, propuestas de identidad, presencia, exportaciones json/csv/html, actualizaciones de fabricantes, escrituras atómicas y migraciones. no elimines protecciones de privacidad ni hagas que usar la cli requiera un navegador o un entorno node.

el archivo `vivo.html` es un resultado generado. la fuente actual de su interfaz es `app/beacon/export/html_export.py`. no soluciones el producto editando solo el artefacto generado.

mantén dos experiencias explícitas:

- informe html autónomo, portable, de solo lectura y utilizable sin conexión.
- aplicación live local con navegación, consulta histórica, acciones persistentes y actualizaciones incrementales.

el informe puede seguir regenerándose mediante `watch -o`. añade un comando como `beacon live` para iniciar la aplicación local y adapta los lanzadores documentando ambos modos.

### 2. CORRECCION DEL DOMINIO ANTES DE AMPLIAR LA INTERFAZ

reproduce con pruebas y corrige estos riesgos antes de apoyar nuevas funcionalidades en ellos:

1. elimina la clasificación de ssh como protocolo sin cifrar. separa protocolo observado, servicio inferido por puerto y exposición administrativa. un número de puerto por sí solo no prueba qué servicio está detrás.
2. revisa la exención completa del host local y el gateway en `assess()`. pueden recibir un trato distinto en confianza inicial, pero su rol no debe ocultar exposición o hallazgos reales. evita mostrar “seguro” cuando no hay datos suficientes.
3. conserva el conjunto de puertos/protocolos objetivo y los resultados de cada escaneo. diferencia abierto, cerrado confirmado, filtrado o sin respuesta, no examinado y error de medición. escanear solo 80 no puede cerrar ni borrar un 22 conocido. un timeout no equivale a cierre confirmado.
4. sustituye el conocimiento global de puertos por cobertura y fecha de observación por dispositivo y puerto. explica cuándo un resultado se conserva del pasado.
5. acota temporalmente los eventos que afectan al riesgo, con razones, pesos y versión de reglas. confiar en un dispositivo no debe borrar las evidencias de exposición.
6. diferencia caída del monitor o interfaz, escaneo incompleto y desaparición de un dispositivo. una interrupción de observación no demuestra ausencia ni pérdida de paquetes.
7. diseña ámbito de red estable antes de habilitar múltiples redes. evita fusionar dispositivos por direcciones privadas repetidas; migra claves, referencias, identidades, eventos y sesiones de forma coherente. una mac tampoco constituye identidad física infalible.
8. valida cancelación y limpieza de sockets, tareas y transacciones. un error de un host debe quedar registrado sin inutilizar toda la sesión ni presentarse como escaneo completo.

añade casos de regresión para cada corrección. si cambia el significado de una puntuación o de un estado, actualiza interfaz, exportación y documentación conjuntamente.

### 3. ARQUITECTURA DE LA APLICACION LIVE

introduce una capa de servicios de aplicación reutilizada por cli y api. mantén los scanners independientes de la interfaz y el sql dentro de persistencia. divide plantillas, estilos, componentes y comportamiento del actual exportador sin perder el empaquetado autónomo.

elige la solución web de menor complejidad que cubra navegación, acciones y pruebas. justifica la elección en un registro de decisión. un frontend compilado es aceptable si aporta valor concreto; sus assets deben incluirse en la distribución para que el usuario final no necesite node. no introduzcas microservicios, redis, cuentas en la nube o reescrituras en rust sin una necesidad medida.

proporciona api versionada para estado, dispositivos, eventos, revisión, identidades, presencia, servicios, trabajos de escaneo, perfiles y configuración. usa esquemas explícitos, validación, paginación, filtros, errores comprensibles y control de concurrencia para ediciones. documenta contratos y compatibilidad.

usa eventos enviados por el servidor si bastan para las actualizaciones. incorpora identificadores monotónicos, heartbeat, reconexión con espera creciente y recuperación desde el último evento. cuando el histórico ya no permita reanudar, obtiene un snapshot consistente. evita duplicados, actualizaciones fuera de orden y colas ilimitadas. sondeo incremental es un fallback válido.

coordina un único propietario de los trabajos de escaneo por ámbito, con cola acotada, cancelación y prevención de solapamientos. varias pestañas no deben iniciar varios monitores involuntariamente. define el comportamiento cuando coinciden cli, servicio y web. no compartas una conexión sqlite entre hilos sin un diseño compatible; utiliza transacciones breves y una estrategia clara de lectores/escritores.

separa pausar las actualizaciones visuales de detener el monitor. muestra qué acción se ha realizado. no ejecutes operaciones mutantes mediante peticiones de lectura ni comandos shell construidos con entrada del navegador.

### 4. NAVEGACION Y ESTRUCTURA DE LIVE

crea un contenedor de aplicación con navegación lateral en escritorio y navegación accesible en móvil. añade selector de red/perfil, búsqueda global, indicador de salud del monitor, fecha del último resultado válido y acceso a configuración. cada vista debe tener url estable, soportar recarga y conservar filtros pertinentes en la url.

agrupa la navegación para evitar una lista interminable: operación —resumen, dispositivos, revisión y eventos—; análisis —presencia, identidades, servicios y redes—; administración —escaneos, informes y configuración—. el detalle de dispositivo debe ser accesible directamente desde cualquier vista.

| vista | contenido y acciones reales |
|---|---|
| resumen | dispositivos observados, pendientes de revisar, cambios recientes, calidad de observación y salud del monitor; indicadores enlazados a listas filtradas y una próxima acción clara. |
| dispositivos | búsqueda por alias, nombre, ip, mac, fabricante, etiqueta y servicio; filtros combinables, ordenación, columnas configurables, vistas guardadas, paginación y acciones masivas con resultado individual. |
| detalle de dispositivo | ficha, direcciones y fuentes, confianza, alias, etiquetas, notas, rol, primera/última observación, servicios, riesgo explicado, latencia, eventos, identidades y presencia; acciones de editar, revisar y volver a comprobar. |
| revisión | cola priorizada con evidencia, contexto y razones; confiar, revocar confianza, revisar un aviso, posponer con vencimiento y aceptar/rechazar una propuesta de identidad. |
| eventos | cronología filtrable por red, fecha, tipo, gravedad, dispositivo y revisión; agrupación de repeticiones, detalle y enlaces al contexto del cambio. |
| presencia | sesiones y mapa semanal por dispositivo/identidad; disponibilidad observada, cobertura del monitor, incertidumbre y explicación de anomalías. |
| identidades | candidatos con evidencia y confianza, comparación de miembros, confirmación, rechazo, separación y trazabilidad. |
| servicios | inventario de puertos y servicios por protocolo, cobertura de pruebas, banners seguros, tls, antigüedad y cambios. |
| redes | perfiles, interfaces, rangos, gateway y dispositivos agrupados; cualquier mapa distingue relaciones observadas, inferidas y desconocidas. |
| escaneos | historial, estado, etapas, duración, alcance, errores, perfil usado, planificación, inicio y cancelación. |
| informes | generación por ámbito y fechas, selección de campos, resumen de cambios, exportación json/csv/html y vista de impresión. |
| configuración y diagnóstico | perfiles, límites, retención, notificaciones, idioma, tema, rutas relevantes, capacidades disponibles y solución de errores comunes. |

no inventes una topología física a partir de un barrido arp. si solo conoces pertenencia a una subred, representa agrupaciones, no enlaces de switch o conexiones wifi ficticias.

### 5. DISEÑO, ACCESIBILIDAD Y FLUJOS

conserva la identidad sobria de beacon, aumentando legibilidad, coherencia y jerarquía. define tokens de color, tipografía, espaciado, densidad, bordes, foco y estados. permite temas claro, oscuro y sistema. añade español e inglés con cadenas centralizadas y formatos locales de fecha, hora y números.

utiliza etiquetas y símbolos además de color. no marques todo lo desconocido como amenaza ni utilices puntuaciones sin explicación. distingue hechos medidos, inferencias, información antigua y datos no disponibles. muestra “sin muestras” cuando corresponda, nunca una gráfica o un cero ficticio.

asegura navegación completa con teclado, foco visible, orden lógico, etiquetas, títulos, semántica de tablas, gestión de foco en diálogos, reducción de movimiento y anuncios de cambios moderados. verifica contraste y zoom; cualquier objetivo de accesibilidad debe tener evidencia, no solo una declaración.

verifica escritorio y móvil, al menos a 360, 768, 1280 y 1920 píxeles. evita desbordamiento horizontal de la página; tablas anchas pueden tener desplazamiento contenido y alternativa adecuada para móvil. las actualizaciones no deben robar foco, cerrar el detalle o borrar formularios sin guardar.

define estados de carga, vacío, sin resultados, primer uso, permisos insuficientes, offline, datos antiguos, reconexión y error parcial. cada estado debe explicar qué ocurre y ofrecer una acción útil. incorpora búsqueda rápida y atajos documentados sin interferir con la escritura.

el primer uso debe guiar la elección de interfaz/red, mostrar las capacidades disponibles, ejecutar un primer descubrimiento y revisar la línea base. confiar en todos no será una aceptación automática. en operaciones masivas identifica exactamente qué elementos selecciona el usuario, incluyendo el comportamiento entre páginas.

### 6. FUNCIONALIDADES DE ALTO VALOR

completa las siguientes capacidades con almacenamiento, api, cli cuando proceda e interfaz:

- perfiles de red persistentes: alcance, interfaces, exclusiones, puertos, timeouts, frecuencia, límites y características activadas.
- inventario enriquecido: alias, categorías editables, etiquetas, notas, responsable opcional y equipos marcados como esenciales.
- línea base por red y comparación entre escaneos compatibles: altas, ausencias, cambios de dirección y de exposición; explica diferencias de cobertura.
- políticas de alerta: ámbito, condiciones, gravedad, periodo de evaluación, agrupación, enfriamiento, mantenimiento y silencios con vencimiento.
- entrega opcional por escritorio y webhook, con registro, reintentos acotados e idempotencia. otros conectores solo con configuración explícita y pruebas; no envíes datos a servicios externos por defecto.
- histórico real de mediciones de latencia, pérdida observada, jitter y puertos, con retención y agregados. no presentes interpolaciones como mediciones reales ni conviertas ausencia de observación en caída confirmada.
- continuidad de identidad: evidencia legible, umbrales configurables, rechazo persistente, deshacer vínculos y prohibición de heredar confianza automáticamente. muestra incertidumbre y evita mezclar candidatos ambiguos.
- presencia: aprendizaje visible, mínimos de cobertura, timezone explícita, tratamiento de cambios de hora, periodos sin monitorización y privacidad configurable.
- enriquecimiento tls: certificado, emisor, nombres y vencimiento, límites de tamaño/tiempo y distinción entre certificado observado y validación de confianza. no deduzcas vulnerabilidades confirmadas solo por un banner.
- escucha pasiva opcional para señales útiles de arp, dhcp y mdns, con permisos claros, minimización de datos y funcionamiento base sin privilegios.
- ipv6 incremental con ndp y alcance por interfaz; no intentes enumerar un /64. integra direcciones, claves y visualización sin duplicar identidades arbitrariamente.
- ejecución sin terminal con arranque/parada limpios, instalación opcional como servicio y registro de diagnóstico. valida lo que puedas por plataforma y declara las combinaciones no probadas.

no conviertas beacon en un sistema de explotación, bloqueo automático o inspección de contenidos. el valor principal es observar con precisión, explicar y ayudar a decidir. pospón integraciones que diluyan ese objetivo hasta completar el núcleo.

### 7. PERSISTENCIA, PRIVACIDAD Y SEGURIDAD

evoluciona el esquema mediante migraciones versionadas. añade ámbito de red, cobertura de escaneo, observaciones o snapshots necesarios, series temporales, etiquetas/notas, políticas, entregas y auditoría de acciones. define unidades y timestamps; guarda tiempos en utc y transforma para presentación.

prueba migración desde cada versión soportada con datos. prepara copia de seguridad consistente antes de cambios estructurales, documenta recuperación y comprueba restauración en una base temporal. no copies sin coordinación un archivo sqlite activo ignorando su wal.

añade índices y consultas paginadas según patrones reales. evita cargar todos los dispositivos y puertos para resolver una ficha. define retención independiente para eventos, mediciones, presencia y auditoría; ejecutar limpieza debe conservar integridad referencial y explicar qué se borra.

la interfaz local debe escuchar en loopback por defecto. protege acciones sensibles también en localhost: validación de host/origen, defensa frente a dns rebinding, autenticación de sesión apropiada y protección csrf cuando se utilicen cookies. acceso desde lan requiere configuración explícita, autenticación y documentación del transporte seguro. nunca expongas escaneo arbitrario sin control de ámbito.

mantén escape de datos de red, política de contenido restrictiva y neutralización de fórmulas en csv. los nombres, banners, registros y mensajes externos son datos no confiables. no uses html sin sanear ni enlaces ejecutables derivados de banners. sirve assets localmente y evita dependencias remotas para el funcionamiento normal.

limita tamaño y frecuencia de peticiones, jobs, colas y mensajes en streaming. protege secretos de notificación y evita volcarlos en logs o exports. usa permisos de archivo adecuados cuando la plataforma los soporte.

presencia y huellas permanecen locales por defecto. incorporarlas a informes compartibles requiere selección explícita. añade vista previa y opción de anonimizar identificadores; documenta que la seudonimización no garantiza anonimato. conserva la exclusión actual de datos sensibles y prueba que nuevas vistas no la eludan.

### 8. RENDIMIENTO Y FIABILIDAD

mide antes de optimizar. registra tiempo por etapa, tiempo hasta el primer resultado, duración total, memoria, consultas y tamaños de respuesta. para redes grandes, limita tareas en vuelo con pools y colas acotadas; limitar sockets mediante semáforo no basta si creas todas las tareas por adelantado.

define presupuestos separados para sockets, resolución, banners y latencia; admite cancelación, timeouts y resultados parciales. evita solapar rondas cuando el escaneo tarda más que su intervalo. diferencia intervalo programado y tiempo real entre inicios.

en live, actualiza solo los datos afectados. pagina o virtualiza listas según mediciones, limita historiales en memoria y garantiza que clientes lentos no bloqueen el scanner. las notificaciones no deben ejecutarse bloqueando el bus síncrono actual.

crea fixtures deterministas de 50, 500 y 5.000 dispositivos y un histórico de 100.000 eventos. usa datos sintéticos para medir la interfaz y la base, sin lanzar barridos de esos tamaños sobre redes reales. registra hardware, dataset y configuración de cada benchmark.

objetivos iniciales de aceptación, sujetos a medición y ajuste justificado: respuesta visual de búsqueda/filtro inferior a 200 ms en el escenario de 500 dispositivos; p95 inferior a 300 ms para lecturas paginadas de api en el equipo de referencia; reflejar un cambio persistido en live en menos de 2 s bajo condiciones locales normales. informa valores reales y desviaciones. no prometas una duración de escaneo independiente de red, alcance y timeouts.

### 9. CALIDAD, DISTRIBUCION Y DOCUMENTACION

parte de las 241 pruebas que pasaban en la revisión inicial y vuelve a verificar el estado actual. añade pruebas por comportamiento, no por copiar detalles internos de implementación.

cubre dominio, migraciones, consultas, api, autorización local, cancelación, fallos parciales, streaming y exportaciones. los tests automáticos deben usar red simulada o servicios de loopback controlados y no modificar la base real del usuario.

añade pruebas de navegador para primer uso, navegación directa, filtros, edición de alias, confianza, revisión, identidad, presencia, reconexión y exportación. incluye teclado, tamaños móviles y verificaciones de accesibilidad. un test que busque un fragmento de html no demuestra que la interacción javascript funcione.

prueba al menos estos escenarios: monitor detenido, interfaz desaparecida, inventario vacío, miles de registros, hostname malicioso, base antigua, escritura concurrente, perfil de puertos parcial, timeout de sonda, cambio de red con la misma ip, clientes múltiples y conexión de eventos interrumpida.

añade integración continua para lint y pruebas, construcción del paquete y comprobación de que instala con sus assets. configura matriz de plataformas/versiones soportadas cuando sea viable; no afirmes compatibilidad solo porque exista un script de arranque. mantén el lockfile coherente y revisa el coste de nuevas dependencias.

actualiza instalación, inicio rápido, comandos, arquitectura, configuración, privacidad, capacidades por plataforma, ejemplos y diagnóstico. separa claramente funciones disponibles y futuras. incorpora fixtures de demostración opcionales, identificados como simulados y separados de datos reales. sincroniza versión y changelog con los cambios realmente entregados.

### 10. ORDEN DE EJECUCION Y ENTREGABLES

trabaja en incrementos utilizables y verificables, siguiendo las dependencias:

1. diagnóstico actualizado, baseline de pruebas/rendimiento y corrección de riesgo, cobertura de puertos y estados de observación.
2. servicios compartidos, migraciones necesarias, api local, seguridad, gestión de trabajos y transporte de actualizaciones.
3. aplicación live con navegación, resumen, inventario, detalle, revisión y eventos; acciones completas y compatibilidad de exportación.
4. identidades, presencia, servicios, históricos, comparación de escaneos y perfiles de red.
5. políticas, notificaciones, tls, escucha pasiva opcional, ipv6 y ejecución en segundo plano, construidos sobre las fases anteriores.
6. accesibilidad y rendimiento medidos, distribución, pruebas integrales, documentación y revisión final.

las fases anteriores describen el orden, no una excusa para abandonar el resto tras entregar el dashboard. si una capacidad queda bloqueada por permisos, hardware o credenciales, implementa y prueba lo verificable, registra la limitación y continúa con el trabajo independiente.

para cada fase entrega código integrado, migraciones cuando procedan, pruebas, instrucciones de ejecución y evidencia de los criterios completados. conserva un registro de decisiones y riesgos concretos. no publiques, despliegues externamente ni modifiques servicios del sistema sin autorización aplicable.

### 11. CRITERIOS DE ACEPTACION DEL PRODUCTO COMPLETO

- puedo arrancar beacon live con un comando documentado y conocer en segundos si el monitor funciona, qué red observa y cuándo obtuvo datos válidos.
- puedo navegar por secciones y abrir directamente la ficha de un dispositivo sin perder filtros ni estado al actualizarse los datos.
- puedo cambiar alias, confianza y revisión desde la web y ver los mismos resultados en la cli y tras reiniciar.
- puedo explicar cada riesgo mediante evidencia, actualidad y cobertura; ssh no aparece como protocolo sin cifrar y el gateway no recibe inmunidad automática.
- un escaneo de un subconjunto de puertos no elimina observaciones fuera de ese subconjunto ni confunde timeout con cierre.
- puedo distinguir una caída de dispositivo de una interrupción de monitorización y consultar las limitaciones de cada observación.
- puedo revisar vínculos de identidad sin confianza heredada y ver presencia con cobertura e incertidumbre explícitas.
- puedo usar perfiles con rangos repetidos sin mezclar inventarios y comparar escaneos indicando diferencias de alcance.
- las vistas y gráficas utilizan datos persistidos o muestran estados vacíos honestos; no existen botones que simulen éxito.
- puedo usar las funciones principales con teclado y en móvil, conservar el foco y recuperar una conexión live interrumpida.
- los informes autónomos siguen funcionando sin servidor ni recursos remotos y no incluyen presencia o huellas sensibles sin selección explícita.
- puedo migrar una base existente, hacer copia, restaurarla y aplicar retención sin perder integridad.
- las pruebas, el lint, las comprobaciones de navegador y los benchmarks están ejecutados y documentados; cualquier comprobación pendiente figura como pendiente.
- la aplicación se distribuye con sus recursos y la documentación describe el comportamiento real, incluida la diferencia entre informe html y aplicación live.

### 12. INFORME FINAL OBLIGATORIO

al terminar, presenta qué cambió y qué problemas resolvió, cómo arrancar y utilizar la nueva experiencia, archivos principales, resultados de validación, comparativa medida con el baseline, compatibilidad y migraciones, y limitaciones reales pendientes. indica expresamente qué plataformas y escenarios se probaron.

no declares “200 % mejor” ni “la mejor del mercado” sin una definición y evidencia que lo sustente. demuestra la mejora con flujos completos, datos más fiables, operaciones más rápidas, menores errores y una experiencia de live que permita administrar la red de principio a fin.
