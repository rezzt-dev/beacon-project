###  PROJECTS TO DEVELOP  |  BEACON PROJECT
> proyecto de desarrollo corto y scripting, pensado para "rust" o "python".
---
####   BEACON PROJECT  |  INFORMACION GENERAL
proyecto pensado para el desarrollo de scripting, herramienta de terminal que descubre todos los dispositivos conectados a tu red local, identifica fabricante por mac, escanea puertos abiertos, mide latencia y avisa cuando aparece un dispositivo desconocido. esta herramienta esta pensada en el uso del sistemas informaticos o personas de seguridad, pudiendo analizar todos los dispositivos y caracteristicas de la red, a traves del uso de librerias o bibliotecas, clases propias y algoritmos complejos.

este proyecto aunque sea de corto desarrollo, esta pensado para combinar varias herramientas de scripting usando python o rust, ya que tenemos que tocar sockets crudos, arp, concurrencia de una gran cantidad de peticiones en tiempo real y parseo de protocolos. se tiene que realizar un motor o algoritmo de limpieza de datos para poder sacar una salida profesional, pudiendo hacer el export de los datos en live table con preview, pudiendo realizar o ver los cambios en tiempo real. este proyecto es muy util para el portfolio, ya que necesitas entender el funcionamiento de la red ademas del framework que se esta usando.
---
####   BEACON PROJECT  |  INFORMACION TECNICA
esta seccion contiene parte de la informacion tecnica para el desarrollo del proyecto, desde una vision de poder realizar un programa que sea capaz de analizar cientos de hosts. primero vamos a empezar con las librerias que cubren cada parte del proyecto:
   - **descubrimiento arp:** `scrapy` (`srp` con broadcast ethernet). es la opcion mas comoda para sockets crudos y parseo de protocolos. necesita root/administrador (y npcap en windows).
   - **fabricante por mac:** base oui del ieee (`mac-vendor-lookup` o el fichero `manuf` de wireshark), cargada en local para que funcione offline.
   - **escaneo de puertos:** `asyncio` con `open_connection`, un `semaphore` y timeouts. hace un connect scan concurrente sin root y escala bien, como extra para el portfolio s epuede agregar un sync scan con scapy.
   - **latencia:** tiempo de respuesta arp/icmp mas rtt de conexion tcp, con varias respuestas para sacar media, minimo, maximo y jitter.
   - **tabla en vivo con preview:** `rich` (`live` + `table`) para algo ligero, o `textual` si quieres una tui interactiva con paneles, filtros y detalle del dispositivo al seleccionarlo.
   - **persistencia y alertas:** `sqlite` para guardar dispositivos conocidos y detectar los desconocidos al compararlos con la base.
   - **cli:** `typer` o `click`.

**motor de limpieza de datos.** se va a desarrollar un motor o conjunto de algoritmos para poder limpiar todos los datos que se van encontrando a traves de las diferentes funciones o librerias.
   - normalizar macs a un unico formato y deduplicar fusionando por mac (una ip puede cambiar, la mac no).
   - detectar macs aleatorizadas (bit "locally adminsitered"), muy comunes en moviles, para no marcarlas como fabricante desconocido.
   - eriquecer cada dispositivo con hostname (dns inverso, mdns, netbios), una estimacion de so por ttl y banner de servicios.
   - mantener un historial de estado (visto por primera vez, ultima vez visto, online/offline) y emitir eventos de cambio: nuevo, desaparecido, puerto abierto nuevo.
---
####   BEACON PROJECT  |  ARQUITECTURA Y DATOS EXTRA
para tener un proyecto serio y profesional, necesitamos una estructura de directorios y ficheros que este preparado para un aumento y una escalabilidad bastante grande, ademas de poder tener todo organizado y pensado para un proyecto de python.
   - **scanners/** (arp, puertos, latencia) producen datos crudos. si algun dia o durante el desarrollo algun _scanner_ se queda limitado, se puede reescribir en **rust** e implementarlo en el proyecto con _pyo3_.
   - **core/** (modelos con `dataclass` o `pydantic`, normalización, diff contra la base) los limpia y genera eventos.
   - **storage/** (sqlite) guarda el estado.
   - **ui/** (rich/textual) y **export/** (json, csv, html) consumen los eventos.

para poder tener una etapa de planteamiento y desarrollo, necesitamos analizar aquellas cosas que tenemos que tener en cuenta para evitar problemas o fallos, o incluso datos especiales y necesarios para un desarrollo profesional y sacar un proyecto util.
   - `scapy.sniff` bloquea, asi que hay que usar `asyncsniffer`  o ejecutarlo en un executor para integrarlo con asyncio.
   - scapy es lento enviando miles de paquetes por segundo, pero en una lan no importa.
   - los privilegios (root/npcap) condicionan el diseño: conviene que el mod sin root (connect scan, lectura de la tabla arp del sistema) funcione como alternativa.
---
