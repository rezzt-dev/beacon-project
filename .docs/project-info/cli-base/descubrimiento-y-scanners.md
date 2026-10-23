###  BEACON PROJECT  |  DESCUBRIMIENTO Y SCANNERS
> cómo encuentra beacon los dispositivos y cómo obtiene puertos, latencia, nombres y ttl. todo vive en `app/beacon/scanners/`.
---
####   RED E INTERFACES
fichero: `scanners/network.py`.
   - las interfaces y sus macs se leen con `psutil` (multiplataforma). se ignoran loopback y link-local.
   - la interfaz por defecto es la que tiene la ip de origen que usaría el kernel para salir a internet: se "conecta" un socket udp a `192.0.2.1` (no se envía ningún paquete) y se lee su dirección local.
   - la puerta de enlace se lee de `/proc/net/route` en linux y de la tabla de rutas de scapy en el resto.
   - la red máxima permitida es `/16` (65.534 hosts), para evitar barridos accidentales enormes.
---
####   MODO PRIVILEGIADO
fichero: `scanners/arp.py` (`arp_sweep`).
   - envía un `who-has` arp a toda la red con broadcast ethernet usando `scapy.srp` y recoge las respuestas con su rtt.
   - `srp` es bloqueante, así que se ejecuta en un executor para no detener el bucle de `asyncio`.
   - es el método más fiable: un host no puede participar en la lan sin responder a arp, aunque bloquee icmp y tcp.
   - requisitos: root/administrador o `cap_net_raw`, y npcap en windows. `scanners/privileges.py` lo comprueba abriendo un socket raw.
---
####   MODO SIN PRIVILEGIOS
fichero: `pipeline.py` (`_discover`) junto con `scanners/icmp.py` y `scanners/arp.py`.
   1. **barrido icmp** a todos los hosts con el pinger asíncrono propio (ver abajo). cada respuesta aporta ip, rtt y ttl.
   2. **lectura de la tabla arp del sistema:** cada paquete enviado obliga al kernel a resolver la mac, así que tras el barrido la caché arp contiene también los hosts que descartan icmp (por ejemplo, windows con el firewall por defecto).
      - linux: `ip -j -4 neigh` (json, con estado). solo `REACHABLE` se considera fresco; `STALE`, `DELAY` y `PROBE` necesitan confirmación. si `ip` no existe, se usa `/proc/net/arp`.
      - macos y windows: se parsea `arp -a`.
   3. **confirmación tcp:** las entradas no frescas que nadie confirmó se prueban con conexiones tcp a puertos habituales (`80, 443, 22, 445, 139, 62078, 8080`). una conexión aceptada o rechazada (rst) demuestra que el host está vivo. las que no responden se descartan como caché antigua.
   4. si no hay icmp sin privilegios disponible, la caché arp se "ceba" enviando un datagrama udp vacío al puerto 9 de cada host.
---
####   PINGER ICMP ASINCRONO
fichero: `scanners/icmp.py` (`IcmpPinger`).
   - construye y parsea los paquetes echo a mano (`build_echo_request`, `parse_echo_reply`, checksum rfc 1071).
   - usa sockets `SOCK_DGRAM` + `IPPROTO_ICMP` (icmp sin root en linux y macos) y, si no se puede, `SOCK_RAW` como root. en windows no se usa y se recurre a tcp.
   - el ttl de la respuesta se obtiene con `IP_RECVTTL` (mensajes de control de `recvmsg`) o de la cabecera ip en modo raw.
   - las respuestas se emparejan por `(ip de origen, número de secuencia)` y resuelven futures de `asyncio`; un único lector por socket atiende a cientos de pings simultáneos.
   - **problema resuelto durante el desarrollo:** los paquetes enviados a ips sin respuesta arp quedan retenidos ~3 segundos en el kernel y ocupan el buffer de envío del socket (unos 220 paquetes). en un barrido `/24` el envío fallaba con `EAGAIN` y la espera de escritura nunca terminaba, bloqueando el escaneo. la solución combina: envío no bloqueante con reintentos acotados (`SEND_WINDOW`), un pool de 4 sockets para repartir el buffer y un timeout que empieza a contar cuando el paquete realmente sale. el mismo control se aplica al cebado udp.
---
####   ESCANEO DE PUERTOS
fichero: `scanners/ports.py`.
   - tcp connect scan con `asyncio.open_connection`: no requiere privilegios. estados: `open` (conecta), `closed` (rst) y `filtered` (timeout o inalcanzable). solo se guardan los abiertos.
   - un pool fijo de workers consume los puertos de un iterador compartido, así que la memoria se mantiene plana incluso con `all` (65.535 puertos). un semáforo global limita los sockets abiertos entre todos los hosts.
   - presets: `top` (≈110 puertos más comunes, incluidos iot y móviles), `web`, `admin`, `iot` y `all`.
   - **banners:** se leen hasta 512 bytes; si el servicio no habla primero y es un puerto http, se envía un `GET /` y se resume la respuesta como `estado | server: cabecera`. el texto pasa por `clean_banner`.
   - nombres de servicio: tabla propia para puertos habituales en lan (`62078 iphone-sync`, `8123 home-assistant`, `1883 mqtt`...) y `getservbyport` para el resto.
---
####   LATENCIA
fichero: `scanners/latency.py`.
   - por defecto 3 muestras icmp separadas 200 ms. se calculan media, mínimo, máximo, jitter (media de diferencias absolutas entre muestras consecutivas) y pérdida.
   - si el host no responde a icmp, se mide el tiempo del handshake tcp contra un puerto abierto conocido o uno habitual. el método usado queda registrado (`icmp` o `tcp/<puerto>`).
---
####   RESOLUCION DE NOMBRES
fichero: `scanners/hostname.py` y `scanners/protocols/`.
   - se lanzan en paralelo tres consultas y gana la primera válida por prioridad: **dns inverso** → **mdns** → **netbios**.
   - **dns inverso:** `gethostbyaddr` en un pool de hilos dedicado con timeout.
   - **mdns:** consulta ptr unicast (`legacy unicast`, rfc 6762) al puerto 5353 del propio host. el paquete dns se construye y se parsea con código propio, incluida la compresión de nombres y la protección contra bucles de punteros.
   - **netbios:** consulta `NBSTAT` (rfc 1001/1002) al puerto 137 y se toma el nombre único con sufijo `0x00` (nombre de equipo).
---
####   ESTIMACION DE SO
fichero: `core/osguess.py`. el ttl observado se redondea al ttl inicial más probable (32, 64, 128 o 255): 64 → linux/unix/macos (también ios y android), 128 → windows, 255 → dispositivo de red. es una pista, no una huella completa. el equipo local muestra su so real.
---
