###  BEACON PROJECT  |  MOTOR DE LIMPIEZA DE DATOS
> reglas que convierten observaciones crudas y ruidosas de todos los scanners en un único dispositivo por host real. código en `app/beacon/core/engine.py` y `app/beacon/core/mac.py`.
---
####   ENTRADA Y SALIDA
   - **entrada:** una lista de `Observation` (ip, mac opcional, fuente, ttl, rtt y si es "fresca"). las fuentes posibles son `arp-sweep`, `arp-table`, `icmp`, `tcp` y `local`.
   - **salida:** `MergeResult` con los dispositivos indexados por mac, los conflictos de ip detectados y el número de observaciones descartadas (visible al final del escaneo).
---
####   NORMALIZACION DE MACS
   - cualquier notación se convierte a `aa:bb:cc:dd:ee:ff`: con dos puntos, guiones, formato cisco `aabb.ccdd.eeff`, hexadecimal sin separadores y el formato de macos que elimina ceros (`0:1b:c5:0:0:a`).
   - se rechazan valores inválidos, la mac de broadcast, `00:00:00:00:00:00` (entradas arp incompletas) y las direcciones multicast (bit i/g).
---
####   FILTRADO DE IPS
   - se descartan ips inválidas, no especificadas, multicast, loopback y reservadas.
   - se descartan las ips fuera de la red escaneada, y la dirección de red y la de broadcast (salvo en `/31` y `/32`).
---
####   ENTRADAS ANTIGUAS DE LA CACHE ARP
   - una entrada de la tabla arp que no sea `REACHABLE` puede ser de un dispositivo que ya se fue. se marca como no fresca y solo se acepta si otra fuente (icmp o tcp) confirma esa ip en el mismo escaneo; si no, se descarta.
---
####   FUSION POR MAC
   - todas las observaciones con la misma mac forman un único dispositivo: **una ip puede cambiar, la mac no**.
   - si una mac aparece con varias ips, la ip principal es la de la fuente más fiable (`local` > `arp-sweep` > `arp-table` > `icmp` > `tcp`) y el resto se guardan en `ips`.
   - las observaciones sin mac (icmp, tcp) se asignan al dispositivo que tiene esa ip. si ningún dispositivo la tiene, se crea uno con clave `ip:<dirección>`.
   - todas las ips locales del equipo se registran con la mac de la interfaz, por lo que una ip secundaria del propio equipo no aparece como un dispositivo desconocido.
---
####   MACS ALEATORIZADAS
   - si el bit "locally administered" está activo (segundo dígito hexadecimal 2, 6, a o e) en una mac unicast, el dispositivo se marca como `randomized_mac`.
   - no se consulta su fabricante (no existe) y se muestra como `randomized (private mac)` en lugar de `unknown`. es lo habitual en móviles modernos con la privacidad de wi-fi activada.
   - el motor de limpieza no los relaciona entre sí: eso lo hace después `core/identity.py` (huella por hostname, servicios mdns, puertos y ttl), que propone vínculos con evidencias y nunca hereda la confianza. ver `persistencia-y-eventos.md`.
---
####   CONFLICTOS DE IP
   - si una misma ip responde desde dos o más macs en el mismo escaneo, se genera un `IpConflict`: puede ser una mala configuración o un ataque de arp spoofing. se convierte en un evento `ip-conflict` con severidad `alert`.
   - las observaciones sin mac de esa ip no se atribuyen a ninguno de los dispositivos en conflicto.
---
####   ENRIQUECIMIENTO Y TEXTO
   - **ttl:** se conserva el mayor ttl visto (el más cercano al valor inicial) y se recalcula la estimación de so (`apply_ttl`).
   - **fabricante:** búsqueda por prefijo más largo en la base oui (`/36`, `/28` y `/24`).
   - **hostnames (`clean_hostname`):** minúsculas, sin punto final ni caracteres de control; se descartan nombres que son la propia ip, nombres `in-addr.arpa` y nombres con caracteres inválidos.
   - **banners (`clean_banner`):** se decodifican, se eliminan caracteres de control, se toma la primera línea útil, se colapsan espacios y se limitan a 160 caracteres.
---
####   ESTADO E HISTORIAL
la parte temporal de la limpieza (primera vez visto, última vez visto, online/offline y periodo de gracia antes de marcar offline) está documentada en `persistencia-y-eventos.md`.
---
