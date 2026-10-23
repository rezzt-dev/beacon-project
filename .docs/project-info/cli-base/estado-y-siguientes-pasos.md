###  BEACON PROJECT  |  ESTADO Y SIGUIENTES PASOS
> limitaciones conocidas de la fase cli base y propuesta de trabajo para las siguientes fases.
---
####   LIMITACIONES CONOCIDAS
   - **modo sin privilegios:** un dispositivo que descarta icmp, no tiene ningún puerto tcp habitual accesible y cuya entrada arp no está en estado `REACHABLE` puede no detectarse en un escaneo concreto. el modo privilegiado no tiene esta limitación.
   - **macs aleatorizadas:** algunos móviles cambian de mac al reconectarse, por lo que pueden aparecer como dispositivos nuevos. hoy no se correlacionan por hostname u otras huellas.
   - **solo ipv4:** no hay descubrimiento ipv6 (ndp).
   - **solo la lan local:** el barrido arp y la tabla arp solo tienen sentido en la red de la interfaz; escanear subredes remotas funciona únicamente con icmp/tcp y sin macs.
   - **windows:** sin icmp sin privilegios; el modo sin privilegios usa udp para cebar la caché arp y tcp para latencia.
   - **banners:** no se negocia tls, así que los puertos https no muestran banner.
   - **estimación de so:** basada solo en ttl; es orientativa.
   - **modo privilegiado:** pendiente de verificación en vivo con root.
---
####   SIGUIENTES PASOS PROPUESTOS
**fase tui**
   - interfaz con `textual`: paneles, filtros, detalle del dispositivo al seleccionarlo y acciones (confiar, alias) desde la propia tabla. reutilizaría el pipeline, el repositorio y el `EventBus` sin cambios.

**descubrimiento y fingerprinting**
   - syn scan con scapy en modo privilegiado (extra previsto en `general-info.md`).
   - escucha pasiva con `AsyncSniffer` (arp, dhcp, mdns) para detectar dispositivos en tiempo real sin esperar al siguiente ciclo.
   - correlación de macs aleatorizadas por hostname, huella dhcp o servicios mdns.
   - banners tls (certificado y cn) y más sondas por protocolo (ssh, smb, rtsp, upnp).
   - descubrimiento ipv6 con ndp.

**alertas e integración**
   - notificaciones como suscriptores del `EventBus`: escritorio, webhook, correo, telegram.
   - fichero de configuración (`beacon.toml`) para valores por defecto, redes y exclusiones.
   - servicio en segundo plano (unidad systemd) que ejecute `watch` sin terminal.

**rendimiento**
   - si el barrido o el escaneo de puertos se quedan cortos en redes `/16`, reescribir el scanner correspondiente en rust con `pyo3`, manteniendo la interfaz `list[Observation]`.

**proceso**
   - integración continua (lint + tests) en github actions.
   - cerrar la versión `0.1.0` en `changelog.md` siguiendo `.docs/guidelines/pr-merge-release-guidelines.md`.
---
