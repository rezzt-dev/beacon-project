###  BEACON PROJECT  |  ESTADO Y SIGUIENTES PASOS
> limitaciones conocidas de la fase cli base y propuesta de trabajo para las siguientes fases.
---
####   LIMITACIONES CONOCIDAS
   - **modo sin privilegios:** un dispositivo que descarta icmp, no tiene ningún puerto tcp habitual accesible y cuya entrada arp no está en estado `REACHABLE` puede no detectarse en un escaneo concreto. el modo privilegiado no tiene esta limitación.
   - **macs aleatorizadas:** algunos móviles cambian de mac al reconectarse. beacon propone el vínculo (`identity-candidate`, `devices candidates`) cuando coinciden hostname y servicios mdns, pero **los pesos y umbrales no se han calibrado con capturas reales**, y un móvil sin hostname ni respuesta mdns sigue apareciendo como dispositivo nuevo. el vínculo siempre lo confirma el usuario.
   - **presencia:** los umbrales (14 días, 6 sesiones, 10 %, 90 %) son una propuesta sin calibrar con datos reales. los escaneos manuales esporádicos producen sesiones de un solo punto; el perfil solo es fiable con `watch` o con escaneos periódicos.
   - **riesgo:** la puntuación es una heurística explicable, no un veredicto; los pesos están sin calibrar.
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
   - huella dhcp (opción 55 y nombre de host) como rasgo adicional para la identidad de macs aleatorizadas.
   - calibrar identidad, presencia y riesgo con capturas y datos reales de varias redes.
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
