###  BEACON PROJECT  |  PRIVACIDAD Y SEGURIDAD
> qué guarda beacon, qué puede salir del equipo y cómo se protege la aplicación local.
---
####   DATOS
| dato | dónde | sale del equipo |
|---|---|---|
| inventario, puertos, eventos, escaneos, mediciones | base sqlite local | solo en informes que generes o en avisos de un canal que configures |
| presencia (sesiones) | base local | solo si incluyes la presencia en un informe; nunca en avisos |
| huellas de identidad (servicios mdns) | base local | solo con `--include-fingerprint` o la opción equivalente en informes |
| notas y responsable | base local | nunca |
| secretos de canales | base local | nunca por la api ni en informes; solo firman los avisos |
| token y clave de sesión de live | `<datos>/live-token`, `<datos>/live-session-key` (permisos 600) | no |
la seudonimización de informes sustituye direcciones, macs, nombres y alias por etiquetas con una clave aleatoria por informe y reconstruye los mensajes de los eventos sin identificadores. oculta datos ante un lector casual; no garantiza anonimato, porque fabricantes, puertos y horarios pueden identificar un hogar o una persona.
---
####   APLICACION LOCAL
   - escucha en loopback; otra dirección exige `--allow-lan`.
   - solo responde a los `Host` con los que se arrancó (defensa frente a dns rebinding).
   - las escrituras exigen mismo origen (`Origin`, `Sec-Fetch-Site`), sesión válida y la cabecera csrf.
   - acceso por enlace con el token en el fragmento (no llega a registros ni a `Referer`); la cookie de sesión está firmada con hmac, es `HttpOnly` y `SameSite=Strict`, y caduca en 12 h.
   - límites: 64 kb por cuerpo, cubos de frecuencia por cliente (acceso, lectura, escritura, trabajos), 32 streams, cola de 4 trabajos.
   - cabeceras: csp sin código en línea ni recursos remotos (`default-src 'none'`), `nosniff`, `frame-ancestors 'none'`, `referrer-policy: no-referrer`, `cache-control: no-store` en la api.
   - los datos de red (nombres, banners, certificados, mensajes) se insertan siempre como texto; los csv neutralizan fórmulas; los informes html mantienen su csp con hashes.
---
####   ALCANCE DE ESCANEO
la web solo escanea perfiles cuyo objetivo es un rango privado (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16) de como máximo /16, o la red de la interfaz; una nueva comprobación de un dispositivo es un /32 de su propia red. nunca se construyen comandos de shell con datos del navegador: las notificaciones de escritorio y el servicio usan listas de argumentos.
