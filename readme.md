<div align="center">

# BEACON

**discover, understand and monitor every device on your local network: what is there, what changed, what deserves attention and what you can do about it.**

![python](https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white)
![status](https://img.shields.io/badge/estado-en%20desarrollo-orange?style=flat-square)
![license](https://img.shields.io/badge/license-all%20rights%20reserved-red?style=flat-square)
![platform](https://img.shields.io/badge/probado-linux-lightgrey?style=flat-square)

[castellano](#castellano) · [english](#english)

</div>

---

## CASTELLANO

### DESCRIPCION

beacon descubre los dispositivos de la red local, los identifica (fabricante, nombre, servicios, certificados), mide su latencia y sus puertos, guarda su historia y explica qué ha cambiado y por qué algo merece atención. todo se queda en tu equipo: no hay cuentas en la nube ni se envía nada fuera salvo que configures un canal de notificación.

tiene tres formas de uso sobre los mismos datos y las mismas reglas:

| experiencia | para qué | cómo |
|---|---|---|
| **aplicación live** | navegar el inventario, revisar avisos, editar alias y confianza, ver presencia, identidades y servicios, lanzar y programar escaneos, configurar alertas. se actualiza en vivo. | `beacon live` |
| **cli** | escanear, revisar y consultar desde la terminal o desde scripts (`--json`). | `beacon scan`, `beacon review`, `beacon devices` … |
| **informe html** | una página autónoma de solo lectura que funciona sin conexión y sin beacon; puede regenerarse en cada ciclo. | `beacon export informe.html`, `beacon watch -o vivo.html` |

### INSTALACION

```bash
uv sync                              # o: pip install -e .
uv run beacon vendors update         # descarga la base de fabricantes (oui) una vez
```

python 3.11 o superior. no hace falta node ni navegador para usar la cli; la aplicación live se sirve desde el propio paquete.

### INICIO RAPIDO

```bash
uv run beacon live                   # abre la aplicación en el navegador y guía el primer descubrimiento
uv run beacon live --monitor 60      # igual, monitorizando cada 60 s desde el arranque
uv run beacon scan -p top            # un escaneo desde la terminal, con los 100 puertos más habituales
uv run beacon review                 # decide uno a uno sobre los dispositivos pendientes
uv run beacon demo /tmp/demo.db      # crea una red simulada para probar sin escanear nada
uv run beacon --db /tmp/demo.db live # y ábrela
```

`beacon live` escucha en `127.0.0.1` y abre un enlace de acceso privado (`beacon live --url` lo vuelve a mostrar). `scripts/beacon-live.sh` (o `.bat`) arranca la aplicación; con `--report` mantiene el informe html regenerado por `watch`.

### QUE HACE HOY

- **descubrimiento:** barrido arp con `scapy` cuando hay privilegios; sin ellos, icmp propio, tabla arp del sistema y confirmación tcp. vecinos ipv6 desde la tabla ndp del sistema (nunca se recorre un /64).
- **identificación:** fabricante por oui sin conexión, macs aleatorias, hostname (dns inverso, dns del router, mdns, netbios), servicios mdns, estimación de so por ttl.
- **puertos con estados honestos:** abierto, cerrado (rechazado), sin respuesta, error de sonda y "no examinado". escanear un subconjunto no cierra lo que no examinó; un timeout no es un cierre. cobertura y fecha por dispositivo.
- **protocolo observado e inferido:** el banner (ssh, http, telnet, ftp, vnc…) o un handshake tls pesan más que el número de puerto; los certificados tls se registran (sujeto, emisor, nombres, validez) sin afirmar que sean de confianza.
- **riesgo explicable (reglas v2):** cada punto tiene motivo, base (observado, inferido, histórico, contexto) y fecha; ssh es administración cifrada, no protocolo en claro; el gateway y el propio equipo no tienen inmunidad; sin datos de puertos el riesgo es "incompleto", no "seguro".
- **revisión guiada:** cola por riesgo, confiar (con alias sugerido), revisado sin confiar, posponer con vencimiento, olvidar, y propuestas de identidad.
- **identidad continua:** propone que una mac aleatoria nueva es un equipo conocido con evidencias; se confirma o se rechaza (para siempre), nunca hereda confianza.
- **presencia:** sesiones, mapa semanal y anomalías que solo cuentan las horas en que beacon estaba vigilando; zona horaria configurable; datos locales que no salen en informes salvo que los incluyas.
- **redes:** el mismo rango detrás de otro router es otra red; inventarios separados.
- **historia:** cada escaneo queda registrado como completo, incompleto, fallido o cancelado, con etapas y errores; latencia y pérdida por escaneo; comparación entre escaneos que explica las diferencias de alcance.
- **alertas:** políticas por tipo, gravedad, dispositivo y riesgo, con umbral en ventana, enfriamiento, silencios y ventanas de mantenimiento; entrega por notificación de escritorio o webhook firmado, con reintentos acotados e idempotencia. nada se envía por defecto.
- **escucha pasiva opcional:** arp, dhcp y mdns con privilegios, para escanear en cuanto aparece una mac desconocida.
- **operación:** perfiles de escaneo, copias de seguridad coherentes y restauración verificada, retención con vista previa, servicio de usuario (`beacon service install`) y registro de diagnóstico.

### PREVISTO, NO DISPONIBLE

- syn scan con `scapy` en modo privilegiado.
- interfaz de terminal a pantalla completa con `textual`.
- reescritura de scanners en rust con `pyo3` si una medición lo justifica (las actuales no lo hacen).
- calibrar con capturas reales los pesos de riesgo, identidad y presencia.

### PRIVACIDAD Y SEGURIDAD

- todo vive en una base sqlite local (`beacon status` muestra la ruta). la presencia, las huellas de identidad, las notas y el responsable no salen en informes salvo selección explícita; los informes pueden seudonimizarse (oculta identificadores, no garantiza anonimato).
- la aplicación live solo responde en loopback, valida `Host` y `Origin`, usa sesión firmada `HttpOnly`/`SameSite=Strict`, token csrf, límites de tamaño y frecuencia y una csp sin código en línea ni recursos remotos. abrirla a la red local exige `--allow-lan` (y conviene `--tls-cert`/`--tls-key`).
- la web solo escanea rangos privados de hasta /16 definidos en perfiles; nunca recibe un objetivo arbitrario ni ejecuta comandos construidos con datos del navegador.

### PLATAFORMAS

| plataforma | estado |
|---|---|
| linux, python 3.13 | probado: pruebas unitarias, de api, de cli y de navegador (chromium), instalación del wheel. |
| linux con privilegios (barrido arp, escucha pasiva) | analizadores probados con paquetes construidos; sin verificación en vivo con root. |
| macos, windows; python 3.11 y 3.12 | configurados en la integración continua; no verificados en esta entrega. |

### DOCUMENTACION

- [evolución integral: arquitectura, api, decisiones, rendimiento y seguimiento](.docs/project-info/evolucion/readme.md)
- [documentación de la fase cli](.docs/project-info/cli-base/readme.md)

### AVISO LEGAL

utiliza beacon únicamente en redes de tu propiedad o sobre las que tengas autorización expresa. el escaneo de redes ajenas sin permiso puede ser ilegal.

### LICENCIA

todos los derechos reservados © 2026 rezzt-dev. consulta el fichero [`license.md`](license.md) para más información.

---

## ENGLISH

### DESCRIPTION

beacon discovers the devices on your local network, identifies them (vendor, name, services, certificates), measures their latency and ports, keeps their history and explains what changed and why something deserves attention. everything stays on your machine: no cloud accounts, and nothing is sent anywhere unless you set up a notification channel.

three ways to use it, over the same data and the same rules:

| experience | for | how |
|---|---|---|
| **live app** | browse the inventory, review warnings, edit aliases and trust, see presence, identities and services, run and schedule scans, set up alerts. updates live. | `beacon live` |
| **cli** | scan, review and query from a terminal or from scripts (`--json`). | `beacon scan`, `beacon review`, `beacon devices` … |
| **html report** | a standalone, read-only page that works offline and without beacon; can be regenerated every cycle. | `beacon export report.html`, `beacon watch -o live.html` |

### INSTALLATION

```bash
uv sync                              # or: pip install -e .
uv run beacon vendors update         # download the vendor (oui) database once
```

python 3.11 or newer. the cli needs neither node nor a browser; the live app is served from the package itself.

### QUICK START

```bash
uv run beacon live                   # opens the app in the browser and guides the first discovery
uv run beacon live --monitor 60      # same, monitoring every 60 s from the start
uv run beacon scan -p top            # one scan from the terminal, with the 100 most common ports
uv run beacon review                 # decide one by one on the pending devices
uv run beacon demo /tmp/demo.db      # create a simulated network to try it without scanning
uv run beacon --db /tmp/demo.db live # and open it
```

`beacon live` listens on `127.0.0.1` and opens a private sign-in link (`beacon live --url` prints it again). `scripts/beacon-live.sh` (or `.bat`) starts the app; with `--report` it keeps the html report regenerated by `watch`.

### WHAT IT DOES TODAY

- **discovery:** arp sweep with `scapy` when privileged; otherwise its own icmp, the system arp table and tcp confirmation. ipv6 neighbours from the system ndp table (a /64 is never swept).
- **identification:** offline oui vendor, randomized macs, hostname (reverse dns, router dns, mdns, netbios), mdns services, os estimate from ttl.
- **ports with honest states:** open, closed (refused), no answer, probe error and "not examined". scanning a subset never closes what it did not examine; a timeout is not a close. coverage and date per device.
- **observed vs inferred protocol:** a banner (ssh, http, telnet, ftp, vnc…) or a tls handshake outweighs the port number; tls certificates are recorded (subject, issuer, names, validity) without claiming trust.
- **explainable risk (rules v2):** every point has a reason, a basis (observed, inferred, history, context) and a date; ssh is encrypted administration, not a cleartext protocol; the gateway and this host get no immunity; without port data the risk is "incomplete", never "safe".
- **guided review:** risk-ordered queue, trust (with a suggested alias), reviewed-but-untrusted, snooze until a date, forget, and identity proposals.
- **continuous identity:** proposes that a new random mac is a known device, with evidence; confirm or reject (for good); trust is never inherited.
- **presence:** sessions, a weekly map and anomalies that only count the hours beacon was watching; configurable time zone; local data left out of reports unless you include it.
- **networks:** the same range behind another router is another network, with its own inventory.
- **history:** every scan is recorded as complete, incomplete, failed or cancelled, with stages and errors; latency and loss per scan; scan comparison that explains differences in scope.
- **alerts:** policies by type, severity, device and risk, with threshold in a window, cooldown, silences and maintenance windows; delivery as a desktop notification or a signed webhook, with bounded retries and idempotency. nothing is sent by default.
- **optional passive listening:** arp, dhcp and mdns with privileges, to scan as soon as an unknown mac shows up.
- **operations:** scan profiles, consistent backups and verified restore, retention with preview, user service (`beacon service install`) and a diagnostic log.

### PLANNED, NOT AVAILABLE

- syn scan with `scapy` in privileged mode.
- a full-screen terminal ui with `textual`.
- rewriting scanners in rust with `pyo3` if a measurement justifies it (current ones do not).
- calibrating the risk, identity and presence weights with real captures.

### PRIVACY AND SECURITY

- everything lives in a local sqlite database (`beacon status` shows where). presence, identity fingerprints, notes and owners stay out of reports unless explicitly chosen; reports can be pseudonymized (hides identifiers, does not guarantee anonymity).
- the live app only answers on loopback, checks `Host` and `Origin`, uses a signed `HttpOnly`/`SameSite=Strict` session, a csrf token, size and rate limits and a csp with no inline code and no remote resources. opening it to the lan requires `--allow-lan` (and preferably `--tls-cert`/`--tls-key`).
- the web app only scans private ranges of at most /16 defined in profiles; it never accepts an arbitrary target nor runs commands built from browser input.

### PLATFORMS

| platform | status |
|---|---|
| linux, python 3.13 | tested: unit, api, cli and browser (chromium) tests, wheel installation. |
| linux with privileges (arp sweep, passive listening) | parsers tested with crafted packets; not verified live with root. |
| macos, windows; python 3.11 and 3.12 | configured in continuous integration; not verified in this delivery. |

### DOCUMENTATION

- [full evolution (in spanish): architecture, api, decisions, performance and tracking](.docs/project-info/evolucion/readme.md)
- [documentation of the cli phase (in spanish)](.docs/project-info/cli-base/readme.md)

### LEGAL NOTICE

use beacon only on networks you own or have explicit authorization to test. scanning networks without permission may be illegal.

### LICENSE

all rights reserved © 2026 rezzt-dev. see the [`license.md`](license.md) file for more information.

### VALIDACION DE LA VERSION 0.2.0

La continuación de la evolución y sus límites están registrados en [validación final](.docs/project-info/evolucion/validacion-final.md), [seguimiento](.docs/project-info/evolucion/seguimiento.md) y [rendimiento medido](.docs/project-info/evolucion/rendimiento.md). Se ha verificado localmente en Linux con Python 3.13 y Chromium; la matriz de otras plataformas está configurada en CI y pendiente de ejecución remota. La migración automática sigue en el esquema v5 y conserva una copia previa para bases antiguas.

En discos sin enlaces simbólicos (por ejemplo, este repositorio en exFAT), crea el entorno fuera del proyecto:

```bash
UV_PROJECT_ENVIRONMENT="$HOME/.cache/beacon/venv" uv sync --group dev --group browser
UV_PROJECT_ENVIRONMENT="$HOME/.cache/beacon/venv" uv run beacon live
```
