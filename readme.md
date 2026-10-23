<div align="center">

# BEACON

**terminal tool that discovers every device on your local network, identifies vendors by mac, scans open ports, measures latency and alerts when an unknown device appears.**

![python](https://img.shields.io/badge/python-3.11%2B-3776ab?style=flat-square&logo=python&logoColor=white)
![status](https://img.shields.io/badge/estado-en%20desarrollo-orange?style=flat-square)
![license](https://img.shields.io/badge/license-all%20rights%20reserved-red?style=flat-square)
![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=flat-square)

[castellano](#castellano) · [english](#english)

</div>

---

## CASTELLANO

### DESCRIPCION

beacon es una herramienta de terminal pensada para administradores de sistemas y perfiles de seguridad. descubre todos los dispositivos conectados a la red local, identifica el fabricante a partir de la mac, escanea puertos abiertos, mide la latencia y avisa cuando aparece un dispositivo desconocido.

el proyecto combina sockets crudos, arp, concurrencia de un gran número de peticiones en tiempo real y parseo de protocolos, junto con un motor de limpieza de datos que permite obtener una salida profesional y exportable.

### CARACTERISTICAS

- **descubrimiento arp:** barrido de la red con broadcast ethernet usando `scapy` (`srp`).
- **fabricante por mac:** base oui del ieee cargada en local, para que funcione sin conexión.
- **escaneo de puertos:** connect scan concurrente con `asyncio`, un `semaphore` y timeouts, sin necesidad de root. como extra, syn scan con `scapy`.
- **latencia:** tiempo de respuesta arp/icmp más rtt de conexión tcp, con varias muestras para calcular media, mínimo, máximo y jitter.
- **tabla en vivo con preview:** interfaz en terminal con `rich` (`live` + `table`) o `textual`, con paneles, filtros y detalle del dispositivo.
- **persistencia y alertas:** `sqlite` para guardar los dispositivos conocidos y detectar los desconocidos al compararlos con la base.
- **exportación:** salida en `json`, `csv` y `html`.
- **modo sin privilegios:** connect scan y lectura de la tabla arp del sistema como alternativa cuando no hay root.
- **triage guiado:** `beacon review` recorre los avisos sin revisar ordenados por una puntuación de riesgo con motivos legibles; el primer escaneo no genera una alerta por cada host.
- **identidad continua:** un móvil con mac aleatorizada que vuelve con otra mac se reconoce por hostname y servicios mdns y se propone como el mismo dispositivo (sin heredar la confianza).
- **ritmo de presencia:** historial de conexiones (`beacon timeline`), mapa de calor semanal por dispositivo y avisos cuando alguien aparece fuera de su rutina o un equipo siempre encendido desaparece. son datos personales: se guardan solo en local, fuera de las exportaciones, y se borran con `beacon prune`.

### STACK TECNICO

| área | tecnología |
|---|---|
| lenguaje | python (con posibilidad de reescribir scanners en rust mediante `pyo3`) |
| red y protocolos | `scapy`, `asyncio` |
| fabricante por mac | `mac-vendor-lookup` o fichero `manuf` de wireshark |
| interfaz | `rich` (cli actual), `textual` (tui prevista) |
| cli | `typer` |
| persistencia | `sqlite` |
| modelos de datos | `dataclass` |
| interfaces de red | `psutil` |

### ARQUITECTURA

```
app/beacon/
├── scanners/    # arp, icmp, puertos, latencia y hostnames: producen datos crudos
├── core/        # modelos, motor de limpieza y diff contra la base: limpia y genera eventos
├── storage/     # sqlite: guarda el estado
├── ui/          # rich: tablas, progreso y vista en vivo
├── export/      # json, csv y html
├── cli/         # comandos typer
└── pipeline.py  # orquesta un escaneo completo
```

los `scanners/` producen datos crudos, `core/` los limpia y genera eventos, `storage/` guarda el estado, y `ui/` y `export/` consumen esos eventos. si algún scanner se queda limitado en rendimiento, puede reescribirse en rust e integrarse con `pyo3`.

### INSTALACION Y USO

```bash
uv sync                          # o: pip install -e .
uv run beacon vendors update     # descarga la base oui una vez
uv run beacon scan               # primer escaneo
uv run beacon review             # revisa cada dispositivo con su riesgo y decide (o: devices trust-all)
uv run beacon watch -o vivo.html # monitorización en vivo con alertas
uv run beacon timeline --since 7d  # quién estuvo conectado y cuándo
```

la documentación completa de la versión cli está en [`.docs/project-info/cli-base/`](.docs/project-info/cli-base/readme.md).

### MOTOR DE LIMPIEZA DE DATOS

- normaliza las macs a un único formato y deduplica fusionando por mac (una ip puede cambiar, la mac no).
- detecta macs aleatorizadas (bit "locally administered"), muy comunes en móviles, para no marcarlas como fabricante desconocido.
- enriquece cada dispositivo con hostname (dns inverso, mdns, netbios), una estimación de so por ttl y banner de servicios.
- mantiene un historial de estado (visto por primera vez, última vez visto, online/offline) y emite eventos de cambio: nuevo, desaparecido y puerto abierto nuevo.
- relaciona las macs aleatorizadas de un mismo dispositivo con evidencias explícitas y guarda sesiones de presencia para detectar comportamientos fuera de patrón.

### CONSIDERACIONES TECNICAS

- `scapy.sniff` bloquea, así que se usa `AsyncSniffer` o un executor para integrarlo con `asyncio`.
- scapy es lento enviando miles de paquetes por segundo, pero en una lan no supone un problema.
- los privilegios (root/npcap en windows) condicionan el diseño, por lo que el modo sin root debe funcionar como alternativa.

### AVISO LEGAL

utiliza beacon únicamente en redes de tu propiedad o sobre las que tengas autorización expresa. el escaneo de redes ajenas sin permiso puede ser ilegal.

### LICENCIA

todos los derechos reservados © 2026 rezzt-dev. consulta el fichero [`license.md`](license.md) para más información.

---

## ENGLISH

### DESCRIPTION

beacon is a terminal tool built for system administrators and security professionals. it discovers every device connected to the local network, identifies the vendor from the mac address, scans open ports, measures latency and alerts when an unknown device appears.

the project combines raw sockets, arp, real-time concurrency over a large number of requests and protocol parsing, along with a data cleaning engine that produces a professional, exportable output.

### FEATURES

- **arp discovery:** network sweep with ethernet broadcast using `scapy` (`srp`).
- **mac vendor lookup:** ieee oui database loaded locally, so it works offline.
- **port scanning:** concurrent connect scan with `asyncio`, a `semaphore` and timeouts, no root required. as an extra, syn scan with `scapy`.
- **latency:** arp/icmp response time plus tcp connection rtt, with multiple samples to compute average, minimum, maximum and jitter.
- **live table with preview:** terminal interface with `rich` (`live` + `table`) or `textual`, with panels, filters and device details.
- **persistence and alerts:** `sqlite` to store known devices and detect unknown ones by comparing against the database.
- **export:** output in `json`, `csv` and `html`.
- **unprivileged mode:** connect scan and reading the system arp table as a fallback when root is not available.
- **guided triage:** `beacon review` walks through unreviewed warnings sorted by a risk score with readable reasons; the first scan no longer raises one alert per host.
- **continuous identity:** a phone with a randomized mac that comes back with another mac is recognized by hostname and mdns services and proposed as the same device (trust is never inherited).
- **presence rhythm:** connection history (`beacon timeline`), a weekly heatmap per device and warnings when a device shows up outside its routine or an always-on one disappears. this is personal data: it stays local, out of exports, and `beacon prune` deletes it.

### TECH STACK

| area | technology |
|---|---|
| language | python (with the option to rewrite scanners in rust through `pyo3`) |
| network and protocols | `scapy`, `asyncio` |
| mac vendor lookup | `mac-vendor-lookup` or wireshark `manuf` file |
| interface | `rich` (current cli), `textual` (planned tui) |
| cli | `typer` |
| persistence | `sqlite` |
| data models | `dataclass` |
| network interfaces | `psutil` |

### ARCHITECTURE

```
app/beacon/
├── scanners/    # arp, icmp, ports, latency and hostnames: produce raw data
├── core/        # models, cleaning engine and diff against the database: cleans data and emits events
├── storage/     # sqlite: stores the state
├── ui/          # rich: tables, progress and live view
├── export/      # json, csv and html
├── cli/         # typer commands
└── pipeline.py  # orchestrates a full scan
```

`scanners/` produce raw data, `core/` cleans it and emits events, `storage/` persists the state, and `ui/` and `export/` consume those events. if a scanner becomes a performance bottleneck, it can be rewritten in rust and integrated through `pyo3`.

### INSTALLATION AND USAGE

```bash
uv sync                          # or: pip install -e .
uv run beacon vendors update     # download the oui database once
uv run beacon scan               # first scan
uv run beacon review             # go through each device with its risk and decide (or: devices trust-all)
uv run beacon watch -o live.html # live monitoring with alerts
uv run beacon timeline --since 7d  # who was connected and when
```

the full documentation of the cli version (in spanish) lives in [`.docs/project-info/cli-base/`](.docs/project-info/cli-base/readme.md).

### DATA CLEANING ENGINE

- normalizes macs to a single format and deduplicates by merging on mac (an ip can change, the mac does not).
- detects randomized macs (the "locally administered" bit), very common on phones, so they are not flagged as unknown vendor.
- enriches each device with hostname (reverse dns, mdns, netbios), an os estimate based on ttl and service banners.
- keeps a state history (first seen, last seen, online/offline) and emits change events: new, disappeared and new open port.
- links the randomized macs of one device with explicit evidence and stores presence sessions to detect behavior outside the usual pattern.

### TECHNICAL NOTES

- `scapy.sniff` blocks, so `AsyncSniffer` or an executor is used to integrate it with `asyncio`.
- scapy is slow when sending thousands of packets per second, but on a lan this is not a problem.
- privileges (root/npcap on windows) shape the design, so the unprivileged mode must work as a fallback.

### LEGAL NOTICE

use beacon only on networks you own or have explicit authorization to test. scanning networks without permission may be illegal.

### LICENSE

all rights reserved © 2026 rezzt-dev. see the [`license.md`](license.md) file for more information.