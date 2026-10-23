###  BEACON PROJECT  |  INSTALACION Y USO
> requisitos, instalación del entorno, privilegios y primeros pasos con la cli.
---
####   REQUISITOS
   - python 3.11 o superior.
   - [`uv`](https://docs.astral.sh/uv/) recomendado (también funciona con `pip`).
   - linux, macos o windows. en windows el modo privilegiado necesita npcap y una terminal de administrador.

dependencias de ejecución declaradas en `pyproject.toml`: `typer`, `rich`, `psutil` y `scapy`. dependencias de desarrollo (grupo `dev`): `pytest` y `ruff`.
---
####   INSTALACION
con `uv`, desde la raíz del repositorio:
```bash
uv sync                    # crea el entorno e instala beacon en modo editable
uv run beacon --help
```
con `pip`:
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
beacon --help
```
> nota: si el repositorio está en un disco que no admite enlaces simbólicos (ntfs, exfat...), `uv` y `venv` no pueden crear `.venv` dentro de él. en ese caso hay que crear el entorno fuera del repositorio con `UV_PROJECT_ENVIRONMENT=~/.venvs/beacon uv sync` y usar la misma variable en `uv run`.

también se puede lanzar sin instalar el comando, desde el código fuente:
```bash
python app/app.py --help
python -m beacon --help      # con app/ en el PYTHONPATH
```
---
####   PRIVILEGIOS
beacon elige el modo automáticamente (`--mode auto`):

| modo | cuándo | cómo descubre |
|---|---|---|
| `privileged` | root/administrador (o `cap_net_raw`) y `scapy` instalado | barrido arp con broadcast ethernet (`srp`). es el más fiable: detecta incluso hosts que bloquean icmp y tcp. |
| `unprivileged` | usuario normal | barrido icmp sin privilegios, lectura de la tabla arp del sistema y confirmación tcp. no necesita root. |

en linux, el icmp sin privilegios depende de `net.ipv4.ping_group_range` (abierto por defecto en la mayoría de distribuciones). si no está disponible, beacon "ceba" la caché arp con datagramas udp.
---
####   DATOS LOCALES
| dato | ruta por defecto (linux) | variable |
|---|---|---|
| directorio de datos | `~/.local/share/beacon/` | `BEACON_HOME` |
| base de datos sqlite | `~/.local/share/beacon/beacon.db` | `BEACON_DB` o `--db` |
| base de fabricantes | `~/.local/share/beacon/manuf` | — |

en macos se usa `~/Library/Application Support/beacon/` y en windows `%LOCALAPPDATA%\beacon\`. si no existe la copia del usuario, se intenta usar el `manuf` de una instalación de wireshark.
---
####   PRIMEROS PASOS
```bash
beacon vendors update            # una vez: descarga la base oui (~58.000 prefijos)
beacon interfaces                # comprueba la interfaz y la red detectadas (★)
beacon scan -p top               # primer escaneo: los dispositivos salen como avisos, no como alertas
beacon review                    # recorre cada dispositivo con su riesgo: confiar, alias, ignorar, olvidar
beacon devices trust-all         # alternativa si conoces toda la red: línea base de golpe
beacon scan -p top -o informe.html
beacon watch -n 60 -o vivo.html  # monitorización continua con exportación en vivo
beacon timeline --since 7d       # quién estuvo conectado y cuándo
```
a partir de la línea base, cualquier dispositivo que aparezca y no esté marcado como de confianza genera una alerta. si un móvil con mac aleatorizada vuelve con otra mac, beacon propone vincularla (`beacon devices candidates` y `beacon devices link`) en lugar de alertar como si fuera un intruso.

para tareas programadas (cron, systemd timers), `--fail-on-alert` hace que `beacon scan` termine con código `3` si hubo alertas, `--fail-on-risk 55` solo si un aviso afecta a un dispositivo de riesgo alto, y `--json` imprime el resultado completo por la salida estándar.

las sesiones de presencia (cuándo estuvo conectado cada dispositivo) son datos personales: se guardan solo en la base local, no salen en las exportaciones y se pueden desactivar con `--no-presence` o borrar con `beacon prune --sessions-older-than 365d`.
---
####   AVISO
utiliza beacon únicamente en redes propias o sobre las que tengas autorización expresa.
---
