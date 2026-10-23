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
beacon scan                      # primer escaneo: todos los dispositivos salen como nuevos
beacon devices trust-all         # marca el estado actual como línea base conocida
beacon devices trust 192.168.1.1 --alias router
beacon scan -p top -o informe.html
beacon watch -n 60 -o vivo.html  # monitorización continua con exportación en vivo
```
a partir de la línea base, cualquier dispositivo que aparezca y no esté marcado como de confianza genera una alerta.

para tareas programadas (cron, systemd timers), `--fail-on-alert` hace que `beacon scan` termine con código `3` si hubo alertas, y `--json` imprime el resultado completo por la salida estándar.
---
####   AVISO
utiliza beacon únicamente en redes propias o sobre las que tengas autorización expresa.
---
