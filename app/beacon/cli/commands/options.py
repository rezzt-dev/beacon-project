 # import libraries ->
import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer

from beacon.core.models import ScanMode
from beacon.scanners.ports import parse_port_spec


 # shared option types ->
_DURATION = re.compile(r"^(\d+)([mhdw])$")
_DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_duration(value: str) -> timedelta:
  """`30m`, `24h`, `7d` or `2w` as a timedelta; anything else is a usage error."""
  match = _DURATION.match(value.strip().lower())
  if match is None or int(match.group(1)) == 0:
    raise typer.BadParameter(f"{value!r} is not a duration; use a number and a unit: 30m, 24h, 7d or 2w")
  return timedelta(**{_DURATION_UNITS[match.group(2)]: int(match.group(1))})


def check_duration(value: str) -> str:
  parse_duration(value)
  return value


def _parse_ports(value: str | None) -> str | None:
  if value is not None:
    try:
      parse_port_spec(value)
    except ValueError as exc:
      raise typer.BadParameter(str(exc)) from exc
  return value


Target = Annotated[
  str | None,
  typer.Argument(help="network to scan in cidr notation (e.g. 192.168.1.0/24). defaults to the interface network.", show_default=False),
]
Interface = Annotated[str | None, typer.Option("--iface", "-i", help="network interface to use.", show_default=False)]
Ports = Annotated[
  str | None,
  typer.Option(
    "--ports",
    "-p",
    callback=_parse_ports,
    help="ports to scan: [bold]top[/bold], web, admin, iot, all, 22,80 or 1-1024 (combinable).",
    show_default=False,
  ),
]
Mode = Annotated[ScanMode, typer.Option("--mode", "-m", help="discovery mode: auto picks privileged when root is available.")]
Samples = Annotated[int, typer.Option("--samples", "-s", min=0, max=50, help="latency samples per host (0 disables).")]
NoResolve = Annotated[bool, typer.Option("--no-resolve", help="skip hostname resolution (dns, mdns, netbios).")]
NoBanners = Annotated[bool, typer.Option("--no-banners", help="do not read service banners from open ports.")]
Timeout = Annotated[float, typer.Option("--timeout", "-t", min=0.1, max=30, help="discovery timeout per host, seconds.")]
PortTimeout = Annotated[float, typer.Option("--port-timeout", min=0.1, max=30, help="tcp connect timeout, seconds.")]
NoIdentity = Annotated[
  bool, typer.Option("--no-identity", help="skip the mdns service probe and the matching of randomized macs.")
]
NoPresence = Annotated[
  bool, typer.Option("--no-presence", help="do not record presence sessions or raise presence anomalies.")
]
Output = Annotated[
  Path | None,
  typer.Option("--output", "-o", help="export results to a file (.json, .csv or .html).", show_default=False),
]
LiveOutput = Annotated[
  Path | None,
  typer.Option(
    "--output",
    "-o",
    help="keep a live export updated after every scan; an .html file auto-refreshes in the browser.",
    show_default=False,
  ),
]
Format = Annotated[str | None, typer.Option("--format", "-f", help="export format, overrides the file extension.", show_default=False)]
JsonOut = Annotated[bool, typer.Option("--json", help="print machine readable json to stdout.")]
