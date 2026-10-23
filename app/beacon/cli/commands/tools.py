 # import libraries ->
import asyncio
import contextlib
import json
import socket
from typing import Annotated

import typer
from rich import box
from rich.table import Table

from beacon.cli.commands.options import JsonOut, NoBanners, PortTimeout
from beacon.core.models import Latency
from beacon.scanners.icmp import IcmpPinger
from beacon.scanners.latency import measure_latency
from beacon.scanners.network import default_interface, list_interfaces
from beacon.scanners.ports import parse_port_spec, scan_ports
from beacon.ui.console import console, err_console
from beacon.ui.render import fmt_latency, interfaces_table


 # helpers ->
HostArg = Annotated[str, typer.Argument(help="ip address or hostname.")]


def _resolve(host: str) -> str:
  try:
    return socket.gethostbyname(host)
  except OSError as exc:
    raise typer.BadParameter(f"cannot resolve {host!r}: {exc}") from exc


 # ports ->
def ports(
  host: HostArg,
  spec: Annotated[str, typer.Option("--ports", "-p", help="top, web, admin, iot, all, 22,80 or 1-1024.")] = "top",
  timeout: PortTimeout = 1.0,
  concurrency: Annotated[int, typer.Option("--concurrency", "-c", min=1, max=5000, help="parallel connections.")] = 512,
  no_banners: NoBanners = False,
  json_out: JsonOut = False,
) -> None:
  """tcp connect scan of a single host (no privileges required)."""
  ip = _resolve(host)
  port_list = parse_port_spec(spec)
  with err_console.status(f"scanning {len(port_list)} ports on {ip}…", spinner="dots") if not json_out else contextlib.nullcontext():
    found = asyncio.run(
      scan_ports(ip, port_list, timeout, banner_timeout=None if no_banners else 1.5, workers=min(concurrency, len(port_list)))
    )
  if json_out:
    typer.echo(json.dumps({"host": host, "ip": ip, "scanned": len(port_list), "open": [p.to_dict() for p in found]}, indent=2))
    return
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold", title=f"{host} ({ip})", title_justify="left")
  table.add_column("port", justify="right", style="bold")
  table.add_column("service")
  table.add_column("rtt", justify="right", style="muted")
  table.add_column("banner", overflow="fold")
  for p in found:
    table.add_row(f"{p.port}/tcp", p.service or "—", f"{p.rtt_ms:.1f} ms" if p.rtt_ms else "—", p.banner or "—")
  console.print(table)
  console.print(f"[muted]{len(found)} open of {len(port_list)} scanned[/muted]")


 # ping ->
def ping(
  host: HostArg,
  count: Annotated[int, typer.Option("--count", "-c", min=1, max=1000, help="number of probes.")] = 5,
  interval: Annotated[float, typer.Option("--interval", min=0.05, help="seconds between probes.")] = 0.5,
  timeout: Annotated[float, typer.Option("--timeout", "-t", min=0.1, help="seconds to wait for each reply.")] = 1.0,
  json_out: JsonOut = False,
) -> None:
  """measure latency, jitter and loss (icmp, falling back to tcp handshakes)."""
  ip = _resolve(host)

  async def measure() -> tuple[Latency, int | None]:
    pinger = IcmpPinger.open()
    try:
      return await measure_latency(ip, count, timeout, pinger, interval=interval)
    finally:
      if pinger is not None:
        pinger.close()

  latency, ttl = asyncio.run(measure())
  if json_out:
    typer.echo(json.dumps({"host": host, "ip": ip, "ttl": ttl, **latency.to_dict()}, indent=2))
    return
  console.print(f"[bold]{host}[/bold] ({ip}) via {latency.method}: ", fmt_latency(latency), end="")
  console.print(f"  [muted]{latency.received}/{latency.sent} replies · min {latency.min} · max {latency.max} ms" + (f" · ttl {ttl}" if ttl else "") + "[/muted]")
  if not latency.received:
    raise typer.Exit(1)


 # interfaces ->
def interfaces(json_out: JsonOut = False) -> None:
  """list ipv4 interfaces; the one marked ★ is used by default."""
  found = list_interfaces()
  default = default_interface()
  if json_out:
    typer.echo(
      json.dumps(
        [
          {
            "name": i.name,
            "ip": str(i.ip),
            "network": str(i.network),
            "mac": i.mac,
            "gateway": str(i.gateway) if i.gateway else None,
            "default": default is not None and i == default,
          }
          for i in found
        ],
        indent=2,
      )
    )
    return
  console.print(interfaces_table(found, default))
