 # import libraries ->
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from beacon import __version__
from beacon.cli.commands.options import Format, JsonOut, check_duration, parse_duration
from beacon.cli.context import get_app
from beacon.core.events import EventType, Severity
from beacon.core.models import DeviceStatus, utcnow
from beacon.export import export_to_file
from beacon.scanners.privileges import can_open_raw_socket, scapy_available
from beacon.ui.console import console, success
from beacon.ui.render import events_table


 # events ->
def events(
  ctx: typer.Context,
  limit: Annotated[int, typer.Option("--limit", "-l", min=1, help="maximum number of events.")] = 30,
  kind: Annotated[list[EventType] | None, typer.Option("--type", help="filter by event type (repeatable).")] = None,
  severity: Annotated[Severity | None, typer.Option("--severity", help="minimum severity.")] = None,
  device: Annotated[str | None, typer.Option("--device", "-d", help="only events of this device.")] = None,
  pending: Annotated[
    bool, typer.Option("--pending", help="only alerts and warnings that no one has reviewed (see `beacon review`).")
  ] = False,
  json_out: JsonOut = False,
) -> None:
  """show the event history: new devices, disconnections, ip changes, ports, presence."""
  app = get_app(ctx)
  device_key = app.find_device_or_exit(device).key if device else None
  found = app.repository.list_events(
    limit=limit, device_key=device_key, types=kind, min_severity=severity, pending_only=pending
  )
  if json_out:
    typer.echo(json.dumps([e.to_dict() for e in found], indent=2, ensure_ascii=False))
  elif found:
    console.print(events_table(found, title=None))
  else:
    console.print("[muted]nothing pending review[/muted]" if pending else "[muted]no events recorded yet[/muted]")


 # export ->
def export(
  ctx: typer.Context,
  path: Annotated[Path, typer.Argument(help="destination file; the extension selects the format.")],
  fmt: Format = None,
  online: Annotated[bool, typer.Option("--online", help="only devices seen in the last scan.")] = False,
  events_limit: Annotated[int, typer.Option("--events", min=0, help="recent events to include (json/html).")] = 50,
  include_fingerprint: Annotated[
    bool, typer.Option("--include-fingerprint", help="add the identity fingerprint (mdns services) to json exports.")
  ] = False,
) -> None:
  """export the stored inventory to json, csv or a standalone html report."""
  repo = get_app(ctx).repository
  devices = repo.list_devices(status=DeviceStatus.ONLINE if online else None)
  recent = repo.list_events(limit=events_limit) if events_limit else []
  last = repo.stats()["last_scan"]
  meta = {
    "network": last["network"] if last else None,
    "include_fingerprint": include_fingerprint,
    "ports_known": repo.ports_ever_scanned(),
  }
  written = export_to_file(path, devices, recent, meta, fmt)
  success(f"exported {len(devices)} devices to {written}")


 # prune ->
def prune(
  ctx: typer.Context,
  sessions_older_than: Annotated[
    str,
    typer.Option(
      "--sessions-older-than",
      callback=check_duration,
      help="delete presence sessions that ended longer ago than this (30m, 24h, 365d, 52w).",
    ),
  ],
) -> None:
  """delete old presence history to keep the database small."""
  removed = get_app(ctx).repository.prune_sessions(utcnow() - parse_duration(sessions_older_than))
  success(f"{removed} presence sessions removed")


 # status ->
def status(ctx: typer.Context) -> None:
  """show where data lives, inventory counters and available scan capabilities."""
  app = get_app(ctx)
  stats = app.repository.stats()
  vendors = app.vendors
  raw = can_open_raw_socket()
  grid = Table.grid(padding=(0, 2))
  grid.add_column(style="muted")
  grid.add_column()
  last = stats["last_scan"]
  for label, value in (
    ("version", __version__),
    ("database", str(app.settings.db_path)),
    ("oui database", f"{vendors.source} ({len(vendors):,} prefixes)" if len(vendors) else "[warning]missing - run `beacon vendors update`[/warning]"),
    ("devices", f"{stats['total']} known · {stats['online']} online · {stats['untrusted']} untrusted · {stats['randomized']} randomized macs"),
    ("scans", f"{stats['scans']}" + (f" · last {last['finished_at']} on {last['network']}" if last else "")),
    ("raw sockets", "[ok]available[/ok]" if raw else "[warning]not available (unprivileged mode)[/warning]"),
    ("scapy", "[ok]installed[/ok]" if scapy_available() else "[warning]missing[/warning]"),
  ):
    grid.add_row(label, value)
  console.print(grid)
