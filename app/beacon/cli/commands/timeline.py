 # import libraries ->
import json
from datetime import timedelta
from ipaddress import IPv4Address
from typing import Annotated

import typer

from beacon.cli.commands.options import JsonOut, check_duration, parse_duration
from beacon.cli.context import get_app
from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.presence import MIN_PROFILE_DAYS, Cell, timeline_cells
from beacon.ui.console import console
from beacon.ui.render import bucket_count, timeline_table


 # constants ->
NAME_WIDTH = 24
# marker, device name and the table borders take this much of the terminal
CHROME_WIDTH = NAME_WIDTH + 8


 # helpers ->
def _one_row_per_identity(devices: list[Device]) -> list[Device]:
  """the macs of a linked identity share one history, so only the latest of them gets a row."""
  latest: dict[int | str, Device] = {}
  for device in sorted(devices, key=lambda d: d.last_seen.timestamp() if d.last_seen else 0):
    latest[device.identity_id if device.identity_id is not None else device.key] = device
  return sorted(latest.values(), key=lambda d: IPv4Address(d.ip))


 # command ->
def timeline(
  ctx: typer.Context,
  since: Annotated[
    str, typer.Option("--since", callback=check_duration, help="how far back to look: 30m, 24h, 7d, 2w.")
  ] = "24h",
  device: Annotated[str | None, typer.Option("--device", "-d", help="only this device (mac, ip, alias or hostname).")] = None,
  online_only: Annotated[bool, typer.Option("--online-only", help="only devices that are online now.")] = False,
  step: Annotated[int, typer.Option("--step", min=1, help="minutes per column; merged when the terminal is narrow.")] = 30,
  json_out: JsonOut = False,
) -> None:
  """show when each device was connected, as a time line or as json sessions."""
  app = get_app(ctx)
  repo = app.repository
  now = utcnow()
  window = parse_duration(since)
  start = now - window

  if device:
    selected = [app.find_device_or_exit(device)]
  else:
    selected = repo.list_devices(status=DeviceStatus.ONLINE if online_only else None)
  selected = _one_row_per_identity(selected)
  sessions = repo.sessions_by_identity(selected, since=start)
  present = [d for d in selected if sessions[d.key]]

  if json_out:
    typer.echo(
      json.dumps(
        {
          "since": start.isoformat(),
          "until": now.isoformat(),
          "devices": [
            {"device_key": d.key, "name": d.display_name, "sessions": [s.to_dict() for s in sessions[d.key]]}
            for d in present
          ],
        },
        indent=2,
        ensure_ascii=False,
      )
    )
    return

  total, oldest = repo.presence_span()
  if not total:
    console.print(
      "[muted]no presence history yet: sessions are recorded by `beacon scan` and `beacon watch`[/muted]"
    )
    return
  if not present:
    console.print(f"[muted]no device was connected in the last {since}[/muted]")
    return

  buckets = bucket_count(window, timedelta(minutes=step), max(8, console.width - CHROME_WIDTH))
  rows: list[tuple[Device, list[Cell]]] = [
    (d, timeline_cells(sessions[d.key], start, now, buckets)) for d in present
  ]
  console.print(timeline_table(rows, start, now, NAME_WIDTH))
  slot = window / buckets
  console.print(
    f"[muted]█ present · ▒ partly · · absent    each column ≈ {_minutes(slot)}[/muted]"
  )
  days = (now - oldest).days if oldest else 0
  if days < MIN_PROFILE_DAYS:
    console.print(
      f"[muted]history: {days}/{MIN_PROFILE_DAYS} days · unusual presence needs {MIN_PROFILE_DAYS} days of data per device[/muted]"
    )


def _minutes(value: timedelta) -> str:
  seconds = value.total_seconds()
  if seconds < 90:
    return f"{seconds:.0f} s"
  minutes = seconds / 60
  return f"{minutes:.0f} min" if minutes < 120 else f"{minutes / 60:.1f} h"
