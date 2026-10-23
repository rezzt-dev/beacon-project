 # import libraries ->
import json
from typing import Annotated

import typer

from beacon.cli.commands.options import JsonOut
from beacon.cli.context import get_app
from beacon.core.models import DeviceStatus
from beacon.ui.console import console, success
from beacon.ui.render import device_detail, devices_table


 # sub application ->
app = typer.Typer(help="inspect and manage the known device inventory.", no_args_is_help=True)
DeviceRef = Annotated[str, typer.Argument(help="mac, ip, alias or hostname of the device.")]


@app.command("list")
def list_devices(
  ctx: typer.Context,
  online: Annotated[bool, typer.Option("--online", help="only devices seen in the last scan.")] = False,
  untrusted: Annotated[bool, typer.Option("--untrusted", help="only devices not marked as trusted.")] = False,
  json_out: JsonOut = False,
) -> None:
  """list every device beacon has ever seen."""
  repo = get_app(ctx).repository
  devices = repo.list_devices(
    status=DeviceStatus.ONLINE if online else None,
    trusted=False if untrusted else None,
  )
  if json_out:
    typer.echo(json.dumps([d.to_dict() for d in devices], indent=2, ensure_ascii=False))
    return
  console.print(devices_table(devices, show_ports=any(d.open_ports for d in devices)))
  console.print(f"[muted]{len(devices)} devices · ● trusted online · [alert]●[/alert] untrusted online · ○ offline[/muted]")


@app.command()
def show(ctx: typer.Context, ref: DeviceRef, json_out: JsonOut = False) -> None:
  """show everything known about one device, with its recent events."""
  app_ctx = get_app(ctx)
  device = app_ctx.find_device_or_exit(ref)
  events = app_ctx.repository.list_events(limit=15, device_key=device.key)
  if json_out:
    typer.echo(json.dumps({**device.to_dict(), "events": [e.to_dict() for e in events]}, indent=2, ensure_ascii=False))
    return
  console.print(device_detail(device, events))


@app.command()
def trust(
  ctx: typer.Context,
  ref: DeviceRef,
  alias: Annotated[str | None, typer.Option("--alias", "-a", help="friendly name to set at the same time.")] = None,
) -> None:
  """mark a device as known so it no longer raises alerts."""
  app_ctx = get_app(ctx)
  device = app_ctx.find_device_or_exit(ref)
  app_ctx.repository.set_trusted(device.key, True)
  if alias is not None:
    app_ctx.repository.set_alias(device.key, alias.strip() or None)
  success(f"{alias or device.display_name} ({device.key}) is now trusted")


@app.command()
def untrust(ctx: typer.Context, ref: DeviceRef) -> None:
  """remove the trusted mark from a device."""
  app_ctx = get_app(ctx)
  device = app_ctx.find_device_or_exit(ref)
  app_ctx.repository.set_trusted(device.key, False)
  success(f"{device.display_name} ({device.key}) is no longer trusted")


@app.command("trust-all")
def trust_all(
  ctx: typer.Context,
  yes: Annotated[bool, typer.Option("--yes", "-y", help="skip the confirmation prompt.")] = False,
) -> None:
  """trust every device in the inventory (baseline after the first scan of your own network)."""
  repo = get_app(ctx).repository
  pending = repo.list_devices(trusted=False)
  if not pending:
    console.print("[muted]every known device is already trusted[/muted]")
    return
  console.print(devices_table(pending, title="devices that will be trusted", show_ports=False))
  if not yes:
    typer.confirm(f"trust these {len(pending)} devices?", abort=True)
  success(f"{repo.trust_all()} devices marked as trusted")


@app.command()
def alias(
  ctx: typer.Context,
  ref: DeviceRef,
  name: Annotated[str, typer.Argument(help="new alias; an empty string clears it.")],
) -> None:
  """give a device a friendly name."""
  app_ctx = get_app(ctx)
  device = app_ctx.find_device_or_exit(ref)
  app_ctx.repository.set_alias(device.key, name.strip() or None)
  success(f"{device.key} alias {'set to ' + repr(name.strip()) if name.strip() else 'cleared'}")


@app.command()
def forget(
  ctx: typer.Context,
  ref: DeviceRef,
  yes: Annotated[bool, typer.Option("--yes", "-y", help="skip the confirmation prompt.")] = False,
) -> None:
  """delete a device and its ports from the inventory (its events are kept)."""
  app_ctx = get_app(ctx)
  device = app_ctx.find_device_or_exit(ref)
  if not yes:
    typer.confirm(f"forget {device.display_name} ({device.key})?", abort=True)
  app_ctx.repository.delete_device(device.key)
  success(f"{device.key} removed; it will be reported as new if it shows up again")
