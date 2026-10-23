 # import libraries ->
import json
from datetime import timedelta
from typing import Annotated

import typer
from rich.console import RenderableType
from rich.markup import escape
from rich.text import Text

from beacon.cli.commands.options import JsonOut
from beacon.cli.context import get_app
from beacon.core.identity import fingerprint, score
from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.presence import PROFILE_WEEKS, build_profile, is_profilable
from beacon.storage import Repository
from beacon.ui.console import console, error, success
from beacon.ui.render import candidates_table, device_detail, devices_table, presence_heatmap


 # sub application ->
app = typer.Typer(help="inspect and manage the known device inventory.", no_args_is_help=True)
DeviceRef = Annotated[str, typer.Argument(help="mac, ip, alias or hostname of the device.")]


@app.command("list")
def list_devices(
  ctx: typer.Context,
  online: Annotated[bool, typer.Option("--online", help="only devices seen in the last scan.")] = False,
  untrusted: Annotated[bool, typer.Option("--untrusted", help="only devices not marked as trusted.")] = False,
  risk: Annotated[bool, typer.Option("--risk", help="add the risk score and its reasons.")] = False,
  json_out: JsonOut = False,
) -> None:
  """list every device beacon has ever seen."""
  app_ctx = get_app(ctx)
  devices = app_ctx.repository.list_devices(
    status=DeviceStatus.ONLINE if online else None,
    trusted=False if untrusted else None,
  )
  risks = app_ctx.assess_devices(devices) if risk else None
  if json_out:
    typer.echo(
      json.dumps(
        [{**d.to_dict(), **(risks[d.key].to_dict() if risks else {})} for d in devices], indent=2, ensure_ascii=False
      )
    )
    return
  console.print(devices_table(devices, show_ports=any(d.open_ports for d in devices), risks=risks))
  console.print(f"[muted]{len(devices)} devices · ● trusted online · [alert]●[/alert] untrusted online · ○ offline[/muted]")


@app.command()
def show(ctx: typer.Context, ref: DeviceRef, json_out: JsonOut = False) -> None:
  """show everything known about one device, with its recent events."""
  app_ctx = get_app(ctx)
  repo = app_ctx.repository
  device = app_ctx.find_device_or_exit(ref)
  events = repo.list_events(limit=15, device_key=device.key)
  risk = app_ctx.assess_devices([device])[device.key]
  members = repo.identity_members(device)
  if json_out:
    data = {
      **device.to_dict(fingerprint=True),
      **risk.to_dict(),
      "identity_members": [m.to_dict(fingerprint=True) for m in members],
      "events": [e.to_dict() for e in events],
    }
    typer.echo(json.dumps(data, indent=2, ensure_ascii=False))
    return
  console.print(device_detail(device, events, risk, members, _presence(repo, device)))


def _presence(repo: Repository, device: Device) -> RenderableType:
  """the weekly presence heatmap, or the reason there is none yet."""
  if not is_profilable(device):
    return Text(
      "presence: this mac is randomized and not linked to an identity, so its history is fragmented "
      "(see `beacon devices candidates`)",
      style="muted",
    )
  now = utcnow()
  sessions = repo.sessions_by_identity([device], since=now - timedelta(weeks=PROFILE_WEEKS))[device.key]
  if not sessions:
    return Text("presence: no sessions recorded yet", style="muted")
  return presence_heatmap(build_profile(sessions, now))


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
def candidates(ctx: typer.Context, json_out: JsonOut = False) -> None:
  """show randomized macs that may be a known device back with a new private address."""
  repo = get_app(ctx).repository
  matches = repo.list_candidates()
  devices = repo.load_devices()
  if json_out:
    typer.echo(
      json.dumps(
        [
          {
            "new": m.new_key,
            "candidate": m.candidate_key,
            "score": m.score,
            "link": str(m.level),
            "evidence": list(m.evidence),
          }
          for m in matches
        ],
        indent=2,
        ensure_ascii=False,
      )
    )
    return
  if not matches:
    console.print("[muted]no link candidates[/muted]")
    return
  console.print(candidates_table(matches, devices))
  console.print("[muted]confirm one with `beacon devices link <new mac> <candidate mac>`[/muted]")


@app.command()
def link(
  ctx: typer.Context,
  new: Annotated[str, typer.Argument(help="the newer mac (mac, ip, alias or hostname).")],
  old: Annotated[str, typer.Argument(help="the older mac of the same physical device.")],
  trust: Annotated[
    bool | None,
    typer.Option("--trust/--no-trust", help="trust the new mac too; asked when omitted. trust is never copied silently."),
  ] = None,
) -> None:
  """declare that two macs are the same physical device: they share an identity and the alias."""
  app_ctx = get_app(ctx)
  new_device = app_ctx.find_device_or_exit(new)
  old_device = app_ctx.find_device_or_exit(old)
  if new_device.key == old_device.key:
    error("a device cannot be linked to itself")
    raise typer.Exit(1)
  if new_device.identity_id is not None and new_device.identity_id == old_device.identity_id:
    console.print("[muted]these devices are already linked[/muted]")
    return
  _, evidence = score(fingerprint(new_device), fingerprint(old_device))
  if evidence:
    console.print(f"[muted]evidence: {escape(', '.join(evidence))}[/muted]")
  if trust is None:
    trust = typer.confirm(f"also trust {new_device.display_name} ({new_device.key})?", default=False)
  repo = app_ctx.repository
  repo.link_devices(new_device.key, old_device.key)
  if trust:
    repo.set_trusted(new_device.key, True)
  linked = repo.find_device(new_device.key) or new_device
  success(f"linked {new_device.key} with {old_device.key} ({escape(linked.display_name)})")


@app.command()
def unlink(ctx: typer.Context, ref: DeviceRef) -> None:
  """take a mac out of its identity."""
  app_ctx = get_app(ctx)
  device = app_ctx.find_device_or_exit(ref)
  if not app_ctx.repository.unlink_device(device.key):
    error(f"{device.key} is not linked to any identity")
    raise typer.Exit(1)
  success(f"{device.key} is no longer linked")


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
