 # import libraries ->
import json
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.table import Table

from beacon.cli.commands.options import JsonOut
from beacon.cli.context import get_app
from beacon.core.models import utcnow
from beacon.services import profiles as profile_service
from beacon.services import settings as app_settings
from beacon.storage.database import backup_to, restore_from, verify
from beacon.ui.console import console, error, success, warn


 # profiles ->
profiles_app = typer.Typer(help="saved scan profiles: target, ports, exclusions, timing.", no_args_is_help=True)


@profiles_app.command("list")
def profiles_list(ctx: typer.Context, json_out: JsonOut = False) -> None:
  """list the saved profiles."""
  items = get_app(ctx).repository.list_profiles()
  if json_out:
    typer.echo(json.dumps(items, indent=2, ensure_ascii=False))
    return
  if not items:
    console.print("[muted]no profiles yet; create one with `beacon profiles add <name>`[/muted]")
    return
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
  for column in ("name", "target", "interface", "ports", "exclude", "interval"):
    table.add_column(column)
  for p in items:
    table.add_row(
      p["name"],
      p["target"] or "interface network",
      p["interface"] or "default",
      p["ports"] or "—",
      ", ".join(p["exclude"]) or "—",
      f"{p['interval_seconds']}s" if p["interval_seconds"] else "manual",
    )
  console.print(table)


@profiles_app.command("add")
def profiles_add(
  ctx: typer.Context,
  name: Annotated[str, typer.Argument(help="profile name.")],
  target: Annotated[str | None, typer.Option("--target", help="private cidr; defaults to the interface network.")] = None,
  interface: Annotated[str | None, typer.Option("--iface", "-i", help="network interface.")] = None,
  ports: Annotated[str | None, typer.Option("--ports", "-p", help="port spec: top, web, admin, 22,80, 1-1024.")] = None,
  exclude: Annotated[list[str] | None, typer.Option("--exclude", "-x", help="address or range never probed (repeatable).")] = None,
  interval: Annotated[int | None, typer.Option("--interval", min=10, max=86400, help="monitor every N seconds.")] = None,
) -> None:
  """save a scan profile."""
  try:
    created = profile_service.create(
      get_app(ctx).repository,
      {"name": name, "target": target, "interface": interface, "ports": ports, "exclude": exclude or [], "interval_seconds": interval},
      "cli",
    )
  except ValueError as exc:
    error(str(exc))
    raise typer.Exit(1) from exc
  success(f"profile {created['name']!r} saved (id {created['id']})")


@profiles_app.command("remove")
def profiles_remove(ctx: typer.Context, name: Annotated[str, typer.Argument(help="profile name.")]) -> None:
  """delete a profile; scans already made with it are kept."""
  repo = get_app(ctx).repository
  found = repo.get_profile_by_name(name)
  if found is None or not repo.delete_profile(found["id"], "cli"):
    error(f"no profile named {name!r}")
    raise typer.Exit(1)
  success(f"profile {name!r} removed")


 # networks ->
def networks(ctx: typer.Context, json_out: JsonOut = False) -> None:
  """list the networks beacon tells apart (same range behind another router = another network)."""
  items = get_app(ctx).repository.list_networks()
  if json_out:
    typer.echo(json.dumps(items, indent=2, ensure_ascii=False))
    return
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
  for column in ("id", "name", "range", "gateway", "devices", "last scan"):
    table.add_column(column)
  for n in items:
    gateway = f"{n['gateway_ip'] or '?'} ({n['gateway_mac'] or 'mac unknown'})"
    table.add_row(str(n["id"]), n["name"] or "—", n["cidr"], gateway, f"{n['online']}/{n['devices']}", n["last_scan_at"] or "never")
  console.print(table)


 # database maintenance ->
def backup(
  ctx: typer.Context,
  target: Annotated[Path | None, typer.Argument(help="destination file; defaults to <data dir>/backups/.", show_default=False)] = None,
) -> None:
  """copy the database consistently, even while beacon live or watch are writing to it."""
  app = get_app(ctx)
  destination = target or app.settings.data_dir / "backups" / f"beacon-{utcnow():%Y%m%dT%H%M%SZ}.db"
  backup_to(app.repository.conn, destination)
  app.repository.record_audit("cli", "backup", "database", None, path=str(destination))
  problems = verify(destination)
  if problems:
    error(f"the copy failed verification: {problems[0]}")
    raise typer.Exit(1)
  success(f"backup written and verified: {destination}")


def restore(
  ctx: typer.Context,
  source: Annotated[Path, typer.Argument(help="a backup made by `beacon backup`.")],
  yes: Annotated[bool, typer.Option("--yes", "-y", help="skip the confirmation prompt.")] = False,
) -> None:
  """replace the database with a verified backup. stop beacon live and watch first."""
  app = get_app(ctx)
  leases = [lease for lease in app.repository.list_leases() if lease["active"]]
  if leases:
    error(f"{leases[0]['kind']} (pid {leases[0]['pid']}) is using the database", "stop beacon live / watch and try again")
    raise typer.Exit(1)
  if not yes:
    typer.confirm(f"replace {app.settings.db_path} with {source}? the current file is kept as .before-restore", abort=True)
  app.close()
  try:
    restore_from(source, app.settings.db_path)
  except (RuntimeError, OSError) as exc:
    error(str(exc))
    raise typer.Exit(1) from exc
  success(f"database restored from {source}")


def retention(
  ctx: typer.Context,
  apply: Annotated[bool, typer.Option("--apply", help="delete; without it only shows what would go.")] = False,
) -> None:
  """apply the retention policy (settings) to events, sessions, measurements, scans, audit and the change feed."""
  repo = get_app(ctx).repository
  policy = app_settings.retention(repo)
  counts = repo.apply_retention(policy, "cli") if apply else repo.retention_preview(policy)
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
  table.add_column("history")
  table.add_column("kept for")
  table.add_column("deleted" if apply else "would delete", justify="right")
  days = policy.to_dict()
  for name, count in counts.items():
    key = {"port_coverage": "scans_days"}.get(name, f"{name}_days")
    table.add_row(name, f"{days.get(key)} days" if days.get(key) else "forever", str(count))
  console.print(table)
  if not apply:
    warn("nothing deleted yet; run again with --apply. pending reviews and open sessions are always kept")


 # demo data ->
def demo(
  target: Annotated[Path, typer.Argument(help="a new database file to fill with simulated data.")],
  devices: Annotated[int, typer.Option("--devices", min=1, max=20000, help="simulated devices.")] = 50,
  events: Annotated[int, typer.Option("--events", min=0, max=1_000_000, help="extra simulated events.")] = 500,
  days: Annotated[int, typer.Option("--days", min=1, max=60, help="days of hourly history.")] = 14,
) -> None:
  """create a database with a simulated network (198.18.0.0/16, test macs) to try beacon live safely.

  open it with `beacon --db <file> live`. it never touches your real inventory.
  """
  from beacon.demo import populate

  if target.exists():
    error(f"{target} already exists", "demo data only goes into a new file")
    raise typer.Exit(1)
  with console.status("generating simulated data…"):
    counts = populate(target, devices, events, days)
  success(f"simulated network written to {target}: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
  console.print(f"[muted]open it with[/muted] beacon --db {target} live")
