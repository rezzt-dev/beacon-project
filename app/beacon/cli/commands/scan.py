 # import libraries ->
import json
import time
from datetime import timedelta
from typing import Annotated

import typer
from rich.live import Live

from beacon.cli.commands.options import (
  Format,
  Interface,
  JsonOut,
  LiveOutput,
  Mode,
  NoBanners,
  NoIdentity,
  NoPresence,
  NoResolve,
  Output,
  Ports,
  PortTimeout,
  Samples,
  Target,
  Timeout,
)
from beacon.cli.context import LeaseBusy, get_app, take_lease
from beacon.core.events import EventBus, Severity
from beacon.core.models import ScanMode
from beacon.core.presence import SESSION_GAP
from beacon.core.report import ScanReport
from beacon.core.risk import events_at_risk
from beacon.export import export_to_file
from beacon.pipeline import ScanError, ScanOptions
from beacon.scanners.network import TargetError
from beacon.scanners.ports import parse_port_spec
from beacon.services import profiles as profile_service
from beacon.services.risk import assess_devices
from beacon.ui.console import console, err_console, error, success
from beacon.ui.live import WatchView
from beacon.ui.render import devices_table, events_table, scan_summary


 # constants ->
EXIT_ALERTS = 3
EXIT_BUSY = 4
SCAN_LEASE = timedelta(minutes=15)
Profile = Annotated[
  str | None,
  typer.Option("--profile", help="use a saved profile (target, ports, exclusions, timing); other scan flags are ignored.", show_default=False),
]


def _from_profile(app, name: str, trigger: str):
  found = app.repository.get_profile_by_name(name)
  if found is None:
    error(f"no profile named {name!r}", "list them with `beacon profiles list`")
    raise typer.Exit(1)
  return profile_service.scan_options(found, trigger)


def _export_meta(report: ScanReport, **extra: object) -> dict[str, object]:
  """what the exports show about the scan besides the devices: where, how and how long."""
  return {
    "network": report.network,
    "interface": report.interface,
    "mode": str(report.mode),
    "duration": round(report.duration, 1),
    **extra,
  }


 # scan ->
def scan(
  ctx: typer.Context,
  target: Target = None,
  interface: Interface = None,
  ports: Ports = None,
  mode: Mode = ScanMode.AUTO,
  samples: Samples = 3,
  timeout: Timeout = 1.5,
  port_timeout: PortTimeout = 1.0,
  no_resolve: NoResolve = False,
  no_banners: NoBanners = False,
  output: Output = None,
  fmt: Format = None,
  json_out: JsonOut = False,
  no_save: Annotated[bool, typer.Option("--no-save", help="do not store results or events in the database.")] = False,
  grace: Annotated[
    int, typer.Option("--offline-grace", min=0, help="seconds a device may be missing before it is reported offline.")
  ] = 0,
  fail_on_alert: Annotated[
    bool, typer.Option("--fail-on-alert", help=f"exit with code {EXIT_ALERTS} when an alert is raised (cron/ci).")
  ] = False,
  fail_on_risk: Annotated[
    int | None,
    typer.Option(
      "--fail-on-risk",
      min=0,
      max=100,
      help=f"exit with code {EXIT_ALERTS} when a warning or alert hits a device with at least this risk score (cron/ci).",
      show_default=False,
    ),
  ] = None,
  no_identity: NoIdentity = False,
  no_presence: NoPresence = False,
  profile: Profile = None,
) -> None:
  """run one discovery scan: find devices, fingerprint them and report changes."""
  app = get_app(ctx)
  options = _from_profile(app, profile, "cli") if profile else ScanOptions(
    target=target,
    interface=interface,
    mode=mode,
    ports=parse_port_spec(ports) if ports else (),
    discovery_timeout=timeout,
    port_timeout=port_timeout,
    latency_samples=samples,
    resolve_hostnames=not no_resolve,
    grab_banners=not no_banners,
    offline_grace=float(grace),
    identity=not no_identity,
    presence=not no_presence,
    save=not no_save,
  )
  if no_save:
    options.save = False
  try:
    scope = take_lease(app.repository, options, "cli-scan", SCAN_LEASE)
  except LeaseBusy as exc:
    error(str(exc), "wait for it to finish, or stop the monitor in beacon live / the other watch")
    raise typer.Exit(EXIT_BUSY) from exc
  try:
    report = app.run_scan(options, show_progress=not json_out)
  finally:
    if scope:
      app.repository.release_lease(scope)

  if json_out:
    typer.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
  else:
    console.print(devices_table(report.devices, show_ports=bool(options.ports)))
    if report.events:
      console.print(events_table(report.events))
    console.print(scan_summary(report))

  if output is not None:
    path = export_to_file(output, report.devices, report.events, _export_meta(report), fmt)
    (err_console.print if json_out else success)(f"exported {len(report.devices)} devices to {path}")

  if fail_on_alert and report.alerts:
    raise typer.Exit(EXIT_ALERTS)
  if fail_on_risk is not None:
    ports_known = bool(options.ports) or app.repository.ports_ever_scanned()
    if events_at_risk(report.devices, report.events, fail_on_risk, ports_known):
      raise typer.Exit(EXIT_ALERTS)


 # watch ->
def watch(
  ctx: typer.Context,
  target: Target = None,
  interface: Interface = None,
  ports: Ports = None,
  mode: Mode = ScanMode.AUTO,
  interval: Annotated[int, typer.Option("--interval", "-n", min=10, help="seconds between scans.")] = 60,
  samples: Samples = 3,
  timeout: Timeout = 1.5,
  no_resolve: NoResolve = False,
  output: LiveOutput = None,
  no_identity: NoIdentity = False,
  no_presence: NoPresence = False,
  bell: Annotated[bool, typer.Option("--bell", help="ring the terminal bell on every alert.")] = False,
  grace: Annotated[
    int | None,
    typer.Option("--offline-grace", min=0, help="seconds a device may be missing before it is reported offline [default: 2 x interval]."),
  ] = None,
  profile: Profile = None,
) -> None:
  """monitor the network continuously with a live table and alerts on unknown devices."""
  app = get_app(ctx)
  options = _from_profile(app, profile, "watch") if profile else ScanOptions(
    target=target,
    interface=interface,
    mode=mode,
    ports=parse_port_spec(ports) if ports else (),
    discovery_timeout=timeout,
    latency_samples=samples,
    resolve_hostnames=not no_resolve,
    offline_grace=float(2 * interval if grace is None else grace),
    identity=not no_identity,
    presence=not no_presence,
    # scans are `interval` apart: a stay is only broken when several of them are missed
    presence_gap=max(SESSION_GAP.total_seconds(), 3.0 * interval),
  )
  options.trigger = "watch"
  view = WatchView(interval=interval, output=output)
  lease_ttl = timedelta(seconds=3 * interval + 300)
  scope: str | None = None
  bus = EventBus()
  bus.subscribe(view.on_event)
  if bell:
    bus.subscribe(lambda event: console.bell() if event.severity == Severity.ALERT else None)

  try:
    with Live(view, console=console, refresh_per_second=2, transient=False):
      while True:
        try:
          # renewed every cycle: if this process dies, the lease expires and others may scan again
          scope = take_lease(app.repository, options, "cli-watch", lease_ttl) or scope
        except LeaseBusy as exc:
          view.fail(str(exc))
          time.sleep(interval)
          continue
        try:
          report = app.run_scan(options, bus=bus, progress=view)
        except (TargetError, ScanError, OSError) as exc:
          # a dropped wi-fi or a vanished interface must not end a monitoring session
          view.fail(str(exc))
          time.sleep(interval)
          continue
        inventory = app.repository.list_devices()
        view.update(report, inventory)
        if output is not None:
          recent = app.repository.list_events(limit=100)
          meta = _export_meta(
            report, refresh=interval, ports_known=app.repository.ports_ever_scanned(), risks=assess_devices(app.repository, inventory)
          )
          export_to_file(output, inventory, recent, meta)
        time.sleep(interval)
  except KeyboardInterrupt:
    console.print(view.summary())
  finally:
    if scope:
      app.repository.release_lease(scope)
