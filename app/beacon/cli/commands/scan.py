 # import libraries ->
import json
import time
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
  NoResolve,
  Output,
  Ports,
  PortTimeout,
  Samples,
  Target,
  Timeout,
)
from beacon.cli.context import get_app
from beacon.core.events import EventBus, Severity
from beacon.core.models import ScanMode
from beacon.export import export_to_file
from beacon.pipeline import ScanOptions
from beacon.scanners.ports import parse_port_spec
from beacon.ui.console import console, err_console, success
from beacon.ui.live import WatchView
from beacon.ui.render import devices_table, events_table, report_summary


 # constants ->
EXIT_ALERTS = 3


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
) -> None:
  """run one discovery scan: find devices, fingerprint them and report changes."""
  app = get_app(ctx)
  options = ScanOptions(
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
    save=not no_save,
  )
  report = app.run_scan(options, show_progress=not json_out)

  if json_out:
    typer.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
  else:
    console.print(devices_table(report.devices, show_ports=bool(options.ports)))
    if report.events:
      console.print(events_table(report.events))
    console.print(report_summary(report))
    if report.first_run:
      console.print(
        "[accent]first scan:[/accent] review the devices above and run "
        "[bold]beacon devices trust-all[/bold] to set them as your known baseline."
      )

  if output is not None:
    path = export_to_file(output, report.devices, report.events, {"network": report.network}, fmt)
    (err_console.print if json_out else success)(f"exported {len(report.devices)} devices to {path}")

  if fail_on_alert and report.alerts:
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
  bell: Annotated[bool, typer.Option("--bell", help="ring the terminal bell on every alert.")] = False,
  grace: Annotated[
    int | None,
    typer.Option("--offline-grace", min=0, help="seconds a device may be missing before it is reported offline [default: 2 x interval]."),
  ] = None,
) -> None:
  """monitor the network continuously with a live table and alerts on unknown devices."""
  app = get_app(ctx)
  options = ScanOptions(
    target=target,
    interface=interface,
    mode=mode,
    ports=parse_port_spec(ports) if ports else (),
    discovery_timeout=timeout,
    latency_samples=samples,
    resolve_hostnames=not no_resolve,
    offline_grace=float(2 * interval if grace is None else grace),
  )
  view = WatchView(interval=interval)
  bus = EventBus()
  bus.subscribe(view.on_event)
  if bell:
    bus.subscribe(lambda event: console.bell() if event.severity == Severity.ALERT else None)

  try:
    with Live(view, console=console, refresh_per_second=2, transient=False):
      while True:
        report = app.run_scan(options, bus=bus, progress=view)
        inventory = app.repository.list_devices()
        view.update(report, inventory)
        if output is not None:
          recent = app.repository.list_events(limit=100)
          export_to_file(output, inventory, recent, {"network": report.network, "refresh": interval})
        time.sleep(interval)
  except KeyboardInterrupt:
    console.print(f"[muted]watch stopped after {view.cycle} scans, {view.alerts} alerts[/muted]")
