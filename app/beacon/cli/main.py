 # import libraries ->
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.logging import RichHandler

from beacon import __version__
from beacon.cli.commands import devices, inventory, scan, tools, vendors
from beacon.cli.context import AppContext
from beacon.config import Settings
from beacon.pipeline import ScanError
from beacon.scanners.network import TargetError
from beacon.ui.console import err_console, error


 # application ->
app = typer.Typer(
  name="beacon",
  help="discover, fingerprint and monitor every device on your local network.",
  no_args_is_help=True,
  rich_markup_mode="rich",
  context_settings={"help_option_names": ["-h", "--help"]},
  pretty_exceptions_enable=False,
)
app.command(rich_help_panel="scanning")(scan.scan)
app.command(rich_help_panel="scanning")(scan.watch)
app.command(rich_help_panel="tools")(tools.ports)
app.command(rich_help_panel="tools")(tools.ping)
app.command(rich_help_panel="tools")(tools.interfaces)
app.command(rich_help_panel="inventory")(inventory.events)
app.command(rich_help_panel="inventory", name="export")(inventory.export)
app.command(rich_help_panel="inventory")(inventory.status)
app.add_typer(devices.app, name="devices", rich_help_panel="inventory")
app.add_typer(vendors.app, name="vendors", rich_help_panel="tools")


def _version(value: bool) -> None:
  if value:
    typer.echo(f"beacon {__version__}")
    raise typer.Exit()


@app.callback()
def main(
  ctx: typer.Context,
  db: Annotated[Path | None, typer.Option("--db", envvar="BEACON_DB", help="sqlite database path.")] = None,
  verbose: Annotated[bool, typer.Option("--verbose", "-v", help="show debug logs.")] = False,
  _version_flag: Annotated[
    bool, typer.Option("--version", callback=_version, is_eager=True, help="show the version and exit.")
  ] = False,
) -> None:
  logging.basicConfig(
    level=logging.DEBUG if verbose else logging.WARNING,
    format="%(message)s",
    handlers=[RichHandler(console=err_console, show_path=False, rich_tracebacks=verbose)],
  )
  logging.getLogger("scapy").setLevel(logging.ERROR)
  context = AppContext(settings=Settings.load(db), verbose=verbose)
  ctx.obj = context
  ctx.call_on_close(context.close)


 # entry point ->
def run() -> None:
  try:
    app()
  except (TargetError, ScanError, ValueError) as exc:
    error(str(exc))
    sys.exit(1)
  except PermissionError as exc:
    error(f"{exc}. try again with administrator privileges or `--mode unprivileged`.")
    sys.exit(1)
  except KeyboardInterrupt:
    err_console.print("[muted]interrupted[/muted]")
    sys.exit(130)
