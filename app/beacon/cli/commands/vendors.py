 # import libraries ->
from typing import Annotated

import typer

from beacon.cli.context import get_app
from beacon.config import MANUF_URL
from beacon.core.mac import is_randomized, normalize_mac
from beacon.core.vendors import download_manuf
from beacon.ui.console import console, err_console, error, success


 # sub application ->
app = typer.Typer(help="manage the offline mac vendor (ieee oui) database.", no_args_is_help=True)


@app.command()
def update(
  ctx: typer.Context,
  url: Annotated[str, typer.Option("--url", help="source of a wireshark `manuf` formatted file.")] = MANUF_URL,
) -> None:
  """download the latest oui database so vendor lookups work offline."""
  dest = get_app(ctx).settings.oui_path
  with err_console.status(f"downloading {url}…", spinner="dots"):
    try:
      entries = download_manuf(dest, url)
    except (OSError, ValueError) as exc:
      error(f"update failed: {exc}")
      raise typer.Exit(1) from exc
  success(f"{entries:,} vendor prefixes saved to {dest}")


@app.command()
def lookup(ctx: typer.Context, macs: Annotated[list[str], typer.Argument(help="one or more mac addresses.")]) -> None:
  """resolve the vendor of mac addresses."""
  vendors = get_app(ctx).vendors
  for raw in macs:
    mac = normalize_mac(raw)
    if mac is None:
      console.print(f"{raw}  [alert]invalid mac[/alert]")
    elif is_randomized(mac):
      console.print(f"[mac]{mac}[/mac]  [warning]randomized (locally administered) address[/warning]")
    else:
      console.print(f"[mac]{mac}[/mac]  {vendors.lookup(mac) or '[muted]unknown vendor[/muted]'}")
