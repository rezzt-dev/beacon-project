 # import libraries ->
import os
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Annotated

import typer

from beacon.cli.context import get_app
from beacon.ui.console import console, error, hint, success


 # live ->
def live(
  ctx: typer.Context,
  host: Annotated[str, typer.Option("--host", help="address to listen on; loopback unless --allow-lan.")] = "127.0.0.1",
  port: Annotated[int, typer.Option("--port", min=1024, max=65535, help="tcp port of the local web app.")] = 8765,
  allow_lan: Annotated[
    bool, typer.Option("--allow-lan", help="accept connections from the local network (sign-in still required).")
  ] = False,
  tls_cert: Annotated[Path | None, typer.Option("--tls-cert", help="serve https with this certificate (pem).", show_default=False)] = None,
  tls_key: Annotated[Path | None, typer.Option("--tls-key", help="private key of --tls-cert (pem).", show_default=False)] = None,
  no_open: Annotated[bool, typer.Option("--no-open", help="do not open the browser.")] = False,
  monitor: Annotated[
    int | None,
    typer.Option("--monitor", min=10, max=86400, help="start monitoring right away, every N seconds.", show_default=False),
  ] = None,
  profile: Annotated[str | None, typer.Option("--profile", help="network profile the monitor uses.", show_default=False)] = None,
  url_only: Annotated[bool, typer.Option("--url", help="print the sign-in link and exit.")] = False,
  rotate_token: Annotated[bool, typer.Option("--rotate-token", help="invalidate old sign-in links and sessions.")] = False,
  log_file: Annotated[
    Path | None, typer.Option("--log-file", help="write a rotating diagnostic log here (5 files of 2 mb).", show_default=False)
  ] = None,
) -> None:
  """open beacon live: the local web app to explore, review and monitor the network.

  the html report (`beacon export report.html`, `beacon watch -o`) stays available for a
  portable, read-only snapshot; live adds navigation, history and actions that are saved.
  """
  from beacon.web.server import LiveConfig, login_url, serve

  app = get_app(ctx)
  profile_id = None
  if profile is not None:
    found = app.repository.get_profile_by_name(profile)
    if found is None:
      error(f"no profile named {profile!r}", "list them with `beacon profiles list`")
      raise typer.Exit(1)
    profile_id = found["id"]
  config = LiveConfig(
    host=host,
    port=port,
    allow_lan=allow_lan,
    tls_cert=tls_cert,
    tls_key=tls_key,
    rotate_token=rotate_token,
    monitor_profile=profile_id,
    monitor_interval=monitor,
  )
  try:
    config.validate()
  except ValueError as exc:
    error(str(exc), "keep the default loopback address, or add --allow-lan to listen on the network")
    raise typer.Exit(2) from exc
  settings = app.settings
  settings.ensure_dirs()
  if rotate_token:
    from beacon.web.security import Auth

    Auth.from_dir(settings.data_dir, rotate=True)
  link = login_url(settings, config)
  if url_only:
    typer.echo(link)
    return
  app.close()  # the server opens its own connections, one per thread
  if log_file is not None:
    _log_to(log_file)

  console.print(f"[brand]◉ beacon live[/brand]  [accent]{config.scheme}://{'127.0.0.1' if config.is_loopback else host}:{port}[/accent]")
  console.print(f"[muted]sign-in link (keep it private):[/muted] {link}")
  if not config.is_loopback:
    console.print("[warning]! listening on the local network: anyone with the link can sign in[/warning]")
    if tls_cert is None:
      console.print("[warning]! without --tls-cert the session travels unencrypted over the lan[/warning]")
  hint("ctrl+c stops the server; a scan in progress is cancelled and recorded as such")
  if not no_open:
    threading.Thread(target=_open_when_ready, args=(config, link), daemon=True).start()
  try:
    serve(settings, config)
  except OSError as exc:
    error(f"cannot listen on {host}:{port}: {exc}", "choose another port with --port")
    raise typer.Exit(1) from exc
  success("beacon live stopped")


def _open_when_ready(config, link: str, timeout: float = 15.0) -> None:
  health = f"http://127.0.0.1:{config.port}/api/v1/health"
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    try:
      with urllib.request.urlopen(health, timeout=1):  # noqa: S310 - fixed loopback url
        break
    except OSError:
      time.sleep(0.2)
  if config.scheme == "http":
    webbrowser.open(link)


def _log_to(path: Path) -> None:
  """diagnostics for a run without a terminal: scans, failures and notifications, never sign-in tokens."""
  import logging
  from logging.handlers import RotatingFileHandler

  path.parent.mkdir(parents=True, exist_ok=True)
  handler = RotatingFileHandler(path, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
  handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
  for name in ("beacon", "uvicorn.error"):
    logger = logging.getLogger(name)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
  logging.getLogger("beacon").info("beacon live starting (pid %s)", os.getpid())
