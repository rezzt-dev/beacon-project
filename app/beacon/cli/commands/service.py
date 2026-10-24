 # import libraries ->
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated
from xml.sax.saxutils import escape

import typer

from beacon.cli.context import get_app
from beacon.ui.console import console, error, hint, success, warn


 # constants ->
UNIT_NAME = "beacon-live.service"
PLIST_NAME = "dev.beacon.live.plist"
app = typer.Typer(help="run beacon live without a terminal, as a service of your user.", no_args_is_help=True)


 # definitions (pure) ->
def command_line(interval: int, profile: str | None, log_file: Path, db: Path | None) -> list[str]:
  """the exact command the service runs: this python, this beacon, never a shell."""
  args = [sys.executable, "-m", "beacon"]
  if db is not None:
    args += ["--db", str(db)]
  args += ["live", "--no-open", "--monitor", str(interval), "--log-file", str(log_file)]
  if profile:
    args += ["--profile", profile]
  return args


def systemd_unit(args: list[str], data_dir: Path) -> str:
  exec_start = " ".join(shlex.quote(a) for a in args)
  return f"""[Unit]
Description=beacon live: local network inventory and monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Environment=BEACON_HOME={shlex.quote(str(data_dir))}
Restart=on-failure
RestartSec=15
# beacon only needs the network and its own data directory
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
"""


def launchd_plist(args: list[str], data_dir: Path, log_file: Path) -> str:
  items = "\n".join(f"    <string>{escape(a)}</string>" for a in args)
  return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.beacon.live</string>
  <key>ProgramArguments</key>
  <array>
{items}
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>BEACON_HOME</key><string>{escape(str(data_dir))}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardErrorPath</key><string>{escape(str(log_file))}.stderr</string>
</dict>
</plist>
"""


def windows_task(args: list[str]) -> str:
  command = subprocess.list2cmdline(args)
  return f'schtasks /Create /TN "beacon live" /SC ONLOGON /RL LIMITED /TR "{command}"'


def target_path() -> Path | None:
  if sys.platform.startswith("linux"):
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "systemd" / "user" / UNIT_NAME
  if sys.platform == "darwin":
    return Path.home() / "Library" / "LaunchAgents" / PLIST_NAME
  return None


def definition(ctx: typer.Context, interval: int, profile: str | None) -> tuple[str, Path | None]:
  settings = get_app(ctx).settings
  log_file = settings.data_dir / "logs" / "beacon-live.log"
  db = settings.db_path if os.environ.get("BEACON_DB") or settings.db_path != settings.data_dir / "beacon.db" else None
  args = command_line(interval, profile, log_file, db)
  if sys.platform.startswith("linux"):
    return systemd_unit(args, settings.data_dir), target_path()
  if sys.platform == "darwin":
    return launchd_plist(args, settings.data_dir, log_file), target_path()
  return windows_task(args), None


 # commands ->
Interval = Annotated[int, typer.Option("--interval", "-n", min=10, max=86400, help="seconds between scans.")]
Profile = Annotated[str | None, typer.Option("--profile", help="saved profile the monitor uses.", show_default=False)]


@app.command()
def show(ctx: typer.Context, interval: Interval = 300, profile: Profile = None) -> None:
  """print the service definition for this platform without installing anything."""
  text, path = definition(ctx, interval, profile)
  typer.echo(text)
  if path is not None:
    hint(f"`beacon service install` writes it to {path}")


@app.command()
def install(
  ctx: typer.Context,
  interval: Interval = 300,
  profile: Profile = None,
  enable: Annotated[bool, typer.Option("--enable", help="also enable and start it now (systemctl --user / launchctl).")] = False,
  force: Annotated[bool, typer.Option("--force", help="replace an existing definition.")] = False,
) -> None:
  """write a user service that runs beacon live in the background (no root needed, unprivileged scans)."""
  text, path = definition(ctx, interval, profile)
  if path is None:
    console.print("windows: create a logon task with this command (it is not run for you):")
    typer.echo(text)
    return
  if path.exists() and not force:
    error(f"{path} already exists", "use --force to replace it, or `beacon service uninstall` first")
    raise typer.Exit(1)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(text)
  success(f"service definition written to {path}")
  if sys.platform.startswith("linux"):
    steps = [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", UNIT_NAME]]
  else:
    steps = [["launchctl", "load", "-w", str(path)]]
  if not enable:
    for step in steps:
      hint(" ".join(step))
    warn("not started yet: run the commands above, or install again with --enable")
    return
  for step in steps:
    if shutil.which(step[0]) is None:
      error(f"{step[0]} not found", "start the service manually")
      raise typer.Exit(1)
    subprocess.run(step, check=True, timeout=30)
  success("service enabled and started; open it with `beacon live --url`")


@app.command()
def uninstall(ctx: typer.Context) -> None:
  """stop and remove the user service."""
  path = target_path()
  if path is None or not path.exists():
    error("no beacon service is installed for this user")
    raise typer.Exit(1)
  if sys.platform.startswith("linux") and shutil.which("systemctl"):
    subprocess.run(["systemctl", "--user", "disable", "--now", UNIT_NAME], check=False, timeout=30)
  elif sys.platform == "darwin" and shutil.which("launchctl"):
    subprocess.run(["launchctl", "unload", "-w", str(path)], check=False, timeout=30)
  path.unlink()
  success(f"service removed ({path})")
