 # import libraries ->
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from beacon.cli.commands import service
from beacon.cli.main import app


runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
  monkeypatch.setenv("BEACON_HOME", str(tmp_path / "home"))
  monkeypatch.delenv("BEACON_DB", raising=False)
  monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
  return tmp_path


 # definitions ->
def test_unit_files_quote_every_argument():
  args = service.command_line(120, "home office", Path("/var/log/beacon live.log"), None)
  unit = service.systemd_unit(args, Path("/data/beacon"))
  assert "ExecStart=" in unit and "'home office'" in unit and "'/var/log/beacon live.log'" in unit
  assert "--monitor 120" in unit and "NoNewPrivileges=yes" in unit
  plist = service.launchd_plist([*args, "<&>"], Path("/data"), Path("/tmp/x.log"))
  assert "<string>&lt;&amp;&gt;</string>" in plist
  assert service.windows_task(args).startswith('schtasks /Create /TN "beacon live"')


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the user unit path is linux specific")
def test_install_writes_the_unit_and_only_enables_on_request(isolated, monkeypatch):
  calls = []
  monkeypatch.setattr(service.subprocess, "run", lambda args, **kw: calls.append(args))
  result = runner.invoke(app, ["service", "install", "-n", "60"])
  assert result.exit_code == 0, result.output
  unit = isolated / "config" / "systemd" / "user" / "beacon-live.service"
  assert unit.is_file() and "--monitor 60" in unit.read_text()
  assert calls == [] and "not started yet" in result.output
  assert runner.invoke(app, ["service", "install"]).exit_code == 1
  monkeypatch.setattr(service.shutil, "which", lambda name: "/usr/bin/" + name)
  assert runner.invoke(app, ["service", "install", "--force", "--enable"]).exit_code == 0
  assert calls == [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "beacon-live.service"]]
  assert runner.invoke(app, ["service", "uninstall"]).exit_code == 0 and not unit.exists()


 # running without a terminal ->
@pytest.mark.skipif(sys.platform == "win32", reason="posix signals")
def test_live_runs_headless_and_stops_cleanly_on_sigterm(isolated):
  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
  log_file = isolated / "logs" / "live.log"
  env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "app")}
  process = subprocess.Popen(
    [sys.executable, "-m", "beacon", "live", "--no-open", "--port", str(port), "--log-file", str(log_file)],
    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
  )
  try:
    deadline = time.monotonic() + 20
    health = None
    while time.monotonic() < deadline and health is None:
      try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health", timeout=1) as response:
          health = json.loads(response.read())
      except OSError:
        time.sleep(0.2)
    assert health and health["ok"] is True
    started = time.monotonic()
    process.send_signal(signal.SIGTERM)
    _out, err = process.communicate(timeout=15)
    # uvicorn shuts down gracefully, then re-raises the signal: systemd counts sigterm as a clean stop
    assert process.returncode in (0, -signal.SIGTERM) and time.monotonic() - started < 10
    assert "Traceback" not in err
    text = log_file.read_text()
    assert "beacon live starting" in text and (isolated / "home" / "live-token").read_text() not in text
  finally:
    if process.poll() is None:
      process.kill()
