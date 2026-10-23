 # import libraries ->
import json
from datetime import timedelta

import pytest
from typer.testing import CliRunner

from beacon.cli.main import app
from beacon.config import Settings
from beacon.core.events import Event, EventType, Severity
from beacon.core.models import ScanMode, utcnow
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository
from conftest import make_device


runner = CliRunner()
ROUTER = "34:5d:9e:3f:2a:77"
LAPTOP = "b0:a7:b9:dc:71:4a"


 # fixtures ->
@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
  monkeypatch.setenv("BEACON_HOME", str(tmp_path))
  monkeypatch.delenv("BEACON_DB", raising=False)
  monkeypatch.setattr("beacon.core.vendors.SYSTEM_MANUF_PATHS", ())
  return tmp_path


@pytest.fixture
def repo():
  settings = Settings.load()
  settings.ensure_dirs()
  db = Database(settings.db_path)
  yield Repository(db)
  db.close()


def scan(repo, devices, ago, offline=()):
  """store a scan taken `ago` before now."""
  at = utcnow() - ago
  for device in devices:
    device.last_seen = at
    device.first_seen = device.first_seen if device.first_seen and device.first_seen < at else at
  events = [Event(EventType.DEVICE_OFFLINE, Severity.INFO, "gone", device_key=key) for key in offline]
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, at, finished_at=at, devices=devices, events=events))


@pytest.fixture
def history(repo):
  """scans every ten minutes for three hours: the router stayed, the laptop left after the first hour."""
  router, laptop = make_device("192.168.1.1", ROUTER, hostname="router"), make_device("192.168.1.9", LAPTOP, hostname="laptop")
  for minutes in range(180, -1, -10):
    if minutes > 120:
      scan(repo, [router, laptop], timedelta(minutes=minutes))
    else:
      scan(repo, [router], timedelta(minutes=minutes), offline=[LAPTOP] if minutes == 120 else [])
  return repo


 # empty and error states ->
def test_timeline_without_history():
  result = runner.invoke(app, ["timeline"])
  assert result.exit_code == 0
  assert "no presence history yet" in result.output


def test_json_without_history_is_still_valid():
  data = json.loads(runner.invoke(app, ["timeline", "--json"]).output)
  assert data["devices"] == []


@pytest.mark.parametrize("value", ["99x", "abc", "0h", "-5d", ""])
def test_invalid_ranges_are_usage_errors(value):
  result = runner.invoke(app, ["timeline", "--since", value])
  assert result.exit_code == 2
  assert "30m, 24h, 7d or 2w" in result.output


def test_unknown_device_fails_like_the_rest_of_the_cli(history):
  assert runner.invoke(app, ["timeline", "--device", "nope"]).exit_code == 1


def test_nobody_in_the_window(repo):
  gone = make_device("192.168.1.9", LAPTOP, hostname="laptop")
  scan(repo, [gone], timedelta(hours=5))
  scan(repo, [], timedelta(hours=4), offline=[LAPTOP])
  result = runner.invoke(app, ["timeline", "--since", "1h"])
  assert "no device was connected in the last 1h" in result.output


 # output ->
def test_timeline_draws_one_row_per_device_with_text_marks(history):
  result = runner.invoke(app, ["timeline", "--since", "6h"])
  assert result.exit_code == 0, result.output
  rows = {line.split()[1]: line for line in result.output.splitlines() if "router" in line or "laptop" in line}
  assert "█" in rows["router"] and "·" in rows["laptop"] and "█" in rows["laptop"]
  assert "present" in result.output and "absent" in result.output
  assert "history: 0/14 days" in result.output
  assert rows["laptop"].count("█") < rows["router"].count("█")


def test_json_returns_the_sessions_with_iso_dates(history):
  data = json.loads(runner.invoke(app, ["timeline", "--since", "24h", "--json"]).output)
  by_name = {d["name"]: d for d in data["devices"]}
  assert set(by_name) == {"router", "laptop"}
  laptop = by_name["laptop"]["sessions"]
  assert len(laptop) == 1 and laptop[0]["open"] is False
  assert laptop[0]["started_at"] < laptop[0]["ended_at"]
  assert by_name["router"]["sessions"][-1]["open"] is True


def test_device_filter_and_online_only(history):
  only = json.loads(runner.invoke(app, ["timeline", "--device", "laptop", "--json"]).output)
  assert [d["name"] for d in only["devices"]] == ["laptop"]
  online = json.loads(runner.invoke(app, ["timeline", "--online-only", "--json"]).output)
  assert [d["name"] for d in online["devices"]] == ["router"]


def test_a_linked_identity_gets_a_single_row(repo):
  old, new = "8e:e7:35:fe:0c:c6", "9a:11:22:33:44:55"
  scan(repo, [make_device("192.168.1.9", old, hostname="iphone-a", randomized_mac=True)], timedelta(hours=5), offline=[old])
  scan(repo, [make_device("192.168.1.10", new, hostname="iphone-b", randomized_mac=True)], timedelta(hours=1))
  repo.link_devices(new, old)
  data = json.loads(runner.invoke(app, ["timeline", "--json"]).output)
  assert len(data["devices"]) == 1
  assert len(data["devices"][0]["sessions"]) == 2


 # prune ->
def test_prune_removes_old_sessions_and_validates_its_argument(history):
  assert runner.invoke(app, ["prune"]).exit_code == 2
  assert runner.invoke(app, ["prune", "--sessions-older-than", "soon"]).exit_code == 2
  result = runner.invoke(app, ["prune", "--sessions-older-than", "1h"])
  assert result.exit_code == 0 and "1 presence sessions removed" in result.output  # the laptop's, ended two hours ago
  assert "0 presence sessions removed" in runner.invoke(app, ["prune", "--sessions-older-than", "1h"]).output
