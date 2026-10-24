 # import libraries ->
import json
import sys
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network

import pytest
from typer.testing import CliRunner

from beacon.cli.main import app
from beacon.config import Settings
from beacon.core.models import ScanMode
from beacon.core.report import ScanReport
from beacon.scanners.network import InterfaceInfo
from beacon.storage import Database, Repository
from conftest import T0, make_device


runner = CliRunner()
ROUTER = "34:5d:9e:3f:2a:77"


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
  repo = Repository(db)
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0, devices=[make_device("192.168.1.1", ROUTER)]))
  yield repo
  db.close()


 # profiles ->
def test_profiles_are_saved_validated_and_removed(repo):
  added = runner.invoke(app, ["profiles", "add", "home", "--target", "192.168.1.0/24", "--ports", "top", "-x", "192.168.1.200"])
  assert added.exit_code == 0, added.output
  listed = json.loads(runner.invoke(app, ["profiles", "list", "--json"]).output)
  assert listed[0]["name"] == "home" and listed[0]["exclude"] == ["192.168.1.200/32"]
  public = runner.invoke(app, ["profiles", "add", "web", "--target", "8.8.8.0/24"])
  assert public.exit_code == 1 and "private" in public.output
  assert runner.invoke(app, ["profiles", "remove", "home"]).exit_code == 0
  assert runner.invoke(app, ["profiles", "remove", "home"]).exit_code == 1


def test_networks_lists_the_known_networks(repo):
  data = json.loads(runner.invoke(app, ["networks", "--json"]).output)
  assert data[0]["cidr"] == "192.168.1.0/24" and data[0]["devices"] == 1


 # maintenance ->
def test_backup_and_restore_from_the_cli(repo, isolated_home):
  target = isolated_home / "copy.db"
  result = runner.invoke(app, ["backup", str(target)])
  assert result.exit_code == 0 and "verified" in result.output
  repo.delete_device(ROUTER)
  restored = runner.invoke(app, ["restore", str(target), "--yes"])
  assert restored.exit_code == 0, restored.output
  fresh = Repository(Database(Settings.load().db_path))
  assert ROUTER in fresh.load_devices()


def test_restore_refuses_while_someone_scans(repo, isolated_home):
  target = isolated_home / "copy.db"
  runner.invoke(app, ["backup", str(target)])
  repo.acquire_lease("net:192.168.1.0/24", "live-monitor", timedelta(minutes=5), owner="other:1")
  result = runner.invoke(app, ["restore", str(target), "--yes"])
  assert result.exit_code == 1 and "live-monitor" in result.output


def test_retention_previews_before_deleting(repo):
  preview = runner.invoke(app, ["retention"])
  assert preview.exit_code == 0 and "would delete" in preview.output and "nothing deleted yet" in preview.output
  assert runner.invoke(app, ["retention", "--apply"]).exit_code == 0


 # live and leases ->
def test_live_url_prints_a_private_sign_in_link(repo, isolated_home):
  result = runner.invoke(app, ["live", "--url"])
  assert result.exit_code == 0 and result.output.startswith("http://127.0.0.1:8765/login#token=")
  token = (isolated_home / "live-token").read_text()
  assert token in result.output
  if sys.platform != "win32":  # owner-only permissions are a posix notion
    assert (isolated_home / "live-token").stat().st_mode & 0o077 == 0


def test_live_refuses_the_lan_without_consent(repo):
  result = runner.invoke(app, ["live", "--host", "0.0.0.0", "--url"])
  assert result.exit_code == 2 and "--allow-lan" in result.output


def test_a_scan_of_a_network_someone_else_is_scanning_is_refused(repo, monkeypatch):
  iface = InterfaceInfo("wlan0", IPv4Address("192.168.1.5"), IPv4Network("192.168.1.0/24"), "aa:aa:aa:aa:aa:aa")
  monkeypatch.setattr("beacon.web.jobs.resolve_target", lambda _t, _i: (iface, IPv4Network("192.168.1.0/24")))
  repo.acquire_lease("net:192.168.1.0/24", "live-monitor", timedelta(minutes=5), owner="other:1")
  result = runner.invoke(app, ["scan", "--mode", "unprivileged"])
  assert result.exit_code == 4 and "live-monitor" in result.output
