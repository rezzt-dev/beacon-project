 # import libraries ->
import json
from datetime import timedelta

import pytest
from typer.testing import CliRunner

from beacon.cli.main import app
from beacon.config import Settings
from beacon.core.models import ScanMode
from beacon.core.ports import PortSet
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository
from conftest import T0, TOP, make_device


runner = CliRunner()
OLD = "8e:e7:35:fe:0c:c6"
NEW = "9a:11:22:33:44:55"
ROUTER = "34:5d:9e:3f:2a:77"
SERVICES = ["_airplay._tcp", "_raop._tcp"]


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


def save(repo, *devices, at=T0, port_spec=()):
  repo.save_scan(
    ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, at, finished_at=at, devices=list(devices), port_spec=PortSet(port_spec))
  )


@pytest.fixture
def phones(repo):
  """a phone seen on day 0 and a phone with the same name and services that appears a day later."""
  old = make_device("192.168.1.9", OLD, randomized_mac=True, hostname="iphone-de-ana", services=SERVICES, ttl=64)
  new = make_device("192.168.1.10", NEW, randomized_mac=True, hostname="iphone-de-ana", services=SERVICES, ttl=64)
  new.first_seen = new.last_seen = T0 + timedelta(days=1)
  save(repo, old)
  save(repo, new, at=T0 + timedelta(days=1))
  repo.set_alias(OLD, "ana")
  repo.set_trusted(OLD, True)
  return repo


 # candidates ->
def test_candidates_on_an_empty_inventory():
  result = runner.invoke(app, ["devices", "candidates"])
  assert result.exit_code == 0 and "no link candidates" in result.output


def test_candidates_show_score_level_and_evidence(phones):
  result = runner.invoke(app, ["devices", "candidates"])
  assert result.exit_code == 0
  assert NEW in result.output and OLD in result.output and "probable" in result.output
  [entry] = json.loads(runner.invoke(app, ["devices", "candidates", "--json"]).output)
  assert entry["score"] >= 0.8 and entry["link"] == "probable"
  assert "same hostname iphone-de-ana" in entry["evidence"]


 # link and unlink ->
def test_link_asks_before_trusting_and_does_not_copy_trust(phones):
  result = runner.invoke(app, ["devices", "link", NEW, OLD], input="n\n")
  assert result.exit_code == 0, result.output
  assert "linked" in result.output and "also trust" in result.output
  devices = phones.load_devices()
  assert devices[NEW].identity_id == devices[OLD].identity_id is not None
  assert devices[NEW].alias == "ana"
  assert devices[NEW].trusted is False


def test_link_can_trust_the_new_mac_on_request(phones):
  assert runner.invoke(app, ["devices", "link", NEW, OLD, "--trust"]).exit_code == 0
  assert phones.load_devices()[NEW].trusted is True


def test_link_flags_skip_the_question(phones):
  result = runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  assert "also trust" not in result.output and phones.load_devices()[NEW].trusted is False


def test_link_rejects_bad_references(phones):
  assert runner.invoke(app, ["devices", "link", NEW, "nope", "--no-trust"]).exit_code == 1
  assert runner.invoke(app, ["devices", "link", NEW, NEW, "--no-trust"]).exit_code == 1


def test_linking_twice_is_harmless(phones):
  runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  result = runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  assert result.exit_code == 0 and "already linked" in result.output


def test_unlink_undoes_the_link(phones):
  runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  assert runner.invoke(app, ["devices", "unlink", NEW]).exit_code == 0
  assert {d.identity_id for d in phones.load_devices().values()} == {None}
  assert runner.invoke(app, ["devices", "candidates"]).output.count(NEW) >= 1  # proposed again
  again = runner.invoke(app, ["devices", "unlink", NEW])
  assert again.exit_code == 1 and "not linked" in again.output


 # show and list ->
def test_show_displays_identity_and_presence(phones):
  runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  output = runner.invoke(app, ["devices", "show", NEW]).output
  assert "identity" in output and OLD in output and "same hostname iphone-de-ana" in output.replace("\n", " ")
  assert "services" in output and "_airplay._tcp" in output
  assert "risk" in output
  assert "presence" in output


def test_show_explains_why_a_randomized_unlinked_device_has_no_presence_profile(phones):
  assert "not linked to an identity" in runner.invoke(app, ["devices", "show", NEW]).output


def test_show_json_includes_risk_identity_and_fingerprint(phones):
  runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  data = json.loads(runner.invoke(app, ["devices", "show", NEW, "--json"]).output)
  assert data["services"] == SERVICES and data["identity_id"] is not None
  assert [m["mac"] for m in data["identity_members"]] == [OLD]
  assert data["risk_level"] in ("low", "medium", "high") and isinstance(data["risk_reasons"], list)


def test_list_adds_the_risk_column_on_request(repo):
  save(repo, make_device("192.168.1.1", ROUTER, ports=(23,), vendor=None), port_spec=TOP)
  plain = json.loads(runner.invoke(app, ["devices", "list", "--json"]).output)
  assert "risk" not in plain[0] and "services" not in plain[0]
  risky = json.loads(runner.invoke(app, ["devices", "list", "--json", "--risk"]).output)
  assert risky[0]["risk"] >= 55 and risky[0]["risk_level"] == "high"
  assert "risk" in runner.invoke(app, ["devices", "list", "--risk"]).output


def test_the_linked_mark_is_visible_in_the_table(phones):
  runner.invoke(app, ["devices", "link", NEW, OLD, "--no-trust"])
  assert "⛓" in runner.invoke(app, ["devices", "list"]).output


 # privacy ->
def test_exports_leave_the_fingerprint_out_unless_asked(phones, isolated_home):
  target = isolated_home / "inventory.json"
  assert runner.invoke(app, ["export", str(target)]).exit_code == 0
  assert "services" not in json.loads(target.read_text())["devices"][0]
  assert "include_fingerprint" not in target.read_text()
  assert runner.invoke(app, ["export", str(target), "--include-fingerprint"]).exit_code == 0
  assert json.loads(target.read_text())["devices"][0]["services"] == SERVICES


def test_trust_reviews_the_pending_events(repo):
  from beacon.core.events import Event, EventType, Severity

  device = make_device("192.168.1.1", ROUTER)
  repo.save_scan(
    ScanReport(
      "192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0, devices=[device],
      events=[Event(EventType.NEW_DEVICE, Severity.ALERT, "new", device_key=ROUTER)],
    )
  )
  assert runner.invoke(app, ["devices", "trust", ROUTER]).exit_code == 0
  assert repo.list_pending_events() == []
