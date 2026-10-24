 # import libraries ->
import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from beacon.cli.commands import review as review_module
from beacon.cli.commands.review import ReviewAction, apply_action
from beacon.cli.main import app
from beacon.config import Settings
from beacon.core.events import Event, EventType, Severity
from beacon.core.models import ScanMode
from beacon.core.report import ScanReport
from beacon.core.risk import assess
from beacon.storage import Database, Repository
from beacon.ui.console import THEME
from beacon.ui.render import review_table
from conftest import T0, TOP, make_device


runner = CliRunner()
ROUTER = "34:5d:9e:3f:2a:77"
CAMERA = "b0:a7:b9:dc:71:4a"
PHONE = "8e:e7:35:fe:0c:c6"


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


@pytest.fixture
def interactive(monkeypatch):
  monkeypatch.setattr(review_module, "_interactive", lambda: True)


def new_device_event(key, severity=Severity.WARNING):
  return Event(type=EventType.NEW_DEVICE, severity=severity, message=f"found {key}", device_key=key)


@pytest.fixture
def seeded(repo):
  """a router, a phone with a randomized mac and a camera exposing telnet, all untrusted and pending."""
  devices = [
    make_device("192.168.1.1", ROUTER, vendor="Sagemcom", hostname="router.lan"),
    make_device("192.168.1.9", PHONE, randomized_mac=True),
    make_device("192.168.1.50", CAMERA, ports=(23, 80)),
  ]
  events = [new_device_event(d.key, Severity.ALERT if d.key == CAMERA else Severity.WARNING) for d in devices]
  repo.save_scan(
    ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0, devices=devices, events=events, port_spec=TOP)
  )
  return repo


def pending_keys(repo):
  return {e.device_key for e in repo.list_pending_events()}


 # listing ->
def test_review_with_nothing_pending():
  result = runner.invoke(app, ["review", "--list"])
  assert result.exit_code == 0
  assert "nothing pending review" in result.output


def test_list_orders_by_risk_and_explains_each_device(seeded):
  result = runner.invoke(app, ["review", "--list"])
  assert result.exit_code == 0
  lines = [line for line in result.output.splitlines() if "192.168.1." in line]
  assert "192.168.1.50" in lines[0]  # the camera with telnet comes first
  assert "high 85" in lines[0] and "medium 40" in lines[1]


def test_the_review_table_explains_each_device_at_a_normal_width():
  devices = [make_device("192.168.1.50", CAMERA, ports=(23, 80)), make_device("192.168.1.9", PHONE, randomized_mac=True)]
  rows = [(d, assess(d, now=T0)) for d in devices]
  console = Console(width=100, record=True, force_terminal=False, theme=THEME)
  console.print(review_table(rows))
  text = console.export_text()
  assert "telnet on 23" in text and "not trusted" in text


def test_json_lists_pending_devices_with_risk_and_reasons(seeded):
  result = runner.invoke(app, ["review", "--json"])
  data = json.loads(result.output)
  assert [d["key"] for d in data][0] == CAMERA
  assert data[0]["risk_level"] == "high" and data[0]["risk_reasons"]
  assert data[0]["pending_events"][0]["type"] == "new-device"
  assert all(d["risk_reasons"] for d in data if d["risk"] > 0)


def test_unscanned_ports_are_called_out(repo):
  repo.save_scan(
    ScanReport(
      "192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0,
      devices=[make_device("192.168.1.9", PHONE)], events=[new_device_event(PHONE)],
    )
  )
  [case] = json.loads(runner.invoke(app, ["review", "--json"]).output)
  assert case["ports_scanned"] is False


def test_without_a_terminal_review_asks_for_list_or_json(seeded):
  result = runner.invoke(app, ["review"])
  assert result.exit_code == 2
  assert "--list or --json" in result.output
  assert len(pending_keys(seeded)) == 3


 # bulk trust ->
def test_trust_below_trusts_only_low_risk_after_confirmation(seeded):
  nothing = runner.invoke(app, ["review", "--trust-below", "low", "--yes"])
  assert "no pending device has a risk of low or lower" in nothing.output
  assert runner.invoke(app, ["review", "--trust-below", "medium"], input="n\n").exit_code == 1
  assert len(pending_keys(seeded)) == 3
  result = runner.invoke(app, ["review", "--trust-below", "medium", "--yes"])
  assert result.exit_code == 0
  devices = seeded.load_devices()
  assert devices[CAMERA].trusted is False
  assert devices[ROUTER].trusted and devices[PHONE].trusted
  assert pending_keys(seeded) == {CAMERA}


def test_trust_below_reports_when_nothing_matches(seeded):
  seeded.trust_all()
  result = runner.invoke(app, ["review", "--trust-below", "low", "--yes"])
  assert "nothing pending review" in result.output


 # interactive flow ->
def test_each_key_acts_only_on_the_device_in_front(seeded, interactive):
  # riskiest first: camera (high), then router and phone (medium, by ip). trust, trust with alias, ignore
  result = runner.invoke(app, ["review"], input="t" + "a" + "\n" + "i")
  assert result.exit_code == 0, result.output
  devices = seeded.load_devices()
  assert devices[CAMERA].trusted
  assert devices[ROUTER].trusted and devices[ROUTER].alias == "router"
  assert devices[PHONE].trusted is False and devices[PHONE].alias is None
  assert pending_keys(seeded) == set()
  assert "2 trusted" in result.output and "1 ignored" in result.output and "0 still pending" in result.output


def test_forget_skip_and_quit(seeded, interactive):
  result = runner.invoke(app, ["review"], input="fsq")
  assert result.exit_code == 0
  devices = seeded.load_devices()
  assert CAMERA not in devices  # forgotten
  assert pending_keys(seeded) == {ROUTER, PHONE}  # skipped and never reached
  assert "1 forgotten" in result.output and "2 still pending" in result.output


def test_unknown_keys_are_ignored_and_the_review_resumes(seeded, interactive):
  result = runner.invoke(app, ["review"], input="xyzq")
  assert result.exit_code == 0
  assert len(pending_keys(seeded)) == 3


def test_end_of_input_leaves_without_changes(seeded, interactive):
  result = runner.invoke(app, ["review"], input="")
  assert result.exit_code == 0
  assert len(pending_keys(seeded)) == 3


def test_the_alias_prompt_defaults_to_a_suggestion(seeded, interactive):
  result = runner.invoke(app, ["review"], input="sa\n")  # skip the camera, alias the router
  assert result.exit_code == 0
  assert seeded.load_devices()[ROUTER].alias == "router"


def test_an_alias_made_only_of_spaces_is_a_plain_trust(seeded, interactive):
  runner.invoke(app, ["review"], input="sa  \n")
  router = seeded.load_devices()[ROUTER]
  assert router.trusted and router.alias is None


 # decisions ->
def test_apply_action_touches_only_the_chosen_device(seeded):
  devices = seeded.load_devices()
  assert apply_action(seeded, devices[PHONE], ReviewAction.TRUST_ALIAS, "  ana-phone  ") == "trusted"
  loaded = seeded.load_devices()
  assert (loaded[PHONE].alias, loaded[PHONE].trusted) == ("ana-phone", True)
  assert not loaded[ROUTER].trusted and not loaded[CAMERA].trusted
  assert apply_action(seeded, devices[ROUTER], ReviewAction.IGNORE) == "ignored"
  assert not seeded.load_devices()[ROUTER].trusted
  assert apply_action(seeded, devices[CAMERA], ReviewAction.SKIP) == "skipped"
  assert pending_keys(seeded) == {CAMERA}


 # events --pending ->
def test_events_pending_hides_what_was_reviewed(seeded):
  assert len(json.loads(runner.invoke(app, ["events", "--pending", "--json"]).output)) == 3
  seeded.ack_events(PHONE)
  pending = json.loads(runner.invoke(app, ["events", "--pending", "--json"]).output)
  assert {e["device_key"] for e in pending} == {ROUTER, CAMERA}
  seeded.trust_all()
  assert "nothing pending review" in runner.invoke(app, ["events", "--pending"]).output
