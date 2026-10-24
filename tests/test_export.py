 # import libraries ->
import csv
import io
import json

import pytest

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import DeviceStatus
from beacon.export import detect_format, export_to_file, render
from conftest import make_device


 # format detection ->
def test_detect_format(tmp_path):
  assert detect_format(tmp_path / "a.JSON") == "json"
  assert detect_format(tmp_path / "a.htm") == "html"
  assert detect_format(tmp_path / "a.txt", "csv") == "csv"
  with pytest.raises(ValueError):
    detect_format(tmp_path / "a.xml")


 # renderers ->
def test_json_export(tmp_path):
  devices = [make_device("192.168.1.1", "34:5d:9e:3f:2a:77", ports=(80,))]
  events = [Event(type=EventType.NEW_DEVICE, severity=Severity.ALERT, message="new")]
  path = export_to_file(tmp_path / "out" / "inv.json", devices, events, {"network": "192.168.1.0/24"})
  data = json.loads(path.read_text())
  assert data["network"] == "192.168.1.0/24"
  assert data["device_count"] == 1
  assert data["devices"][0]["open_ports"][0]["port"] == 80
  assert data["events"][0]["type"] == "new-device"
  assert not list(path.parent.glob(".*"))  # no temporary files left behind


def test_csv_export_neutralizes_formulas():
  device = make_device("192.168.1.1", "34:5d:9e:3f:2a:77", ports=(22, 80), hostname="=cmd|' /c calc'!a0")
  rows = list(csv.DictReader(io.StringIO(render("csv", [device]))))
  assert rows[0]["hostname"].startswith("'=")
  assert rows[0]["open_ports"] == "22/tcp 80/tcp"


def test_html_export_escapes_untrusted_values():
  device = make_device("192.168.1.1", "34:5d:9e:3f:2a:77", hostname="<script>alert(1)</script>")
  page = render("html", [device], [], {"network": "192.168.1.0/24", "refresh": 30})
  assert "<script>alert(1)</script>" not in page
  assert "&lt;script&gt;" in page
  assert 'http-equiv="refresh" content="30"' in page


 # live html report ->
def test_html_report_only_runs_its_own_inline_code():
  import re

  page = render("html", [make_device("192.168.1.1", "34:5d:9e:3f:2a:77")], [], {"refresh": 30})
  csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
  assert "default-src 'none'" in csp and "script-src 'sha256-" in csp and "'unsafe-inline'" not in csp
  assert " style=" not in page  # inline style attributes would be blocked by the policy
  assert "http" not in csp and "src=\"http" not in page  # nothing is loaded from the network


def test_live_html_refreshes_without_javascript_and_snapshots_do_not():
  device = make_device("192.168.1.1", "34:5d:9e:3f:2a:77")
  live = render("html", [device], [], {"refresh": 45, "duration": 6.2})
  assert '<noscript><meta http-equiv="refresh" content="45"></noscript>' in live
  assert 'data-refresh="45"' in live and 'data-duration="6.2"' in live and 'id="pause"' in live
  snapshot = render("html", [device], [], {})
  assert 'http-equiv="refresh"' not in snapshot and "snapshot" in snapshot


def test_html_report_lists_untrusted_online_devices_first_with_their_risk():
  devices = [
    make_device("192.168.1.2", "aa:bb:cc:00:00:02", trusted=True, vendor="Acme"),
    make_device("192.168.1.9", "aa:bb:cc:00:00:09", ports=(23,), trusted=False),
  ]
  page = render("html", devices, [], {"network": "192.168.1.0/24"})
  assert "<title>(1) beacon · 192.168.1.0/24</title>" in page
  attention = page.split('class="attention"')[1].split("</section>")[0]
  assert "192.168.1.9" in attention and "192.168.1.2" not in attention
  assert "telnet on 23" in attention and "beacon review" in attention


def test_html_report_rows_carry_what_the_filters_need():
  devices = [
    make_device("192.168.1.10", "aa:bb:cc:00:00:10", ports=(22,), hostname="nas.lan", trusted=True),
    make_device("192.168.1.2", "aa:bb:cc:00:00:02", status=DeviceStatus.OFFLINE),
  ]
  page = render("html", devices, [], {})
  online_row = page.index('data-key="aa:bb:cc:00:00:10"')
  assert online_row < page.index('data-key="aa:bb:cc:00:00:02"')  # online before offline
  assert 'data-status="online" data-trusted="1" data-ports="1"' in page
  assert 'data-q="192.168.1.10 192.168.1.10 aa:bb:cc:00:00:10 nas.lan' in page
  assert '<button type="button" data-filter="offline" aria-pressed="false">offline<span class="n">1</span>' in page


def test_html_report_empty_states_explain_what_will_appear():
  page = render("html", [], [], {"refresh": 30})
  assert "waiting for the first scan" in page and "no events yet" in page


def test_html_report_has_a_hostname_column_with_its_source():
  device = make_device("192.168.1.10", "aa:bb:cc:00:00:10", hostname="nas.lan")
  device.hostname_source = "router"
  page = render("html", [device, make_device("192.168.1.2", "aa:bb:cc:00:00:02")], [], {})
  assert '<button type="button">hostname</button>' in page
  assert '<div class="host">nas.lan</div><div class="second">via router</div>' in page
