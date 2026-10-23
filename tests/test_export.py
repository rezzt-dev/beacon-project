 # import libraries ->
import csv
import io
import json

import pytest

from beacon.core.events import Event, EventType, Severity
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
