 # import libraries ->
import json

import pytest
from typer.testing import CliRunner

from beacon import __version__
from beacon.cli.main import app


runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
  monkeypatch.setenv("BEACON_HOME", str(tmp_path))
  monkeypatch.delenv("BEACON_DB", raising=False)
  monkeypatch.setattr("beacon.core.vendors.SYSTEM_MANUF_PATHS", ())
  return tmp_path


 # commands that do not touch the network ->
def test_version():
  result = runner.invoke(app, ["--version"])
  assert result.exit_code == 0
  assert __version__ in result.output


def test_devices_list_on_empty_inventory():
  result = runner.invoke(app, ["devices", "list", "--json"])
  assert result.exit_code == 0
  assert json.loads(result.output) == []


def test_unknown_device_reference_fails():
  result = runner.invoke(app, ["devices", "show", "aa:bb:cc:dd:ee:ff"])
  assert result.exit_code == 1


def test_vendor_lookup_uses_local_database(isolated_home):
  (isolated_home / "manuf").write_text("34:5D:9E\tSagemcom\tSagemcom Broadband SAS\n")
  result = runner.invoke(app, ["vendors", "lookup", "34-5d-9e-3f-2a-77", "8e:e7:35:fe:0c:c6", "nope"])
  assert result.exit_code == 0
  assert "Sagemcom Broadband SAS" in result.output
  assert "randomized" in result.output
  assert "invalid mac" in result.output


def test_export_empty_inventory(isolated_home):
  target = isolated_home / "inventory.json"
  result = runner.invoke(app, ["export", str(target)])
  assert result.exit_code == 0
  assert json.loads(target.read_text())["device_count"] == 0


def test_invalid_port_spec_is_rejected():
  result = runner.invoke(app, ["scan", "--ports", "99999"])
  assert result.exit_code == 2
