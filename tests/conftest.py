 # import libraries ->
from datetime import UTC, datetime

import pytest

from beacon.core.models import Device, DeviceStatus, PortInfo, PortState
from beacon.core.ports import PortSet
from beacon.core.vendors import VendorDatabase
from beacon.storage import Database, Repository


 # fixtures ->
MANUF_SAMPLE = """\
# sample of the wireshark manuf format
34:5D:9E\tSagemcom\tSagemcom Broadband SAS
00:1B:C5\tIeeeRegi\tIEEE Registration Authority
00:1B:C5:00:00/36\tConverging\tConverging Systems Inc.
00:55:DA:10/28\tKoolPOS\tKoolPOS Inc.
B0:A7:B9\tTp-Link\tTP-Link Systems Inc
"""
T0 = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
# the port set most tests pretend was examined
TOP = PortSet(range(1, 1025))


@pytest.fixture
def vendors() -> VendorDatabase:
  return VendorDatabase().load_lines(MANUF_SAMPLE.splitlines())


@pytest.fixture
def repo():
  db = Database(":memory:")
  yield Repository(db)
  db.close()


def make_device(ip: str, mac: str | None = None, ports: tuple[int, ...] = (), **kwargs) -> Device:
  device = Device(
    ip=ip,
    mac=mac,
    ips=[ip],
    ports=[PortInfo(port=p, state=PortState.OPEN, service="svc") for p in ports],
    first_seen=kwargs.pop("first_seen", T0),
    last_seen=kwargs.pop("last_seen", T0),
    status=kwargs.pop("status", DeviceStatus.ONLINE),
    **kwargs,
  )
  return device
