 # import libraries ->
from datetime import timedelta
from ipaddress import IPv4Network

from beacon.core.diff import detect_changes
from beacon.core.engine import IpConflict
from beacon.core.events import EventType, Severity
from beacon.core.models import DeviceStatus
from conftest import T0, make_device


NET = IPv4Network("192.168.1.0/24")
ROUTER = "34:5d:9e:3f:2a:77"
LAPTOP = "b0:a7:b9:dc:71:4a"


def kinds(events):
  return [e.type for e in events]


 # device lifecycle ->
def test_new_device_raises_alert():
  events = detect_changes({}, {ROUTER: make_device("192.168.1.1", ROUTER)}, network=NET)
  assert kinds(events) == [EventType.NEW_DEVICE]
  assert events[0].severity == Severity.ALERT


def test_local_host_is_registered_without_alert():
  events = detect_changes({}, {LAPTOP: make_device("192.168.1.5", LAPTOP, is_local=True)}, network=NET)
  assert events[0].severity == Severity.INFO


def test_known_device_produces_no_events():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, trusted=True)}
  assert detect_changes(previous, {ROUTER: make_device("192.168.1.1", ROUTER)}, network=NET) == []


def test_offline_and_back_online():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, trusted=True)}
  gone = detect_changes(previous, {}, network=NET, now=T0 + timedelta(minutes=5))
  assert kinds(gone) == [EventType.DEVICE_OFFLINE]

  previous[ROUTER].status = DeviceStatus.OFFLINE
  back = detect_changes(previous, {ROUTER: make_device("192.168.1.1", ROUTER)}, network=NET)
  assert kinds(back) == [EventType.DEVICE_ONLINE]
  assert back[0].severity == Severity.INFO


def test_untrusted_device_back_online_is_a_warning():
  previous = {LAPTOP: make_device("192.168.1.9", LAPTOP, status=DeviceStatus.OFFLINE)}
  events = detect_changes(previous, {LAPTOP: make_device("192.168.1.9", LAPTOP)}, network=NET)
  assert events[0].severity == Severity.WARNING


def test_offline_grace_suppresses_flapping():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER)}
  within = detect_changes(previous, {}, network=NET, offline_grace=timedelta(minutes=2), now=T0 + timedelta(minutes=1))
  after = detect_changes(previous, {}, network=NET, offline_grace=timedelta(minutes=2), now=T0 + timedelta(minutes=3))
  assert within == []
  assert kinds(after) == [EventType.DEVICE_OFFLINE]


def test_devices_outside_scanned_network_are_not_marked_offline():
  previous = {ROUTER: make_device("10.0.0.1", ROUTER)}
  assert detect_changes(previous, {}, network=NET, now=T0 + timedelta(hours=1)) == []


 # attribute changes ->
def test_ip_change_is_reported():
  previous = {LAPTOP: make_device("192.168.1.9", LAPTOP)}
  events = detect_changes(previous, {LAPTOP: make_device("192.168.1.42", LAPTOP)}, network=NET)
  assert kinds(events) == [EventType.IP_CHANGED]
  assert events[0].details == {"old_ip": "192.168.1.9", "new_ip": "192.168.1.42"}


def test_port_changes_only_when_ports_were_scanned():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(80, 443))}
  current = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(80, 22))}
  assert detect_changes(previous, current, network=NET, ports_scanned=False) == []
  events = detect_changes(previous, current, network=NET, ports_scanned=True)
  assert kinds(events) == [EventType.PORT_OPENED, EventType.PORT_CLOSED]
  assert events[0].details["port"] == 22
  assert events[1].details["port"] == 443


def test_ip_conflict_is_an_alert():
  events = detect_changes({}, {}, conflicts=[IpConflict("192.168.1.1", (ROUTER, LAPTOP))], network=NET)
  assert kinds(events) == [EventType.IP_CONFLICT]
  assert events[0].severity == Severity.ALERT
  assert "arp spoofing" in events[0].message
