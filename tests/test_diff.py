 # import libraries ->
from datetime import timedelta
from ipaddress import IPv4Network

from beacon.core.diff import detect_changes
from beacon.core.engine import IpConflict
from beacon.core.events import EventType, Severity
from beacon.core.identity import IdentityMatch
from beacon.core.models import DeviceStatus, PortInfo, PortState
from beacon.core.ports import PortSet
from conftest import T0, TOP, make_device


NET = IPv4Network("192.168.1.0/24")
ROUTER = "34:5d:9e:3f:2a:77"
LAPTOP = "b0:a7:b9:dc:71:4a"
PHONE = "8e:e7:35:fe:0c:c6"
PHONE_2 = "9a:11:22:33:44:55"


def kinds(events):
  return [e.type for e in events]


 # device lifecycle ->
def test_new_device_raises_alert():
  previous = {LAPTOP: make_device("192.168.1.5", LAPTOP, trusted=True)}
  current = {LAPTOP: make_device("192.168.1.5", LAPTOP), ROUTER: make_device("192.168.1.1", ROUTER)}
  events = detect_changes(previous, current, network=NET)
  assert kinds(events) == [EventType.NEW_DEVICE]
  assert events[0].severity == Severity.ALERT
  assert events[0].details["baseline"] is False


def test_first_scan_is_a_baseline_not_a_wave_of_alerts():
  current = {ROUTER: make_device("192.168.1.1", ROUTER), PHONE: make_device("192.168.1.9", PHONE, randomized_mac=True)}
  events = detect_changes({}, current, network=NET)
  assert kinds(events) == [EventType.NEW_DEVICE, EventType.NEW_DEVICE]
  assert {e.severity for e in events} == {Severity.WARNING}
  assert all(e.details["baseline"] for e in events)
  assert not [e for e in events if e.severity == Severity.ALERT]


def test_first_scan_still_alerts_on_a_high_risk_device():
  exposed = make_device("192.168.1.66", LAPTOP, ports=(3389,))
  events = detect_changes({}, {LAPTOP: exposed}, network=NET)
  assert events[0].severity == Severity.ALERT
  assert events[0].details["risk"] >= 55


def test_identity_candidate_replaces_the_new_device_alert():
  old = make_device("192.168.1.9", PHONE, randomized_mac=True, hostname="iphone-de-ana", alias="ana", status=DeviceStatus.OFFLINE)
  new = make_device("192.168.1.10", PHONE_2, randomized_mac=True, hostname="iphone-de-ana")
  match = IdentityMatch(PHONE_2, PHONE, 0.86, ("same hostname iphone-de-ana", "same 3 mdns services"))
  events = detect_changes({PHONE: old, ROUTER: make_device("192.168.1.1", ROUTER)}, {PHONE_2: new}, network=NET, identity_candidates={PHONE_2: match})
  candidate = [e for e in events if e.type == EventType.IDENTITY_CANDIDATE]
  assert len(candidate) == 1 and candidate[0].severity == Severity.WARNING
  assert "probably ana" in candidate[0].message and "0.86" in candidate[0].message
  assert candidate[0].details["candidate_key"] == PHONE
  assert EventType.NEW_DEVICE not in kinds(events)


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


def results(device, **states):
  """the probe results of a scan: `p22="closed"` and so on, on top of the device's open ports."""
  for name, state in states.items():
    device.ports.append(PortInfo(int(name[1:]), PortState(state)))
  return device


def test_port_changes_only_when_ports_were_scanned():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(80, 443))}
  current = {ROUTER: results(make_device("192.168.1.1", ROUTER, ports=(80, 22)), p443="closed")}
  assert detect_changes(previous, current, network=NET) == []
  events = detect_changes(previous, current, network=NET, port_spec=TOP, examined_before={ROUTER: TOP})
  assert kinds(events) == [EventType.PORT_OPENED, EventType.PORT_CLOSED]
  assert events[0].details["port"] == 22 and events[0].severity == Severity.WARNING
  assert events[1].details["port"] == 443 and "refused" in events[1].message


 # regression: a partial port scan never invents a close ->
def test_ports_outside_the_examined_set_are_not_closed():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(22, 80))}
  current = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(80,))}
  assert detect_changes(previous, current, network=NET, port_spec=PortSet([80]), examined_before={ROUTER: TOP}) == []


def test_a_timeout_on_a_known_open_port_is_not_a_close():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(22,))}
  current = {ROUTER: results(make_device("192.168.1.1", ROUTER), p22="filtered")}
  assert detect_changes(previous, current, network=NET, port_spec=TOP, examined_before={ROUTER: TOP}) == []
  errored = {ROUTER: results(make_device("192.168.1.1", ROUTER), p22="error")}
  assert detect_changes(previous, errored, network=NET, port_spec=TOP, examined_before={ROUTER: TOP}) == []


def test_a_port_checked_for_the_first_time_is_not_a_new_port():
  previous = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(80,))}
  current = {ROUTER: make_device("192.168.1.1", ROUTER, ports=(80, 8443))}
  events = detect_changes(previous, current, network=NET, port_spec=PortSet([80, 8443]), examined_before={ROUTER: PortSet([80])})
  assert kinds(events) == [EventType.PORT_OPENED]
  assert events[0].severity == Severity.INFO and events[0].details["first_check"] is True
  legacy = detect_changes(previous, current, network=NET, port_spec=PortSet([80, 8443]), examined_before={ROUTER: None})
  assert legacy[0].severity == Severity.WARNING and legacy[0].details["first_check"] is False


 # regression: what could not be probed is not reported offline ->
def test_unobserved_addresses_are_not_reported_offline():
  previous = {LAPTOP: make_device("192.168.1.9", LAPTOP)}
  assert detect_changes(previous, {}, network=NET, now=T0 + timedelta(hours=1), unobserved={"192.168.1.9"}) == []
  assert kinds(detect_changes(previous, {}, network=NET, now=T0 + timedelta(hours=1))) == [EventType.DEVICE_OFFLINE]


def test_ip_conflict_is_an_alert():
  events = detect_changes({}, {}, conflicts=[IpConflict("192.168.1.1", (ROUTER, LAPTOP))], network=NET)
  assert kinds(events) == [EventType.IP_CONFLICT]
  assert events[0].severity == Severity.ALERT
  assert "arp spoofing" in events[0].message
