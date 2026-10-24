 # import libraries ->
import asyncio
import time
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

import pytest

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import DiscoverySource, Observation, ScanMode
from beacon.core.report import ScanReport
from beacon.pipeline import ScanOptions, ScanPipeline
from beacon.scanners.icmp import IcmpPinger
from beacon.scanners.network import InterfaceInfo
from conftest import make_device


ROUTER = "34:5d:9e:3f:2a:77"
OLD_PHONE = "8e:e7:35:fe:0c:c6"
NEW_PHONE = "9a:11:22:33:44:55"
OFFICE_PC = "b0:a7:b9:dc:71:4a"
NET = IPv4Network("192.168.1.0/24")
SERVICES = ["_airplay._tcp", "_companion-link._tcp", "_raop._tcp"]


 # fixtures ->
class Network:
  """what the fake discovery sees: ip -> mac, plus what enrichment would learn about each ip."""

  def __init__(self) -> None:
    self.hosts: dict[str, str] = {}
    self.hostnames: dict[str, str] = {}
    self.services: dict[str, list[str]] = {}
    self.ttl: dict[str, int] = {}
    self.now: datetime = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)


@pytest.fixture
def network(monkeypatch, vendors):
  net = Network()
  iface = InterfaceInfo("wlan0", IPv4Address("192.168.1.5"), NET, "aa:aa:aa:aa:aa:aa", gateway=IPv4Address("192.168.1.1"))
  monkeypatch.setattr("beacon.pipeline.resolve_target", lambda _target, _iface: (iface, NET))
  monkeypatch.setattr("beacon.pipeline.privileged_mode_available", lambda: False)
  monkeypatch.setattr(IcmpPinger, "open", classmethod(lambda cls, *a, **k: None))
  monkeypatch.setattr("beacon.pipeline.utcnow", lambda: net.now)

  async def discover(self, network_, iface_, privileged, pinger, options):
    return [Observation(ip=ip, mac=mac, source=DiscoverySource.ARP_SWEEP) for ip, mac in net.hosts.items()]

  async def enrich(self, devices, options, pinger, router=None):
    for device in devices:
      device.hostname = net.hostnames.get(device.ip)
      device.services = net.services.get(device.ip, []) if options.identity and device.randomized_mac else []
      device.ttl = net.ttl.get(device.ip, 64)

  monkeypatch.setattr(ScanPipeline, "_discover", discover)
  monkeypatch.setattr(ScanPipeline, "_enrich", enrich)
  monkeypatch.setenv("TZ", "UTC")
  time.tzset()
  yield net
  monkeypatch.undo()
  time.tzset()


@pytest.fixture
def pipeline(repo, vendors):
  return ScanPipeline(repo, vendors)


def run(pipeline, **options) -> ScanReport:
  return asyncio.run(pipeline.run(ScanOptions(mode=ScanMode.UNPRIVILEGED, latency_samples=0, **options)))


def kinds(report):
  return [e.type for e in report.events]


 # first scan ->
def test_first_scan_is_a_baseline_without_alerts(network, pipeline):
  network.hosts = {"192.168.1.1": ROUTER, "192.168.1.9": OLD_PHONE, "192.168.1.20": OFFICE_PC}
  report = run(pipeline)
  assert report.first_run
  assert kinds(report) == [EventType.NEW_DEVICE] * 3
  assert report.alerts == []
  assert {e.severity for e in report.events} == {Severity.WARNING}


def test_second_scan_of_the_same_network_is_quiet(network, pipeline):
  network.hosts = {"192.168.1.1": ROUTER, "192.168.1.9": OLD_PHONE}
  run(pipeline)
  assert run(pipeline).events == []


def test_a_stranger_after_the_baseline_is_an_alert(network, pipeline):
  network.hosts = {"192.168.1.1": ROUTER}
  run(pipeline)
  network.hosts["192.168.1.66"] = OFFICE_PC
  report = run(pipeline)
  assert [e.severity for e in report.events] == [Severity.ALERT]


 # identity ->
def phone_back_with_new_mac(network, pipeline, **options):
  network.hosts = {"192.168.1.1": ROUTER, "192.168.1.9": OLD_PHONE}
  for ip in ("192.168.1.9", "192.168.1.10"):
    network.hostnames[ip] = "iphone-de-ana"
    network.services[ip] = SERVICES
  run(pipeline, **options)
  network.now += timedelta(hours=2)
  network.hosts = {"192.168.1.1": ROUTER, "192.168.1.10": NEW_PHONE}
  return run(pipeline, **options)


def test_a_phone_back_with_a_new_private_mac_is_a_candidate_not_an_intruder(network, pipeline, repo):
  report = phone_back_with_new_mac(network, pipeline)
  assert EventType.IDENTITY_CANDIDATE in kinds(report)
  assert EventType.NEW_DEVICE not in kinds(report)
  assert report.alerts == []
  event = next(e for e in report.events if e.type == EventType.IDENTITY_CANDIDATE)
  assert event.details["candidate_key"] == OLD_PHONE and event.details["score"] >= 0.8
  assert repo.load_devices()[NEW_PHONE].services == SERVICES
  assert repo.load_devices()[NEW_PHONE].trusted is False


def test_no_identity_restores_the_plain_new_device_alert(network, pipeline):
  report = phone_back_with_new_mac(network, pipeline, identity=False)
  assert EventType.IDENTITY_CANDIDATE not in kinds(report)
  assert [e.severity for e in report.events if e.type == EventType.NEW_DEVICE] == [Severity.ALERT]


def test_a_phone_that_is_still_online_is_never_its_own_candidate(network, pipeline):
  network.hosts = {"192.168.1.9": OLD_PHONE}
  for ip in ("192.168.1.9", "192.168.1.10"):
    network.hostnames[ip] = "iphone-de-ana"
    network.services[ip] = SERVICES
  run(pipeline)
  network.hosts = {"192.168.1.9": OLD_PHONE, "192.168.1.10": NEW_PHONE}
  report = run(pipeline)
  assert EventType.IDENTITY_CANDIDATE not in kinds(report)
  assert [e.severity for e in report.events] == [Severity.ALERT]


def test_two_newcomers_for_one_candidate_are_ambiguous(network, pipeline):
  network.hosts = {"192.168.1.9": OLD_PHONE}
  for ip in ("192.168.1.9", "192.168.1.10", "192.168.1.11"):
    network.hostnames[ip] = "iphone-de-ana"
    network.services[ip] = SERVICES
  run(pipeline)
  network.hosts = {"192.168.1.10": NEW_PHONE, "192.168.1.11": "9a:11:22:33:44:66"}
  report = run(pipeline)
  assert EventType.IDENTITY_CANDIDATE not in kinds(report)


def test_the_identity_survives_the_next_scan(network, pipeline, repo):
  phone_back_with_new_mac(network, pipeline)
  repo.link_devices(NEW_PHONE, OLD_PHONE)
  network.now += timedelta(minutes=5)
  report = run(pipeline)
  assert report.events == []
  assert repo.load_devices()[NEW_PHONE].identity_id == repo.load_devices()[OLD_PHONE].identity_id is not None


 # presence ->
def record_office_history(repo, device_ip="192.168.1.20", weeks=5):
  """weekday stays from 9 to 18 h for `weeks` weeks, ending the sunday before the test scan."""
  day = datetime(2026, 9, 21, tzinfo=UTC)
  for offset in range(weeks * 7):
    current = day + timedelta(days=offset)
    if current.weekday() >= 5:
      continue
    for hour, gone in ((9, False), (17, False), (18, True)):
      moment = current.replace(hour=hour)
      device = make_device(device_ip, OFFICE_PC, first_seen=day, last_seen=moment)
      events = [Event(EventType.DEVICE_OFFLINE, Severity.INFO, "gone", device_key=OFFICE_PC)] if gone else []
      repo.save_scan(
        ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, moment, finished_at=moment, devices=[] if gone else [device], events=events)
      )
  repo.set_trusted(OFFICE_PC, True)


def test_a_trusted_pc_showing_up_on_sunday_night_is_unusual(network, pipeline, repo):
  record_office_history(repo)
  network.now = datetime(2026, 10, 25, 3, 12, tzinfo=UTC)
  network.hosts = {"192.168.1.20": OFFICE_PC}
  report = run(pipeline)
  assert EventType.UNUSUAL_PRESENCE in kinds(report)
  assert EventType.DEVICE_ONLINE in kinds(report)
  event = next(e for e in report.events if e.type == EventType.UNUSUAL_PRESENCE)
  assert event.severity == Severity.WARNING and "now it is sun 03:12" in event.message
  assert repo.has_event_since(OFFICE_PC, EventType.UNUSUAL_PRESENCE, network.now)


def test_the_same_pc_arriving_at_work_time_is_not_unusual(network, pipeline, repo):
  record_office_history(repo)
  network.now = datetime(2026, 10, 26, 9, 20, tzinfo=UTC)
  network.hosts = {"192.168.1.20": OFFICE_PC}
  assert EventType.UNUSUAL_PRESENCE not in kinds(run(pipeline))


def test_no_presence_neither_records_sessions_nor_raises_anomalies(network, pipeline, repo):
  record_office_history(repo)
  sessions_before = len(repo.list_sessions()[OFFICE_PC])
  network.now = datetime(2026, 10, 25, 3, 12, tzinfo=UTC)
  network.hosts = {"192.168.1.20": OFFICE_PC}
  report = run(pipeline, presence=False)
  assert EventType.UNUSUAL_PRESENCE not in kinds(report)
  assert len(repo.list_sessions()[OFFICE_PC]) == sessions_before


def test_a_young_inventory_raises_no_presence_anomalies(network, pipeline, repo):
  record_office_history(repo, weeks=1)
  network.now = datetime(2026, 10, 25, 3, 12, tzinfo=UTC)
  network.hosts = {"192.168.1.20": OFFICE_PC}
  assert EventType.UNUSUAL_PRESENCE not in kinds(run(pipeline))


def test_an_always_on_device_that_vanishes_breaks_the_routine_once(network, pipeline, repo):
  slow = {"presence_gap": 12 * 3600.0}  # scans six hours apart still count as one stay
  network.hosts = {"192.168.1.1": ROUTER}
  network.now = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)
  while network.now < datetime(2026, 10, 24, 8, 0, tzinfo=UTC):
    run(pipeline, **slow)
    network.now += timedelta(hours=6)
  network.now = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
  run(pipeline, **slow)
  network.now += timedelta(hours=1)
  network.hosts = {}
  first = run(pipeline, **slow)
  assert EventType.ROUTINE_BROKEN in kinds(first)
  assert "missing for 1 h" in next(e.message for e in first.events if e.type == EventType.ROUTINE_BROKEN)
  network.now += timedelta(hours=1)
  assert EventType.ROUTINE_BROKEN not in kinds(run(pipeline, **slow))
