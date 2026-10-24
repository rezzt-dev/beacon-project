 # import libraries ->
import asyncio
import time
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

import pytest

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import DiscoverySource, Observation, PortInfo, PortState, ScanMode
from beacon.core.report import ScanReport, ScanStatus
from beacon.pipeline import ScanOptions, ScanPipeline
from beacon.scanners.icmp import IcmpPinger
from beacon.scanners.network import InterfaceInfo, TargetError
from conftest import make_device


REAL_ENRICH = ScanPipeline._enrich


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
    # what a port scan would find: open ports per ip, and the answer of the others (closed by default)
    self.open_ports: dict[str, set[int]] = {}
    self.silent: dict[str, set[int]] = {}


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

  async def enrich(self, devices, options, pinger, router=None, previous=None):
    for device in devices:
      device.hostname = net.hostnames.get(device.ip)
      device.services = net.services.get(device.ip, []) if options.identity and device.randomized_mac else []
      device.ttl = net.ttl.get(device.ip, 64)
      if options.ports:
        # the scanner contract: every open port, plus every known port that was probed again
        old = (previous or {}).get(device.key)
        tracked = {p.port for p in old.ports} if old else set()
        found = []
        for port in options.ports:
          if port in net.open_ports.get(device.ip, set()):
            found.append(PortInfo(port, PortState.OPEN, service="svc"))
          elif port in tracked:
            state = PortState.FILTERED if port in net.silent.get(device.ip, set()) else PortState.CLOSED
            found.append(PortInfo(port, state))
        device.ports = found

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
  return asyncio.run(pipeline.run(ScanOptions(mode=ScanMode.UNPRIVILEGED, latency_samples=0, ipv6=False, **options)))


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
def record_monitor_coverage(repo, start, end, every=timedelta(hours=1)):
  """completed scans of the network at a steady pace: hours beacon was really watching."""
  moment = start
  rows = []
  while moment < end:
    rows.append((moment.isoformat(), moment.isoformat()))
    moment += every
  repo.resolve_network("192.168.1.0/24", "wlan0")
  repo.conn.executemany(
    "INSERT INTO scans (started_at, finished_at, status, network, network_id) VALUES (?, ?, 'complete', '192.168.1.0/24', 1)", rows
  )
  repo.conn.commit()


def record_office_history(repo, device_ip="192.168.1.20", weeks=5, monitored=True):
  """weekday stays from 9 to 18 h for `weeks` weeks, ending the sunday before the test scan.

  with `monitored` the network was also scanned every hour of nights and weekends.
  """
  day = datetime(2026, 9, 21, tzinfo=UTC)
  if monitored:
    record_monitor_coverage(repo, day, day + timedelta(weeks=weeks))
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


def test_hours_nobody_watched_are_not_evidence_of_a_routine(network, pipeline, repo):
  record_office_history(repo, monitored=False)
  network.now = datetime(2026, 10, 25, 3, 12, tzinfo=UTC)
  network.hosts = {"192.168.1.20": OFFICE_PC}
  assert EventType.UNUSUAL_PRESENCE not in kinds(run(pipeline))


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


 # regression: honest scan status ->
def test_one_broken_host_makes_the_scan_partial_not_failed(network, pipeline, repo, monkeypatch):
  network.hosts = {"192.168.1.1": ROUTER, "192.168.1.20": OFFICE_PC}
  monkeypatch.setattr(ScanPipeline, "_enrich", REAL_ENRICH)

  async def enrich_one(self, device, *_args):
    if device.ip == "192.168.1.20":
      raise RuntimeError("socket exploded")

  monkeypatch.setattr(ScanPipeline, "_enrich_one", enrich_one)
  report = run(pipeline, resolve_hostnames=False)
  assert report.status == ScanStatus.PARTIAL
  assert [(i.stage, i.host) for i in report.issues] == [("enrich", "192.168.1.20")]
  assert {d.ip for d in report.devices} == {"192.168.1.1", "192.168.1.20"}
  assert EventType.SCAN_PARTIAL in kinds(report)
  assert repo.get_scan(report.scan_id)["status"] == "partial"


def test_a_cancelled_scan_is_recorded_and_releases_its_resources(network, pipeline, repo, monkeypatch):
  network.hosts = {"192.168.1.1": ROUTER}
  closed = []

  class FakePinger:
    unsent: set = set()

    def close(self):
      closed.append(True)

  monkeypatch.setattr(IcmpPinger, "open", classmethod(lambda cls, *a, **k: FakePinger()))

  async def hang(self, *_args, **_kwargs):
    await asyncio.sleep(30)

  monkeypatch.setattr(ScanPipeline, "_enrich", hang)

  async def scenario():
    task = asyncio.create_task(pipeline.run(ScanOptions(mode=ScanMode.UNPRIVILEGED, latency_samples=0, ipv6=False)))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
      await task

  asyncio.run(scenario())
  assert closed == [True]
  [scan] = repo.list_scans()
  assert scan["status"] == "cancelled"
  assert repo.load_devices() == {}


def test_a_missing_interface_fails_the_scan_and_raises_one_event(network, pipeline, repo, monkeypatch):
  network.hosts = {"192.168.1.1": ROUTER}
  run(pipeline)

  def gone(_target, _iface):
    raise TargetError("no active ipv4 interface found")

  monkeypatch.setattr("beacon.pipeline.resolve_target", gone)
  for _ in range(3):
    with pytest.raises(TargetError):
      run(pipeline)
  statuses = [s["status"] for s in repo.list_scans()]
  assert statuses == ["failed", "failed", "failed", "complete"]
  assert len(repo.list_events(types=[EventType.SCAN_FAILED])) == 1
  # the monitor failing says nothing about the devices: nothing went offline
  assert repo.load_devices()[ROUTER].status == "online"


 # regression: one network per router, even with the same private range ->
def test_the_same_range_behind_another_router_is_another_inventory(network, pipeline, repo):
  network.hosts = {"192.168.1.1": ROUTER, "192.168.1.20": OFFICE_PC}
  first = run(pipeline)
  network.now += timedelta(hours=1)
  network.hosts = {"192.168.1.1": "34:5d:9e:00:00:01", "192.168.1.20": "b0:a7:b9:00:00:20"}
  second = run(pipeline)
  assert (first.network_id, second.network_id) == (1, 2)
  assert second.first_run and all(e.severity == Severity.WARNING for e in second.events)
  assert set(repo.load_devices(2)) == {"n2:34:5d:9e:00:00:01", "n2:b0:a7:b9:00:00:20"}
  # scanning the second network does not mark the first one offline
  assert {d.status for d in repo.load_devices(1).values()} == {"online"}


 # regression: a partial port profile never invents a close ->
def test_port_profiles_only_change_what_they_examined(network, pipeline, repo):
  network.hosts = {"192.168.1.1": ROUTER}
  network.open_ports = {"192.168.1.1": {22, 80}}
  run(pipeline, ports=(22, 80))
  network.now += timedelta(minutes=5)
  network.open_ports = {"192.168.1.1": {80}}
  only_web = run(pipeline, ports=(80,))
  assert only_web.events == []
  assert [p.port for p in repo.load_devices()[ROUTER].open_ports] == [22, 80]

  network.now += timedelta(minutes=5)
  network.silent = {"192.168.1.1": {22}}
  timeout = run(pipeline, ports=(22,))
  assert timeout.events == []
  port = next(p for p in repo.load_devices()[ROUTER].ports if p.port == 22)
  assert (port.state, port.last_probe) == (PortState.OPEN, PortState.FILTERED)

  network.now += timedelta(minutes=5)
  network.silent = {}
  refused = run(pipeline, ports=(22,))
  assert kinds(refused) == [EventType.PORT_CLOSED]
  assert [p.port for p in repo.load_devices()[ROUTER].open_ports] == [80]


def test_a_port_examined_for_the_first_time_is_informational(network, pipeline, repo):
  network.hosts = {"192.168.1.1": ROUTER}
  network.open_ports = {"192.168.1.1": {80, 8443}}
  run(pipeline, ports=(80,))
  network.now += timedelta(minutes=5)
  report = run(pipeline, ports=(80, 8443))
  [event] = report.events
  assert event.type == EventType.PORT_OPENED and event.severity == Severity.INFO and event.details["first_check"]
