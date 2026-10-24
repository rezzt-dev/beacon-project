 # import libraries ->
import sqlite3
from datetime import timedelta

import pytest

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import DeviceStatus, Latency, PortInfo, PortState, ScanMode
from beacon.core.ports import PortSet
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository
from beacon.storage.database import SCHEMA_VERSION
from conftest import T0, TOP, make_device


ROUTER = "34:5d:9e:3f:2a:77"
PHONE = "8e:e7:35:fe:0c:c6"


def report(devices, events=(), port_spec=(), at=T0):
  return ScanReport(
    network="192.168.1.0/24",
    mode=ScanMode.UNPRIVILEGED,
    started_at=at,
    finished_at=at,
    interface="wlan0",
    devices=list(devices),
    events=list(events),
    port_spec=PortSet(port_spec),
  )


 # schema ->
def test_schema_is_migrated(tmp_path):
  db = Database(tmp_path / "beacon.db")
  assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
  db.close()
  db.conn.execute("PRAGMA user_version = 999")
  db.conn.commit()
  db.close()
  with pytest.raises(RuntimeError):
    _ = Database(tmp_path / "beacon.db").conn


 # devices and ports ->
def test_save_and_load_roundtrip(repo):
  router = make_device("192.168.1.1", ROUTER, ports=(80, 443), vendor="Sagemcom", ttl=64, os_guess="linux/unix/macos")
  router.latency = Latency(method="icmp", sent=3, samples=[1.0, 2.0, 3.0])
  scan_id = repo.save_scan(report([router], port_spec=TOP))
  assert scan_id == 1

  loaded = repo.load_devices()[ROUTER]
  assert loaded.vendor == "Sagemcom"
  assert [p.port for p in loaded.open_ports] == [80, 443]
  assert loaded.latency is not None and loaded.latency.avg == 2.0
  assert loaded.first_seen == T0


def test_ports_are_never_deleted_and_keep_their_state(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER, ports=(80, 443))], port_spec=TOP))
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)]))
  assert [p.port for p in repo.load_devices()[ROUTER].open_ports] == [80, 443]
  later = make_device("192.168.1.1", ROUTER, ports=(22,))
  later.ports.append(PortInfo(443, PortState.CLOSED, last_probe=PortState.CLOSED, checked_at=T0))
  repo.save_scan(report([later], port_spec=TOP))
  device = repo.load_devices()[ROUTER]
  assert [p.port for p in device.open_ports] == [22, 80]
  assert {p.port: str(p.state) for p in device.ports} == {22: "open", 80: "open", 443: "closed"}


def test_port_coverage_is_recorded_per_device_and_scan(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], port_spec=PortSet([22, 80])))
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], port_spec=PortSet([443]), at=T0 + timedelta(hours=1)))
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], at=T0 + timedelta(hours=2)))
  spec, checked = repo.port_coverage()[ROUTER]
  assert spec == PortSet([22, 80, 443]) and checked == T0 + timedelta(hours=1)
  assert [c["spec"] for c in repo.coverage_history(ROUTER)] == ["443", "22,80"]


def test_upsert_keeps_alias_trust_and_known_hostname(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER, hostname="router.lan")]))
  repo.set_alias(ROUTER, "router")
  repo.set_trusted(ROUTER, True)
  later = T0 + timedelta(minutes=5)
  repo.save_scan(report([make_device("192.168.1.2", ROUTER, last_seen=later)], at=later))
  device = repo.load_devices()[ROUTER]
  assert (device.alias, device.trusted, device.hostname, device.ip) == ("router", True, "router.lan", "192.168.1.2")
  assert device.first_seen == T0 and device.last_seen == later


def test_offline_events_update_status(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)]))
  gone = Event(type=EventType.DEVICE_OFFLINE, severity=Severity.INFO, message="gone", device_key=ROUTER)
  repo.save_scan(report([], [gone]))
  assert repo.load_devices()[ROUTER].status == DeviceStatus.OFFLINE


def test_find_device_by_any_reference(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER, hostname="router.lan"), make_device("192.168.1.9", PHONE)]))
  repo.set_alias(PHONE, "Phone")
  assert repo.find_device("34-5D-9E-3F-2A-77").key == ROUTER
  assert repo.find_device("192.168.1.1").key == ROUTER
  assert repo.find_device("router.lan").key == ROUTER
  assert repo.find_device("phone").key == PHONE
  assert repo.find_device("nothing") is None


def test_trust_all_and_forget(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER), make_device("192.168.1.9", PHONE)]))
  assert repo.trust_all() == 2
  assert repo.list_devices(trusted=False) == []
  assert repo.delete_device(PHONE)
  assert list(repo.load_devices()) == [ROUTER]


 # events and stats ->
def test_events_are_filtered(repo):
  events = [
    Event(type=EventType.NEW_DEVICE, severity=Severity.ALERT, message="new", device_key=PHONE),
    Event(type=EventType.IP_CHANGED, severity=Severity.INFO, message="ip", device_key=ROUTER),
    Event(type=EventType.PORT_OPENED, severity=Severity.WARNING, message="port", device_key=ROUTER),
  ]
  repo.save_scan(report([make_device("192.168.1.1", ROUTER), make_device("192.168.1.9", PHONE)], events))
  assert len(repo.list_events()) == 3
  assert [e.message for e in repo.list_events(device_key=ROUTER)] == ["port", "ip"]
  assert [e.message for e in repo.list_events(min_severity=Severity.WARNING)] == ["port", "new"]
  assert [e.message for e in repo.list_events(types=[EventType.NEW_DEVICE])] == ["new"]


def test_stats(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER, trusted=True), make_device("192.168.1.9", PHONE, randomized_mac=True)]))
  stats = repo.stats()
  assert (stats["total"], stats["online"], stats["trusted"], stats["untrusted"], stats["randomized"], stats["scans"]) == (2, 2, 1, 1, 1, 1)


def test_save_scan_is_atomic(repo, monkeypatch):
  def broken(*_args):
    raise sqlite3.OperationalError("disk full")

  monkeypatch.setattr(Repository, "_upsert_device", broken)
  with pytest.raises(sqlite3.OperationalError):
    repo.save_scan(report([make_device("192.168.1.1", ROUTER)]))
  assert repo.list_scans() == []


 # migrations ->
V1_SCHEMA_TABLES = {"devices", "ports", "scans", "events"}


def test_migration_from_v1_keeps_every_row(tmp_path):
  from beacon.storage.database import MIGRATIONS

  path = tmp_path / "old.db"
  conn = sqlite3.connect(path)
  conn.executescript(f"BEGIN;\n{MIGRATIONS[0]}\nPRAGMA user_version = 1;\nCOMMIT;")
  conn.execute(
    "INSERT INTO devices (key, mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
    (ROUTER, ROUTER, "192.168.1.1", "2026-10-24T10:00:00+00:00", "2026-10-24T10:00:00+00:00"),
  )
  conn.execute(
    "INSERT INTO events (timestamp, type, severity, device_key, message) VALUES (?, 'new-device', 'alert', ?, 'old')",
    ("2026-10-24T10:00:00+00:00", ROUTER),
  )
  conn.commit()
  conn.close()

  repo = Repository(Database(path))
  assert repo.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
  device = repo.load_devices()[ROUTER]
  assert (device.services, device.identity_id) == ([], None)
  assert [e.message for e in repo.list_pending_events()] == ["old"]
  assert {"identities", "sessions"} <= {r[0] for r in repo.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
  repo.db.close()


 # reviewed events ->
def alert(key, kind=EventType.NEW_DEVICE, severity=Severity.ALERT, message="x"):
  return Event(type=kind, severity=severity, message=message, device_key=key)


def test_pending_events_are_alerts_and_warnings_of_devices(repo):
  events = [
    alert(PHONE, message="alert"),
    alert(PHONE, EventType.PORT_OPENED, Severity.WARNING, "warning"),
    alert(PHONE, EventType.IP_CHANGED, Severity.INFO, "info"),
    Event(type=EventType.IP_CONFLICT, severity=Severity.ALERT, message="conflict"),
  ]
  repo.save_scan(report([make_device("192.168.1.9", PHONE)], events))
  assert [e.message for e in repo.list_pending_events()] == ["warning", "alert"]
  assert [e.message for e in repo.list_events(pending_only=True, types=[EventType.NEW_DEVICE])] == ["alert"]
  assert all(e.id is not None for e in repo.list_pending_events())


def test_ack_events_is_idempotent_and_limited_to_one_device(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER), make_device("192.168.1.9", PHONE)], [alert(ROUTER), alert(PHONE)]))
  assert repo.ack_events(PHONE) == 1
  assert repo.ack_events(PHONE) == 0
  assert [e.device_key for e in repo.list_pending_events()] == [ROUTER]
  assert len(repo.list_events()) == 2  # history is kept


def test_trusting_or_forgetting_a_device_counts_as_reviewing_it(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER), make_device("192.168.1.9", PHONE)], [alert(ROUTER), alert(PHONE)]))
  repo.set_trusted(ROUTER, True)
  repo.delete_device(PHONE)
  assert repo.list_pending_events() == []
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], [alert(ROUTER)]))
  repo.set_trusted(ROUTER, False)  # untrusting is not a review
  assert len(repo.list_pending_events()) == 1


def test_trust_all_reviews_everything(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER), make_device("192.168.1.9", PHONE)], [alert(ROUTER), alert(PHONE)]))
  repo.trust_all()
  assert repo.list_pending_events() == []


def test_ports_ever_scanned(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)]))
  assert not repo.ports_ever_scanned()
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], port_spec=TOP))
  assert repo.ports_ever_scanned()


 # identities ->
NEW_PHONE = "9a:11:22:33:44:55"


def test_services_are_stored_and_kept_when_a_scan_gets_none(repo):
  repo.save_scan(report([make_device("192.168.1.9", PHONE, services=["_airplay._tcp"])]))
  repo.save_scan(report([make_device("192.168.1.9", PHONE)]))
  assert repo.load_devices()[PHONE].services == ["_airplay._tcp"]
  repo.save_scan(report([make_device("192.168.1.9", PHONE, services=["_raop._tcp"])]))
  assert repo.load_devices()[PHONE].services == ["_raop._tcp"]


def test_link_shares_identity_and_alias_but_not_trust(repo):
  repo.save_scan(report([make_device("192.168.1.9", PHONE, randomized_mac=True), make_device("192.168.1.10", NEW_PHONE, randomized_mac=True)], [alert(NEW_PHONE)]))
  repo.set_alias(PHONE, "ana")
  repo.set_trusted(PHONE, True)
  identity = repo.link_devices(NEW_PHONE, PHONE)
  devices = repo.load_devices()
  assert devices[PHONE].identity_id == devices[NEW_PHONE].identity_id == identity
  assert devices[NEW_PHONE].alias == "ana"
  assert devices[NEW_PHONE].trusted is False
  assert repo.list_pending_events() == []
  assert [d.key for d in repo.identity_members(devices[NEW_PHONE])] == [PHONE]


def test_link_keeps_an_existing_alias_and_merges_identities(repo):
  keys = [PHONE, NEW_PHONE, "aa:00:00:00:00:03", "aa:00:00:00:00:04"]
  repo.save_scan(report([make_device(f"192.168.1.{10 + i}", k, randomized_mac=True) for i, k in enumerate(keys)]))
  repo.set_alias(NEW_PHONE, "mine")
  repo.set_alias(PHONE, "other")
  first = repo.link_devices(NEW_PHONE, PHONE)
  assert repo.load_devices()[NEW_PHONE].alias == "mine"
  second = repo.link_devices(keys[2], keys[3])
  assert first != second
  merged = repo.link_devices(keys[3], PHONE)
  assert {d.identity_id for d in repo.load_devices().values()} == {merged}
  assert repo.conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0] == 1


def test_link_validates_its_arguments(repo):
  repo.save_scan(report([make_device("192.168.1.9", PHONE)]))
  with pytest.raises(ValueError):
    repo.link_devices(PHONE, PHONE)
  with pytest.raises(ValueError):
    repo.link_devices(PHONE, "aa:aa:aa:aa:aa:aa")


def test_unlink_dissolves_an_identity_left_with_one_mac(repo):
  repo.save_scan(report([make_device("192.168.1.9", PHONE), make_device("192.168.1.10", NEW_PHONE)]))
  repo.link_devices(NEW_PHONE, PHONE)
  assert repo.unlink_device(NEW_PHONE)
  assert {d.identity_id for d in repo.load_devices().values()} == {None}
  assert repo.conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0] == 0
  assert not repo.unlink_device(NEW_PHONE)


def test_forgetting_a_member_dissolves_the_identity(repo):
  repo.save_scan(report([make_device("192.168.1.9", PHONE), make_device("192.168.1.10", NEW_PHONE)]))
  repo.link_devices(NEW_PHONE, PHONE)
  repo.delete_device(PHONE)
  assert repo.load_devices()[NEW_PHONE].identity_id is None


def test_list_candidates_proposes_stored_pairs(repo):
  services = ["_airplay._tcp", "_raop._tcp"]
  old = make_device("192.168.1.9", PHONE, randomized_mac=True, hostname="iphone-de-ana", services=services, ttl=64)
  new = make_device("192.168.1.10", NEW_PHONE, randomized_mac=True, hostname="iphone-de-ana", services=services, ttl=64, first_seen=T0 + timedelta(days=1), last_seen=T0 + timedelta(days=1))
  repo.save_scan(report([old]))
  repo.save_scan(report([new], at=T0 + timedelta(days=1)))
  [match] = repo.list_candidates()
  assert (match.new_key, match.candidate_key) == (NEW_PHONE, PHONE)
  repo.link_devices(NEW_PHONE, PHONE)
  assert repo.list_candidates() == []


 # presence sessions ->
def at(minutes):
  return T0 + timedelta(minutes=minutes)


def present(minutes, key=ROUTER, ip="192.168.1.1"):
  return make_device(ip, key, first_seen=T0, last_seen=at(minutes))


def offline_event(key=ROUTER):
  return Event(type=EventType.DEVICE_OFFLINE, severity=Severity.INFO, message="gone", device_key=key)


def test_consecutive_scans_extend_one_session(repo):
  repo.save_scan(report([present(0)], at=at(0)))
  repo.save_scan(report([present(1)], at=at(1)))
  repo.save_scan(report([present(2)], at=at(2)))
  [session] = repo.list_sessions()[ROUTER]
  assert (session.started_at, session.last_seen, session.is_open) == (at(0), at(2), True)
  assert repo.presence_span() == (1, at(0))


def test_offline_closes_the_session_at_the_last_sighting_not_at_the_scan(repo):
  repo.save_scan(report([present(0)], at=at(0)))
  repo.save_scan(report([present(2)], at=at(2)))
  repo.save_scan(report([], [offline_event()], at=at(10)))
  [session] = repo.list_sessions()[ROUTER]
  assert session.ended_at == at(2) and session.end == at(2)


def test_coming_back_opens_a_second_session(repo):
  repo.save_scan(report([present(0)], at=at(0)))
  repo.save_scan(report([], [offline_event()], at=at(5)))
  repo.save_scan(report([present(30)], at=at(30)))
  sessions = repo.list_sessions()[ROUTER]
  assert [(s.started_at, s.ended_at) for s in sessions] == [(at(0), at(0)), (at(30), None)]


def test_a_long_gap_between_scans_splits_the_session(repo):
  repo.save_scan(report([present(0)], at=at(0)))
  repo.save_scan(report([present(300)], at=at(300)))
  sessions = repo.list_sessions()[ROUTER]
  assert [(s.started_at, s.ended_at) for s in sessions] == [(at(0), at(0)), (at(300), None)]


def test_a_grace_period_keeps_the_session_open_while_the_device_is_missing(repo):
  repo.save_scan(report([present(0)], at=at(0)))
  repo.save_scan(report([], at=at(2)))  # missing, but no offline event yet
  assert repo.list_sessions()[ROUTER][0].is_open


def test_presence_can_be_switched_off(repo):
  repo.save_scan(report([present(0)], at=at(0)), presence=False)
  assert repo.list_sessions() == {} and repo.presence_span() == (0, None)


def test_list_sessions_filters_by_device_and_time(repo):
  repo.save_scan(report([present(0), present(0, PHONE, "192.168.1.9")], at=at(0)))
  repo.save_scan(report([], [offline_event(), offline_event(PHONE)], at=at(60)))
  assert set(repo.list_sessions()) == {ROUTER, PHONE}
  assert set(repo.list_sessions([ROUTER])) == {ROUTER}
  assert repo.list_sessions([ROUTER], since=at(30)) == {}
  assert repo.list_sessions([]) == {}


def test_linked_macs_share_one_history(repo):
  repo.save_scan(report([make_device("192.168.1.9", PHONE, first_seen=T0, last_seen=at(0))], at=at(0)))
  repo.save_scan(report([], [offline_event(PHONE)], at=at(5)))
  repo.save_scan(report([make_device("192.168.1.10", NEW_PHONE, first_seen=at(60), last_seen=at(60))], at=at(60)))
  repo.link_devices(NEW_PHONE, PHONE)
  devices = repo.load_devices()
  pooled = repo.sessions_by_identity([devices[NEW_PHONE]])[NEW_PHONE]
  assert [s.device_key for s in pooled] == [PHONE, NEW_PHONE]


def test_sessions_are_removed_with_their_device(repo):
  repo.save_scan(report([present(0)], at=at(0)))
  repo.delete_device(ROUTER)
  assert repo.list_sessions() == {}


def test_prune_only_deletes_old_closed_sessions(repo):
  repo.save_scan(report([present(0), present(0, PHONE, "192.168.1.9")], at=at(0)))
  repo.save_scan(report([present(1, PHONE, "192.168.1.9")], [offline_event()], at=at(1)))
  assert repo.prune_sessions(at(10)) == 1
  assert set(repo.list_sessions()) == {PHONE}
  assert repo.prune_sessions(at(100000)) == 0  # the open one stays


def test_has_event_since(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], [Event(type=EventType.ROUTINE_BROKEN, severity=Severity.WARNING, message="x", device_key=ROUTER, timestamp=at(10))]))
  assert repo.has_event_since(ROUTER, EventType.ROUTINE_BROKEN, at(5))
  assert not repo.has_event_since(ROUTER, EventType.ROUTINE_BROKEN, at(11))
  assert not repo.has_event_since(PHONE, EventType.ROUTINE_BROKEN, at(0))


def test_a_failure_while_recording_sessions_rolls_the_whole_scan_back(repo, monkeypatch):
  def broken(*_args):
    raise sqlite3.OperationalError("disk full")

  monkeypatch.setattr(Repository, "_record_sessions", broken)
  with pytest.raises(sqlite3.OperationalError):
    repo.save_scan(report([make_device("192.168.1.1", ROUTER)]))
  assert repo.list_scans() == [] and repo.load_devices() == {}


def test_recent_port_openings_keep_the_newest_per_port_and_skip_first_checks(repo):
  def opened(port, at, first_check=False):
    return Event(EventType.PORT_OPENED, Severity.WARNING, "x", device_key=ROUTER, details={"port": port, "first_check": first_check}, timestamp=at)

  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], [opened(22, T0), opened(22, T0 + timedelta(hours=1)), opened(8443, T0, first_check=True)]))
  [event] = repo.recent_port_openings(T0 - timedelta(days=1))
  assert event.details["port"] == 22 and event.timestamp == T0 + timedelta(hours=1) and event.acked_at is None
  repo.ack_events(ROUTER)
  assert repo.recent_port_openings(T0 - timedelta(days=1))[0].acked_at is not None
  assert repo.recent_port_openings(T0 + timedelta(hours=2)) == []
  assert repo.recent_port_openings(T0 - timedelta(days=1), device_keys=["someone"]) == []


def test_pending_events_are_grouped_per_device(repo):
  events = [Event(EventType.NEW_DEVICE, Severity.WARNING, f"e{i}", device_key=ROUTER, timestamp=T0 + timedelta(minutes=i)) for i in range(7)]
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], events))
  assert repo.pending_by_device() == {ROUTER: (7, T0 + timedelta(minutes=6))}
  latest = repo.latest_pending([ROUTER], per_device=3)[ROUTER]
  assert [e.message for e in latest] == ["e6", "e5", "e4"]


def test_recent_opening_preserves_the_latest_events_review_state(repo):
  events = [Event(EventType.PORT_OPENED, Severity.WARNING, str(i), device_key=ROUTER,
                  details={"port": 22}, timestamp=T0 + timedelta(hours=i)) for i in (2, 0, 1)]
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], events))
  latest = max(repo.list_events(), key=lambda e: e.timestamp)
  repo.ack_event(latest.id)
  [found] = repo.recent_port_openings(T0)
  assert found.id == latest.id and found.timestamp == latest.timestamp
  assert found.acked_at is not None
  assert repo.port_change_counts(T0) == {(EventType.PORT_OPENED, 22): 3}
