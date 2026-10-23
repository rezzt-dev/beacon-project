 # import libraries ->
import sqlite3
from datetime import timedelta

import pytest

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import DeviceStatus, Latency, ScanMode
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository
from beacon.storage.database import SCHEMA_VERSION
from conftest import T0, make_device


ROUTER = "34:5d:9e:3f:2a:77"
PHONE = "8e:e7:35:fe:0c:c6"


def report(devices, events=(), ports_scanned=False, at=T0):
  return ScanReport(
    network="192.168.1.0/24",
    mode=ScanMode.UNPRIVILEGED,
    started_at=at,
    finished_at=at,
    interface="wlan0",
    devices=list(devices),
    events=list(events),
    ports_scanned=ports_scanned,
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
  scan_id = repo.save_scan(report([router], ports_scanned=True))
  assert scan_id == 1

  loaded = repo.load_devices()[ROUTER]
  assert loaded.vendor == "Sagemcom"
  assert [p.port for p in loaded.open_ports] == [80, 443]
  assert loaded.latency is not None and loaded.latency.avg == 2.0
  assert loaded.first_seen == T0


def test_ports_are_synced_only_when_scanned(repo):
  repo.save_scan(report([make_device("192.168.1.1", ROUTER, ports=(80, 443))], ports_scanned=True))
  repo.save_scan(report([make_device("192.168.1.1", ROUTER)], ports_scanned=False))
  assert [p.port for p in repo.load_devices()[ROUTER].open_ports] == [80, 443]
  repo.save_scan(report([make_device("192.168.1.1", ROUTER, ports=(22,))], ports_scanned=True))
  assert [p.port for p in repo.load_devices()[ROUTER].open_ports] == [22]


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
