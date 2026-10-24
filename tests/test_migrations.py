 # import libraries ->
import sqlite3

import pytest

from beacon.core.events import EventType
from beacon.core.models import PortState
from beacon.storage import Database, Repository
from beacon.storage.database import MIGRATIONS, SCHEMA_VERSION, backup_to, restore_from, verify


ROUTER = "34:5d:9e:3f:2a:77"
PHONE = "8e:e7:35:fe:0c:c6"


 # fixtures ->
def legacy_database(path, version: int) -> None:
  """a database created by an older build at schema `version`, with the data that build could hold."""
  conn = sqlite3.connect(path)
  for index in range(version):
    conn.executescript(f"BEGIN;\n{MIGRATIONS[index]}\nPRAGMA user_version = {index + 1};\nCOMMIT;")
  extra = ", services, identity_id" if version >= 3 else ""
  extra_values = ", '[\"_airplay._tcp\"]', NULL" if version >= 3 else ""
  for key, ip, gateway in ((ROUTER, "192.168.1.1", 1), (PHONE, "192.168.1.9", 0)):
    conn.execute(
      f"""INSERT INTO devices (key, mac, ip, ips, vendor, alias, trusted, status, is_gateway, first_seen, last_seen{extra})
          VALUES (?, ?, ?, ?, 'Acme', ?, 1, 'online', ?, '2026-10-01T10:00:00+00:00', '2026-10-20T10:00:00+00:00'{extra_values})""",
      (key, key, ip, f'["{ip}"]', "router" if gateway else None, gateway),
    )
  conn.execute(
    """INSERT INTO ports (device_key, port, protocol, service, banner, first_seen, last_seen)
       VALUES (?, 22, 'tcp', 'ssh', 'SSH-2.0-dropbear', '2026-10-01T10:00:00+00:00', '2026-10-20T10:00:00+00:00')""",
    (ROUTER,),
  )
  conn.execute(
    """INSERT INTO scans (started_at, finished_at, network, interface, mode, ports_scanned, device_count, event_count)
       VALUES ('2026-10-20T09:59:00+00:00', '2026-10-20T10:00:00+00:00', '192.168.1.0/24', 'wlan0', 'unprivileged', 1, 2, 1)"""
  )
  conn.execute(
    """INSERT INTO events (scan_id, timestamp, type, severity, device_key, ip, mac, message)
       VALUES (1, '2026-10-20T10:00:00+00:00', 'new-device', 'warning', ?, '192.168.1.9', ?, 'found')""",
    (PHONE, PHONE),
  )
  if version >= 4:
    conn.execute(
      "INSERT INTO sessions (device_key, started_at, last_seen) VALUES (?, '2026-10-20T09:00:00+00:00', '2026-10-20T10:00:00+00:00')",
      (PHONE,),
    )
  conn.commit()
  conn.close()


 # migrations ->
@pytest.mark.parametrize("version", [1, 2, 3, 4])
def test_every_supported_version_migrates_with_its_data(tmp_path, version):
  path = tmp_path / "beacon.db"
  legacy_database(path, version)
  db = Database(path)
  repo = Repository(db)
  assert db.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
  assert db.last_backup is not None and db.last_backup.exists()

  devices = repo.load_devices()
  assert set(devices) == {ROUTER, PHONE}
  assert devices[ROUTER].alias == "router" and devices[ROUTER].trusted and devices[ROUTER].network_id == 1
  [port] = devices[ROUTER].ports
  assert (port.state, port.last_probe, str(port.checked_at)) == (PortState.OPEN, PortState.OPEN, "2026-10-20 10:00:00+00:00")
  # the legacy scan examined ports but did not record which: known, set unknown
  assert repo.port_coverage()[ROUTER][0] is None

  [network] = repo.list_networks()
  assert (network["id"], network["cidr"], network["gateway_mac"]) == (1, "192.168.1.0/24", ROUTER)
  [scan] = repo.list_scans()
  assert scan["status"] == "complete" and scan["network_id"] == 1
  [event] = repo.list_events()
  assert event.type == EventType.NEW_DEVICE and event.scan_id == 1 and event.network_id == 1
  if version >= 4:
    assert len(repo.list_sessions()[PHONE]) == 1
  assert verify(path) == []
  db.close()


def test_a_migrated_database_keeps_working(tmp_path):
  path = tmp_path / "beacon.db"
  legacy_database(path, 4)
  repo = Repository(Database(path))
  repo.update_device(PHONE, {"alias": "ana's phone", "tags": ["family"]}, expected_version=0)
  repo.set_trusted(PHONE, False)
  assert repo.get_device(PHONE).alias == "ana's phone" and repo.get_device(PHONE).version == 2
  assert [a["action"] for a in repo.list_audit("device", PHONE)] == ["untrust", "edit"]


def test_a_newer_schema_is_refused(tmp_path):
  path = tmp_path / "beacon.db"
  conn = sqlite3.connect(path)
  conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
  conn.close()
  with pytest.raises(RuntimeError, match="newer"):
    _ = Database(path).conn


def test_only_a_few_automatic_backups_are_kept(tmp_path):
  for _ in range(5):
    path = tmp_path / "beacon.db"
    path.unlink(missing_ok=True)
    legacy_database(path, 4)
    Database(path).conn.close()
  assert len(list(tmp_path.glob("beacon.db.v4-*.bak"))) <= 3


 # backup and restore ->
def test_backup_and_restore_round_trip(tmp_path):
  path = tmp_path / "beacon.db"
  legacy_database(path, 4)
  db = Database(path)
  repo = Repository(db)
  copy = db.backup(tmp_path / "copy.db")
  repo.delete_device(PHONE)
  assert PHONE not in repo.load_devices()
  db.close()

  restore_from(copy, path)
  restored = Repository(Database(path))
  assert set(restored.load_devices()) == {ROUTER, PHONE}
  assert (tmp_path / "beacon.db.before-restore").exists()
  assert verify(path) == []


def test_a_damaged_backup_is_not_restored(tmp_path):
  bad = tmp_path / "bad.db"
  bad.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
  target = tmp_path / "beacon.db"
  legacy_database(target, 4)
  with pytest.raises((RuntimeError, sqlite3.DatabaseError)):
    restore_from(bad, target)
  assert sqlite3.connect(target).execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2


def test_backup_while_another_connection_writes(tmp_path):
  path = tmp_path / "beacon.db"
  writer = Database(path)
  repo = Repository(writer)
  legacy = sqlite3.connect(path)
  repo.set_setting("theme", "dark")
  backup_to(legacy, tmp_path / "hot.db")
  assert Repository(Database(tmp_path / "hot.db")).get_setting("theme") == "dark"
