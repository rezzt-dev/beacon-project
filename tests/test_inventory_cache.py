"""Inventory reuse must preserve edits, independent databases and time-sensitive risk."""
from datetime import timedelta

from beacon.core.models import ScanMode
from beacon.core.report import ScanReport
from beacon.services.inventory import DeviceQuery, query_devices
from beacon.storage import Database, Repository
from conftest import T0, make_device


def seed(repo, alias="before"):
  device = make_device("192.168.1.2", "00:11:22:33:44:55", alias=alias)
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0, devices=[device]))
  return device.key


def test_inventory_reuses_a_page_within_the_minute_and_expires_on_time(repo, monkeypatch):
  seed(repo)
  moment = T0 + timedelta(seconds=1, microseconds=123)
  monkeypatch.setattr("beacon.services.inventory.utcnow", lambda: moment)
  query_devices(repo, DeviceQuery())
  original = repo.filter_devices
  calls = []

  def counted(*args, **kwargs):
    calls.append(1)
    return original(*args, **kwargs)

  monkeypatch.setattr(repo, "filter_devices", counted)
  moment += timedelta(seconds=2, microseconds=456)
  assert query_devices(repo, DeviceQuery(size=1)).total == 1
  query_devices(repo, DeviceQuery(sort="risk", descending=True))
  assert calls == []
  moment += timedelta(minutes=1)
  query_devices(repo, DeviceQuery())
  assert len(calls) == 1


def test_inventory_cache_sees_commits_from_another_connection(tmp_path):
  path = tmp_path / "shared.db"
  with Database(path) as db, Database(path) as other_db:
    reader, writer = Repository(db), Repository(other_db)
    key = seed(writer)
    assert query_devices(reader, DeviceQuery()).items[0]["alias"] == "before"
    writer.set_alias(key, "after")
    assert query_devices(reader, DeviceQuery()).items[0]["alias"] == "after"


def test_memory_databases_and_empty_key_filters_are_independent(repo):
  seed(repo)
  assert query_devices(repo, DeviceQuery()).total == 1
  assert query_devices(repo, DeviceQuery(keys=[])).total == 0
  with Database(":memory:") as db:
    other = Repository(db)
    seed(other, "different")
    assert query_devices(other, DeviceQuery()).items[0]["alias"] == "different"


def test_trust_rejects_an_edit_committed_after_the_service_version_check(tmp_path, monkeypatch):
  import pytest

  from beacon.services.inventory import set_trust
  from beacon.storage import ConflictError

  path = tmp_path / "race.db"
  with Database(path) as db, Database(path) as other_db:
    reader, writer = Repository(db), Repository(other_db)
    key = seed(writer)
    original = reader.get_device

    def concurrent_edit(key):
      device = original(key)
      writer.set_alias(key, "edited elsewhere")
      return device

    monkeypatch.setattr(reader, "get_device", concurrent_edit)
    with pytest.raises(ConflictError):
      set_trust(reader, key, True, "web", expected_version=0)
    assert writer.get_device(key).alias == "edited elsewhere"
    assert not writer.get_device(key).trusted
