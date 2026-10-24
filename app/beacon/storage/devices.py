 # import libraries ->
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Any

from beacon.core.mac import normalize_mac
from beacon.core.models import Device, DeviceStatus, Latency, PortInfo, PortState, utcnow
from beacon.storage.base import ConflictError, NotFoundError, Store, dt, placeholders, ts


 # constants ->
# fields a person may edit; everything else comes from the network
EDITABLE_FIELDS = ("alias", "category", "tags", "notes", "owner", "essential")
MAX_TAGS = 16
MAX_TEXT = {"alias": 64, "category": 32, "notes": 2000, "owner": 64, "tag": 32}


def _ip_order(ip: str) -> tuple[int, int]:
  try:
    address = ip_address(ip)
    return address.version, int(address)
  except ValueError:
    return 9, 0


def _like(text: str) -> str:
  escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
  return f"%{escaped}%"


 # filters ->
@dataclass(slots=True)
class DeviceFilter:
  network_id: int | None = None
  status: DeviceStatus | None = None
  trusted: bool | None = None
  q: str | None = None
  tag: str | None = None
  category: str | None = None
  essential: bool | None = None
  has_open_ports: bool | None = None
  port: int | None = None
  keys: list[str] | None = None

  def where(self) -> tuple[str, list[Any]]:
    # in the port subqueries `+p.state` keeps sqlite on the (device_key, port) key instead of the
    # state index, which would scan every open port of the network once per device
    clauses: list[str] = []
    params: list[Any] = []
    if self.network_id is not None:
      clauses.append("d.network_id = ?")
      params.append(self.network_id)
    if self.status is not None:
      clauses.append("d.status = ?")
      params.append(str(self.status))
    if self.trusted is not None:
      clauses.append("d.trusted = ?")
      params.append(int(self.trusted))
    if self.essential is not None:
      clauses.append("d.essential = ?")
      params.append(int(self.essential))
    if self.category:
      clauses.append("d.category = ?")
      params.append(self.category)
    if self.tag:
      clauses.append("EXISTS (SELECT 1 FROM json_each(d.tags) WHERE json_each.value = ?)")
      params.append(self.tag)
    if self.has_open_ports is not None:
      clauses.append(
        ("" if self.has_open_ports else "NOT ") + "EXISTS (SELECT 1 FROM ports p WHERE p.device_key = d.key AND +p.state = 'open')"
      )
    if self.port is not None:
      clauses.append("EXISTS (SELECT 1 FROM ports p WHERE p.device_key = d.key AND +p.state = 'open' AND p.port = ?)")
      params.append(self.port)
    if self.keys is not None:
      clauses.append(f"d.key IN ({placeholders(self.keys) or 'NULL'})")
      params.extend(self.keys)
    if self.q:
      needle = self.q.strip().lower()
      mac = normalize_mac(needle)
      like = _like(needle)
      text = " OR ".join(
        f"LOWER(COALESCE(d.{column}, '')) LIKE ? ESCAPE '\\'"
        for column in ("alias", "hostname", "ip", "ips", "ips6", "mac", "vendor", "tags", "category", "owner", "os_guess")
      )
      ports = (
        "EXISTS (SELECT 1 FROM ports p WHERE p.device_key = d.key AND +p.state = 'open' "
        "AND (CAST(p.port AS TEXT) = ? OR LOWER(COALESCE(p.service, '')) LIKE ? ESCAPE '\\' "
        "OR LOWER(COALESCE(p.protocol_observed, '')) LIKE ? ESCAPE '\\'))"
      )
      clauses.append(f"({text} OR {ports}" + (" OR d.mac = ?" if mac else "") + ")")
      params.extend([like] * 11 + [needle, like, like] + ([mac] if mac else []))
    return (" AND ".join(clauses) or "1 = 1"), params


 # device store ->
class DeviceStore(Store):
  def _row_to_device(self, row: sqlite3.Row, ports: list[PortInfo]) -> Device:
    return Device(
      ip=row["ip"],
      mac=row["mac"],
      ips=json.loads(row["ips"]),
      hostname=row["hostname"],
      hostname_source=row["hostname_source"],
      vendor=row["vendor"],
      randomized_mac=bool(row["randomized_mac"]),
      ttl=row["ttl"],
      os_guess=row["os_guess"],
      ports=ports,
      latency=Latency.from_dict(json.loads(row["latency"])) if row["latency"] else None,
      is_local=bool(row["is_local"]),
      is_gateway=bool(row["is_gateway"]),
      alias=row["alias"],
      trusted=bool(row["trusted"]),
      status=DeviceStatus(row["status"]),
      first_seen=dt(row["first_seen"]),
      last_seen=dt(row["last_seen"]),
      services=json.loads(row["services"]),
      identity_id=row["identity_id"],
      network_id=row["network_id"],
      ips6=json.loads(row["ips6"]),
      category=row["category"],
      tags=json.loads(row["tags"]),
      notes=row["notes"],
      owner=row["owner"],
      essential=bool(row["essential"]),
      version=row["version"],
    )

  @staticmethod
  def _row_to_port(row: sqlite3.Row) -> PortInfo:
    return PortInfo(
      port=row["port"],
      protocol=row["protocol"],
      state=PortState(row["state"]),
      service=row["service"],
      banner=row["banner"],
      protocol_observed=row["protocol_observed"],
      last_probe=PortState(row["last_probe"]) if row["last_probe"] else None,
      checked_at=dt(row["checked_at"]),
      open_seen_at=dt(row["open_seen_at"]),
      first_seen=dt(row["first_seen"]),
      tls=json.loads(row["tls"]) if row["tls"] else None,
    )

  def device_keys(self, network_id: int | None = None) -> set[str]:
    query = "SELECT key FROM devices"
    params = []
    if network_id is not None:
      query += " WHERE network_id = ?"
      params.append(network_id)
    return {r["key"] for r in self.conn.execute(query, params)}

  def _ports_where(self, where: str = "1 = 1", params: Iterable[Any] = ()) -> dict[str, list[PortInfo]]:
    ports: dict[str, list[PortInfo]] = {}
    query = f"SELECT p.* FROM ports p WHERE p.device_key IN (SELECT d.key FROM devices d WHERE {where}) ORDER BY p.port"
    for row in self.conn.execute(query, list(params)):
      ports.setdefault(row["device_key"], []).append(self._row_to_port(row))
    return ports

  def filter_devices(self, flt: DeviceFilter | None = None) -> list[Device]:
    """devices matching `flt`, with their ports, ordered by address. two queries whatever the size."""
    where, params = (flt or DeviceFilter()).where()
    ports = self._ports_where(where, params)
    rows = self.conn.execute(f"SELECT d.* FROM devices d WHERE {where}", params).fetchall()
    devices = [self._row_to_device(row, ports.get(row["key"], [])) for row in rows]
    return sorted(devices, key=lambda d: _ip_order(d.ip))

  def load_devices(self, network_id: int | None = None) -> dict[str, Device]:
    return {d.key: d for d in self.filter_devices(DeviceFilter(network_id=network_id))}

  def list_devices(
    self, status: DeviceStatus | None = None, trusted: bool | None = None, network_id: int | None = None
  ) -> list[Device]:
    return self.filter_devices(DeviceFilter(network_id=network_id, status=status, trusted=trusted))

  def get_device(self, key: str) -> Device | None:
    row = self.conn.execute("SELECT * FROM devices WHERE key = ?", (key,)).fetchone()
    if row is None:
      return None
    ports = [self._row_to_port(r) for r in self.conn.execute("SELECT * FROM ports WHERE device_key = ? ORDER BY port", (key,))]
    return self._row_to_device(row, ports)

  def get_devices(self, keys: Iterable[str]) -> dict[str, Device]:
    wanted = list(dict.fromkeys(keys))
    if not wanted:
      return {}
    return {d.key: d for d in self.filter_devices(DeviceFilter(keys=wanted))}

  def find_device(self, ref: str, network_id: int | None = None) -> Device | None:
    """look a device up by key, mac (any notation), ip, alias or hostname, without loading the inventory.

    a mac or an address seen in several networks resolves to the online, most recently seen one.
    """
    if (device := self.get_device(ref)) is not None:
      return device
    needle = ref.strip().lower()
    mac = normalize_mac(ref)
    query = (
      "SELECT key FROM devices WHERE (mac = ? OR ip = ? OR LOWER(alias) = ? OR LOWER(hostname) = ? "
      "OR EXISTS (SELECT 1 FROM json_each(devices.ips) WHERE json_each.value = ?))"
    )
    params: list[Any] = [mac, needle, needle, needle, needle]
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    query += " ORDER BY status = 'online' DESC, last_seen DESC LIMIT 1"
    row = self.conn.execute(query, params).fetchone()
    return self.get_device(row["key"]) if row else None

  # edits ->
  def _bump(self, key: str, network_id: int | None, actor: str, action: str, **details: Any) -> None:
    self.conn.execute("UPDATE devices SET version = version + 1, updated_at = ? WHERE key = ?", (ts(utcnow()), key))
    self._audit(actor, action, "device", key, **details)
    self._change("device.updated", "device", key, network_id, action=action)

  def _network_of(self, key: str) -> int | None:
    row = self.conn.execute("SELECT network_id FROM devices WHERE key = ?", (key,)).fetchone()
    return row["network_id"] if row else None

  def set_trusted(self, key: str, trusted: bool, actor: str = "cli", expected_version: int | None = None) -> None:
    """trusting a device is a decision about it, so its pending events count as reviewed.

    the events stay in the history and keep feeding the risk score while they are recent.
    """
    with self.conn:
      condition = "" if expected_version is None else " AND version = ?"
      params = (int(trusted), key) if expected_version is None else (int(trusted), key, expected_version)
      changed = self.conn.execute(f"UPDATE devices SET trusted = ? WHERE key = ?{condition}", params).rowcount
      if not changed:
        if expected_version is not None:
          current = self.conn.execute("SELECT version FROM devices WHERE key = ?", (key,)).fetchone()
          if current is None:
            raise NotFoundError(f"device {key} not found")
          raise ConflictError("device", key, current["version"])
        return
      if trusted:
        self._ack(key, actor)
        self.conn.execute("UPDATE devices SET snoozed_until = NULL WHERE key = ?", (key,))
      self._bump(key, self._network_of(key), actor, "trust" if trusted else "untrust")

  def trust_all(self, actor: str = "cli", network_id: int | None = None) -> int:
    scope = "" if network_id is None else " AND network_id = ?"
    params: tuple[Any, ...] = () if network_id is None else (network_id,)
    with self.conn:
      keys = [r["key"] for r in self.conn.execute(f"SELECT key FROM devices WHERE trusted = 0{scope}", params)]
      for key in keys:
        self.conn.execute("UPDATE devices SET trusted = 1, snoozed_until = NULL WHERE key = ?", (key,))
        self._ack(key, actor)
        self._bump(key, self._network_of(key), actor, "trust", bulk=True)
      return len(keys)

  def set_alias(self, key: str, alias: str | None, actor: str = "cli") -> None:
    self.update_device(key, {"alias": alias}, actor=actor)

  def update_device(
    self, key: str, changes: dict[str, Any], expected_version: int | None = None, actor: str = "cli"
  ) -> Device:
    """apply user edits atomically. `expected_version` rejects an edit made on stale data."""
    unknown = set(changes) - set(EDITABLE_FIELDS)
    if unknown:
      raise ValueError(f"fields not editable: {', '.join(sorted(unknown))}")
    values = {name: _clean_field(name, value) for name, value in changes.items()}
    with self.conn:
      row = self.conn.execute("SELECT version, network_id FROM devices WHERE key = ?", (key,)).fetchone()
      if row is None:
        raise NotFoundError(f"device {key} not found")
      if expected_version is not None and row["version"] != expected_version:
        raise ConflictError("device", key, row["version"])
      if values:
        assignments = ", ".join(f"{name} = ?" for name in values)
        params = [json.dumps(v) if name == "tags" else int(v) if name == "essential" else v for name, v in values.items()]
        condition = "" if expected_version is None else " AND version = ?"
        params.append(key)
        if expected_version is not None:
          params.append(expected_version)
        changed = self.conn.execute(f"UPDATE devices SET {assignments} WHERE key = ?{condition}", params).rowcount
        if not changed:
          current = self.conn.execute("SELECT version FROM devices WHERE key = ?", (key,)).fetchone()
          if current is None:
            raise NotFoundError(f"device {key} not found")
          raise ConflictError("device", key, current["version"])
        self._bump(key, row["network_id"], actor, "edit", fields=sorted(values))
    device = self.get_device(key)
    assert device is not None
    return device

  def snooze(self, key: str, until: datetime | None, actor: str = "cli") -> None:
    """postpone the review of a device until `until`; its events stay pending and come back afterwards."""
    with self.conn:
      if not self.conn.execute("UPDATE devices SET snoozed_until = ? WHERE key = ?", (ts(until), key)).rowcount:
        raise NotFoundError(f"device {key} not found")
      self._bump(key, self._network_of(key), actor, "snooze" if until else "unsnooze", until=ts(until))

  def snoozed(self, now: datetime | None = None) -> dict[str, datetime]:
    now = now or utcnow()
    rows = self.conn.execute("SELECT key, snoozed_until FROM devices WHERE snoozed_until IS NOT NULL AND snoozed_until > ?", (ts(now),))
    return {r["key"]: datetime.fromisoformat(r["snoozed_until"]) for r in rows}

  def delete_device(self, key: str, actor: str = "cli") -> bool:
    with self.conn:
      network_id = self._network_of(key)
      self._ack(key, actor)
      deleted = self.conn.execute("DELETE FROM devices WHERE key = ?", (key,)).rowcount > 0
      self._prune_identities()
      if deleted:
        self._audit(actor, "forget", "device", key)
        self._change("device.deleted", "device", key, network_id)
    return deleted

  def tags_in_use(self) -> list[tuple[str, int]]:
    rows = self.conn.execute(
      "SELECT json_each.value AS tag, COUNT(*) AS n FROM devices, json_each(devices.tags) GROUP BY tag ORDER BY n DESC, tag"
    )
    return [(r["tag"], r["n"]) for r in rows]


def _clean_field(name: str, value: Any) -> Any:
  """validate one editable field: strings are stripped and capped, empty means none."""
  if name == "essential":
    if not isinstance(value, bool):
      raise ValueError("essential must be true or false")
    return value
  if name == "tags":
    if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
      raise ValueError("tags must be a list of strings")
    tags = list(dict.fromkeys(t.strip().lower() for t in value if t.strip()))
    if len(tags) > MAX_TAGS:
      raise ValueError(f"at most {MAX_TAGS} tags")
    if any(len(t) > MAX_TEXT["tag"] for t in tags):
      raise ValueError(f"tags are at most {MAX_TEXT['tag']} characters")
    return tags
  if value is None:
    return None
  if not isinstance(value, str):
    raise ValueError(f"{name} must be text")
  text = value.strip()
  if len(text) > MAX_TEXT[name]:
    raise ValueError(f"{name} is at most {MAX_TEXT[name]} characters")
  return text or None


 # port rows ->
def port_rows(conn: sqlite3.Connection, network_id: int | None = None) -> list[dict[str, Any]]:
  """every known port joined with its device, for the services inventory."""
  query = """SELECT p.*, d.ip, d.alias, d.hostname, d.network_id, d.status AS device_status, d.trusted
             FROM ports p JOIN devices d ON d.key = p.device_key"""
  params: list[Any] = []
  if network_id is not None:
    query += " WHERE d.network_id = ?"
    params.append(network_id)
  return [dict(r) for r in conn.execute(query + " ORDER BY p.port, d.ip", params)]
