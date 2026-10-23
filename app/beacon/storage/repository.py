 # import libraries ->
import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.identity import IdentityMatch, suggest_links
from beacon.core.mac import normalize_mac
from beacon.core.models import Device, DeviceStatus, Latency, PortInfo, PortState, utcnow
from beacon.core.presence import SESSION_GAP, Session
from beacon.core.report import ScanReport
from beacon.storage.database import Database


 # helpers ->
def _ts(value: datetime | None) -> str | None:
  return value.isoformat() if value else None


def _dt(value: str | None) -> datetime | None:
  return datetime.fromisoformat(value) if value else None


def _ip_key(device: Device) -> IPv4Address:
  return IPv4Address(device.ip)


# events that ask for a decision from the user: informational ones never need review
_PENDING_SEVERITIES = (str(Severity.ALERT), str(Severity.WARNING))


 # repository ->
class Repository:
  """all sql lives here; the rest of the app only sees domain models."""

  def __init__(self, db: Database) -> None:
    self.db = db

  @property
  def conn(self) -> sqlite3.Connection:
    return self.db.conn

  # devices ->
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
      first_seen=_dt(row["first_seen"]),
      last_seen=_dt(row["last_seen"]),
      services=json.loads(row["services"]),
      identity_id=row["identity_id"],
    )

  def _ports_by_device(self) -> dict[str, list[PortInfo]]:
    ports: dict[str, list[PortInfo]] = {}
    for row in self.conn.execute("SELECT * FROM ports ORDER BY port"):
      ports.setdefault(row["device_key"], []).append(
        PortInfo(port=row["port"], protocol=row["protocol"], state=PortState.OPEN, service=row["service"], banner=row["banner"])
      )
    return ports

  def load_devices(self) -> dict[str, Device]:
    ports = self._ports_by_device()
    rows = self.conn.execute("SELECT * FROM devices").fetchall()
    return {row["key"]: self._row_to_device(row, ports.get(row["key"], [])) for row in rows}

  def list_devices(self, status: DeviceStatus | None = None, trusted: bool | None = None) -> list[Device]:
    devices = [
      d
      for d in self.load_devices().values()
      if (status is None or d.status == status) and (trusted is None or d.trusted == trusted)
    ]
    return sorted(devices, key=_ip_key)

  def find_device(self, ref: str) -> Device | None:
    """look a device up by key, mac (any notation), ip, alias or hostname."""
    devices = self.load_devices()
    if ref in devices:
      return devices[ref]
    mac = normalize_mac(ref)
    if mac and mac in devices:
      return devices[mac]
    needle = ref.strip().lower()
    matches = [
      d
      for d in devices.values()
      if needle in {d.ip, (d.alias or "").lower(), (d.hostname or "").lower()} or needle in d.ips
    ]
    matches.sort(key=lambda d: (d.status != DeviceStatus.ONLINE, -(d.last_seen.timestamp() if d.last_seen else 0)))
    return matches[0] if matches else None

  def set_trusted(self, key: str, trusted: bool) -> None:
    """trusting a device is a decision about it, so its pending events count as reviewed."""
    with self.conn:
      self.conn.execute("UPDATE devices SET trusted = ? WHERE key = ?", (int(trusted), key))
      if trusted:
        self._ack(key)

  def trust_all(self) -> int:
    with self.conn:
      self.conn.execute(
        "UPDATE events SET acked_at = ? WHERE acked_at IS NULL AND device_key IN (SELECT key FROM devices WHERE trusted = 0)",
        (_ts(utcnow()),),
      )
      return self.conn.execute("UPDATE devices SET trusted = 1 WHERE trusted = 0").rowcount

  def set_alias(self, key: str, alias: str | None) -> None:
    with self.conn:
      self.conn.execute("UPDATE devices SET alias = ? WHERE key = ?", (alias, key))

  def delete_device(self, key: str) -> bool:
    with self.conn:
      self._ack(key)
      deleted = self.conn.execute("DELETE FROM devices WHERE key = ?", (key,)).rowcount > 0
      self._prune_identities()
    return deleted

  # scans ->
  def save_scan(self, report: ScanReport, presence: bool = True, presence_gap: timedelta = SESSION_GAP) -> int:
    """persist a finished scan atomically: devices, open ports, presence sessions, offline transitions and events."""
    finished = report.finished_at or report.started_at
    with self.conn:
      cursor = self.conn.execute(
        """INSERT INTO scans (started_at, finished_at, network, interface, mode, ports_scanned, device_count, event_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
          _ts(report.started_at),
          _ts(finished),
          report.network,
          report.interface,
          str(report.mode),
          int(report.ports_scanned),
          len(report.devices),
          len(report.events),
        ),
      )
      scan_id = int(cursor.lastrowid or 0)

      for device in report.devices:
        self._upsert_device(device)
        if report.ports_scanned:
          self._sync_ports(device, finished)

      offline = [(e.device_key,) for e in report.events if e.type == EventType.DEVICE_OFFLINE and e.device_key]
      self.conn.executemany("UPDATE devices SET status = 'offline' WHERE key = ?", offline)
      if presence:
        self._record_sessions(report.devices, [key for (key,) in offline], finished, presence_gap)

      self.conn.executemany(
        """INSERT INTO events (scan_id, timestamp, type, severity, device_key, ip, mac, message, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
          (scan_id, _ts(e.timestamp), str(e.type), str(e.severity), e.device_key, e.ip, e.mac, e.message, json.dumps(e.details))
          for e in report.events
        ],
      )
    return scan_id

  def _upsert_device(self, d: Device) -> None:
    self.conn.execute(
      """INSERT INTO devices (key, mac, ip, ips, hostname, hostname_source, vendor, randomized_mac, ttl, os_guess,
                              alias, trusted, status, is_local, is_gateway, latency, first_seen, last_seen, services)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (key) DO UPDATE SET
           mac = excluded.mac, ip = excluded.ip, ips = excluded.ips,
           hostname = COALESCE(excluded.hostname, devices.hostname),
           hostname_source = COALESCE(excluded.hostname_source, devices.hostname_source),
           vendor = COALESCE(excluded.vendor, devices.vendor),
           randomized_mac = excluded.randomized_mac,
           ttl = COALESCE(excluded.ttl, devices.ttl),
           os_guess = COALESCE(excluded.os_guess, devices.os_guess),
           status = excluded.status, is_local = excluded.is_local, is_gateway = excluded.is_gateway,
           latency = COALESCE(excluded.latency, devices.latency),
           services = CASE WHEN excluded.services = '[]' THEN devices.services ELSE excluded.services END,
           last_seen = excluded.last_seen""",
      (
        d.key,
        d.mac,
        d.ip,
        json.dumps(d.ips or [d.ip]),
        d.hostname,
        d.hostname_source,
        d.vendor,
        int(d.randomized_mac),
        d.ttl,
        d.os_guess,
        d.alias,
        int(d.trusted),
        str(DeviceStatus.ONLINE),
        int(d.is_local),
        int(d.is_gateway),
        json.dumps(d.latency.to_dict()) if d.latency else None,
        _ts(d.first_seen or d.last_seen),
        _ts(d.last_seen),
        json.dumps(d.services),
      ),
    )

  def _sync_ports(self, device: Device, seen_at: datetime) -> None:
    open_ports = device.open_ports
    self.conn.executemany(
      """INSERT INTO ports (device_key, port, protocol, service, banner, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (device_key, port, protocol) DO UPDATE SET
           service = excluded.service, banner = COALESCE(excluded.banner, ports.banner), last_seen = excluded.last_seen""",
      [(device.key, p.port, p.protocol, p.service, p.banner, _ts(seen_at), _ts(seen_at)) for p in open_ports],
    )
    placeholders = ",".join("?" * len(open_ports))
    keep = f"AND port NOT IN ({placeholders})" if open_ports else ""
    self.conn.execute(f"DELETE FROM ports WHERE device_key = ? {keep}", (device.key, *[p.port for p in open_ports]))

  def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
    rows = self.conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(row) for row in rows]

  # events ->
  def list_events(
    self,
    limit: int = 50,
    device_key: str | None = None,
    types: list[EventType] | None = None,
    min_severity: Severity | None = None,
    pending_only: bool = False,
  ) -> list[Event]:
    query = "SELECT * FROM events WHERE 1 = 1"
    params: list[Any] = []
    if device_key:
      query += " AND device_key = ?"
      params.append(device_key)
    if types:
      query += f" AND type IN ({','.join('?' * len(types))})"
      params.extend(str(t) for t in types)
    if min_severity:
      levels = list(Severity)[list(Severity).index(min_severity) :]
      query += f" AND severity IN ({','.join('?' * len(levels))})"
      params.extend(str(s) for s in levels)
    if pending_only:
      query += f" AND acked_at IS NULL AND device_key IS NOT NULL AND severity IN ({','.join('?' * len(_PENDING_SEVERITIES))})"
      params.extend(_PENDING_SEVERITIES)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [
      Event(
        type=EventType(row["type"]),
        severity=Severity(row["severity"]),
        message=row["message"],
        device_key=row["device_key"],
        ip=row["ip"],
        mac=row["mac"],
        details=json.loads(row["details"]),
        timestamp=datetime.fromisoformat(row["timestamp"]),
        id=row["id"],
      )
      for row in self.conn.execute(query, params)
    ]

  def list_pending_events(self) -> list[Event]:
    """alerts and warnings tied to a device that nobody has reviewed yet, newest first."""
    return self.list_events(limit=-1, pending_only=True)

  def ack_events(self, device_key: str) -> int:
    """mark every pending event of a device as reviewed; calling it again changes nothing."""
    with self.conn:
      return self._ack(device_key)

  def _ack(self, device_key: str) -> int:
    return self.conn.execute(
      "UPDATE events SET acked_at = ? WHERE device_key = ? AND acked_at IS NULL", (_ts(utcnow()), device_key)
    ).rowcount

  def has_event_since(self, device_key: str, kind: EventType, since: datetime) -> bool:
    row = self.conn.execute(
      "SELECT 1 FROM events WHERE device_key = ? AND type = ? AND timestamp >= ? LIMIT 1",
      (device_key, str(kind), _ts(since)),
    ).fetchone()
    return row is not None

  def ports_ever_scanned(self) -> bool:
    """false until a scan included ports: without it an empty port list means unknown, not closed."""
    return self.conn.execute("SELECT 1 FROM scans WHERE ports_scanned = 1 LIMIT 1").fetchone() is not None

  # identities ->
  def link_devices(self, new_key: str, old_key: str) -> int:
    """put two macs under one identity, copy the alias to the one without it and review the new one.

    trust is never copied: a hostname is easy to spoof, so trusting the new mac is a separate decision.
    """
    if new_key == old_key:
      raise ValueError("a device cannot be linked to itself")
    with self.conn:
      rows = {
        row["key"]: row
        for row in self.conn.execute(
          "SELECT key, identity_id, alias, hostname FROM devices WHERE key IN (?, ?)", (new_key, old_key)
        )
      }
      if len(rows) != 2:
        raise ValueError("both devices must exist in the inventory")
      existing = sorted({r["identity_id"] for r in rows.values() if r["identity_id"] is not None})
      if existing:
        identity_id = existing[0]
        self.conn.execute(
          f"UPDATE devices SET identity_id = ? WHERE identity_id IN ({','.join('?' * len(existing))})",
          (identity_id, *existing),
        )
      else:
        old = rows[old_key]
        label = old["alias"] or old["hostname"] or old_key
        cursor = self.conn.execute("INSERT INTO identities (label, created_at) VALUES (?, ?)", (label, _ts(utcnow())))
        identity_id = int(cursor.lastrowid or 0)
      self.conn.execute("UPDATE devices SET identity_id = ? WHERE key IN (?, ?)", (identity_id, new_key, old_key))
      if rows[new_key]["alias"] is None and rows[old_key]["alias"]:
        self.conn.execute("UPDATE devices SET alias = ? WHERE key = ?", (rows[old_key]["alias"], new_key))
      self._ack(new_key)
      self._prune_identities()
    return identity_id

  def unlink_device(self, key: str) -> bool:
    """take a device out of its identity; an identity left with a single mac is dissolved."""
    with self.conn:
      changed = self.conn.execute(
        "UPDATE devices SET identity_id = NULL WHERE key = ? AND identity_id IS NOT NULL", (key,)
      ).rowcount > 0
      self._prune_identities()
    return changed

  def _prune_identities(self) -> None:
    self.conn.execute(
      """UPDATE devices SET identity_id = NULL WHERE identity_id IN
           (SELECT identity_id FROM devices WHERE identity_id IS NOT NULL GROUP BY identity_id HAVING COUNT(*) < 2)"""
    )
    self.conn.execute("DELETE FROM identities WHERE id NOT IN (SELECT identity_id FROM devices WHERE identity_id IS NOT NULL)")

  def identity_members(self, device: Device) -> list[Device]:
    """the other macs that belong to the same physical device, oldest first."""
    if device.identity_id is None:
      return []
    members = [d for d in self.load_devices().values() if d.identity_id == device.identity_id and d.key != device.key]
    return sorted(members, key=lambda d: d.first_seen or utcnow())

  def list_candidates(self) -> list[IdentityMatch]:
    """possible links between stored randomized macs, strongest first."""
    return suggest_links(self.load_devices().values())

  # sessions ->
  def _record_sessions(
    self, devices: Iterable[Device], offline_keys: list[str], finished: datetime, gap: timedelta
  ) -> None:
    """extend the open session of every present device, start one when there is none and close the ones that went offline."""
    open_sessions = {
      row["device_key"]: (row["id"], _dt(row["last_seen"]))
      for row in self.conn.execute("SELECT id, device_key, last_seen FROM sessions WHERE ended_at IS NULL")
    }
    for device in devices:
      seen = device.last_seen or finished
      current = open_sessions.get(device.key)
      if current is not None and current[1] is not None and seen - current[1] > gap:
        # the device was not watched for a while: do not claim it was there all along
        self.conn.execute("UPDATE sessions SET ended_at = last_seen WHERE id = ?", (current[0],))
        current = None
      if current is not None:
        self.conn.execute("UPDATE sessions SET last_seen = MAX(last_seen, ?) WHERE id = ?", (_ts(seen), current[0]))
      else:
        self.conn.execute(
          "INSERT INTO sessions (device_key, started_at, last_seen) VALUES (?, ?, ?)", (device.key, _ts(seen), _ts(seen))
        )
    # a session ends when the device was last seen, not when the scan noticed it was gone
    self.conn.executemany(
      "UPDATE sessions SET ended_at = last_seen WHERE device_key = ? AND ended_at IS NULL", [(key,) for key in offline_keys]
    )

  def list_sessions(self, device_keys: Iterable[str] | None = None, since: datetime | None = None) -> dict[str, list[Session]]:
    """sessions per device that were still running at or after `since`, oldest first."""
    query = "SELECT * FROM sessions WHERE 1 = 1"
    params: list[Any] = []
    if since is not None:
      query += " AND last_seen >= ?"
      params.append(_ts(since))
    if device_keys is not None:
      keys = list(device_keys)
      if not keys:
        return {}
      query += f" AND device_key IN ({','.join('?' * len(keys))})"
      params.extend(keys)
    query += " ORDER BY started_at"
    sessions: dict[str, list[Session]] = {}
    for row in self.conn.execute(query, params):
      sessions.setdefault(row["device_key"], []).append(
        Session(
          device_key=row["device_key"],
          started_at=datetime.fromisoformat(row["started_at"]),
          last_seen=datetime.fromisoformat(row["last_seen"]),
          ended_at=_dt(row["ended_at"]),
        )
      )
    return sessions

  def sessions_by_identity(self, devices: Iterable[Device], since: datetime | None = None) -> dict[str, list[Session]]:
    """sessions per device, pooling the macs of a linked identity so a rotating address keeps one history."""
    everyone = list(devices)
    members: dict[int, list[str]] = {}
    for row in self.conn.execute("SELECT key, identity_id FROM devices WHERE identity_id IS NOT NULL"):
      members.setdefault(row["identity_id"], []).append(row["key"])
    group = {d.key: members.get(d.identity_id, [d.key]) if d.identity_id is not None else [d.key] for d in everyone}
    raw = self.list_sessions({key for keys in group.values() for key in keys}, since)
    return {
      key: sorted((s for member in keys for s in raw.get(member, [])), key=lambda s: s.started_at)
      for key, keys in group.items()
    }

  def presence_span(self) -> tuple[int, datetime | None]:
    """how many sessions are stored and when the oldest one started."""
    row = self.conn.execute("SELECT COUNT(*) AS total, MIN(started_at) AS oldest FROM sessions").fetchone()
    return row["total"], _dt(row["oldest"])

  def prune_sessions(self, before: datetime) -> int:
    """delete sessions that ended before `before`; open ones are never touched."""
    with self.conn:
      return self.conn.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?", (_ts(before),)).rowcount

  # stats ->
  def stats(self) -> dict[str, Any]:
    row = self.conn.execute(
      """SELECT COUNT(*) AS total,
                COALESCE(SUM(status = 'online'), 0) AS online,
                COALESCE(SUM(trusted = 1), 0) AS trusted,
                COALESCE(SUM(randomized_mac = 1), 0) AS randomized
         FROM devices"""
    ).fetchone()
    last = self.conn.execute("SELECT finished_at, network FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {
      **dict(row),
      "untrusted": row["total"] - row["trusted"],
      "scans": self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
      "last_scan": dict(last) if last else None,
    }
