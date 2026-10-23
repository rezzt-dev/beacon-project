 # import libraries ->
import json
import sqlite3
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.mac import normalize_mac
from beacon.core.models import Device, DeviceStatus, Latency, PortInfo, PortState
from beacon.core.report import ScanReport
from beacon.storage.database import Database


 # helpers ->
def _ts(value: datetime | None) -> str | None:
  return value.isoformat() if value else None


def _dt(value: str | None) -> datetime | None:
  return datetime.fromisoformat(value) if value else None


def _ip_key(device: Device) -> IPv4Address:
  return IPv4Address(device.ip)


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
    with self.conn:
      self.conn.execute("UPDATE devices SET trusted = ? WHERE key = ?", (int(trusted), key))

  def trust_all(self) -> int:
    with self.conn:
      return self.conn.execute("UPDATE devices SET trusted = 1 WHERE trusted = 0").rowcount

  def set_alias(self, key: str, alias: str | None) -> None:
    with self.conn:
      self.conn.execute("UPDATE devices SET alias = ? WHERE key = ?", (alias, key))

  def delete_device(self, key: str) -> bool:
    with self.conn:
      return self.conn.execute("DELETE FROM devices WHERE key = ?", (key,)).rowcount > 0

  # scans ->
  def save_scan(self, report: ScanReport) -> int:
    """persist a finished scan atomically: devices, open ports, offline transitions and events."""
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
                              alias, trusted, status, is_local, is_gateway, latency, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      )
      for row in self.conn.execute(query, params)
    ]

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
