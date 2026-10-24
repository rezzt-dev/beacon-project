 # import libraries ->
import json
import os
from collections.abc import Iterable
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

from beacon.core.events import EventType
from beacon.core.models import Device, DeviceStatus, PortInfo, utcnow
from beacon.core.ports import PortSet
from beacon.core.presence import SESSION_GAP
from beacon.core.report import ScanIssue, ScanReport, ScanStatus
from beacon.core.risk import RULES_VERSION
from beacon.storage.base import Store, dt, placeholders, ts


 # helpers ->
@lru_cache(maxsize=256)
def _parse_spec(spec: str) -> PortSet:
  """devices share a few port profiles: parse each spec once (a port set is immutable)."""
  return PortSet.parse(spec)


def _pid_alive(pid: int | None) -> bool:
  if not pid:
    return False
  if pid == os.getpid():
    return True
  try:
    os.kill(pid, 0)
  except ProcessLookupError:
    return False
  except (PermissionError, OSError):
    return True
  return True


 # scan store ->
class ScanStore(Store):
  # lifecycle ->
  def _ensure_network(self, network_id: int | None, cidr: str | None, interface: str | None) -> None:
    """scans saved without network resolution (imports, tests) still belong to a real network row."""
    if network_id is None:
      return
    self.conn.execute(
      "INSERT OR IGNORE INTO networks (id, cidr, interface, created_at) VALUES (?, ?, ?, ?)",
      (network_id, cidr or "unknown", interface, ts(utcnow())),
    )

  def begin_scan(self, report: ScanReport) -> int:
    """register a running scan so it shows up (and can be told apart from a crash) before it ends."""
    with self.conn:
      self._ensure_network(report.network_id, report.network, report.interface)
      cursor = self.conn.execute(
        """INSERT INTO scans (started_at, status, network, network_id, target, interface, mode, trigger, profile_id,
                              ports_scanned, port_spec, rules_version, pid, heartbeat_at)
           VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
          ts(report.started_at),
          report.network,
          report.network_id,
          report.target or report.network,
          report.interface,
          str(report.mode),
          report.trigger,
          report.profile_id,
          int(report.ports_scanned),
          str(report.port_spec) or None,
          RULES_VERSION,
          os.getpid(),
          ts(utcnow()),
        ),
      )
      scan_id = int(cursor.lastrowid or 0)
      self._change("scan.started", "scan", str(scan_id), report.network_id, trigger=report.trigger)
    return scan_id

  def heartbeat_scan(self, scan_id: int, stage: str | None = None) -> None:
    with self.conn:
      self.conn.execute("UPDATE scans SET heartbeat_at = ? WHERE id = ?", (ts(utcnow()), scan_id))
      if stage:
        self._change("scan.progress", "scan", str(scan_id), None, stage=stage)

  def end_scan(
    self,
    scan_id: int | None,
    status: ScanStatus,
    issues: Iterable[ScanIssue] = (),
    stages: dict[str, float] | None = None,
    network: str | None = None,
    started_at: datetime | None = None,
    trigger: str = "cli",
    network_id: int | None = None,
  ) -> int:
    """close a scan that produced no inventory changes: failed, cancelled. creates the row when needed."""
    issues = list(issues)
    now = utcnow()
    with self.conn:
      self._ensure_network(network_id, network, None)
      if scan_id is None:
        cursor = self.conn.execute(
          "INSERT INTO scans (started_at, status, network, network_id, target, trigger, pid) VALUES (?, 'running', ?, ?, ?, ?, ?)",
          (ts(started_at or now), network, network_id, network, trigger, os.getpid()),
        )
        scan_id = int(cursor.lastrowid or 0)
      self.conn.execute(
        "UPDATE scans SET status = ?, finished_at = ?, issues = ?, stages = ?, heartbeat_at = ? WHERE id = ?",
        (str(status), ts(now), json.dumps([i.to_dict() for i in issues]), json.dumps(stages or {}), ts(now), scan_id),
      )
      self._change("scan.finished", "scan", str(scan_id), network_id, status=str(status))
    return scan_id

  def abort_stale_scans(self, older_than: timedelta = timedelta(minutes=10)) -> int:
    """scans left `running` by a process that died are marked aborted, so history never lies about them."""
    cutoff = utcnow() - older_than
    aborted = 0
    with self.conn:
      for row in self.conn.execute("SELECT id, pid, heartbeat_at FROM scans WHERE status = 'running'").fetchall():
        beat = dt(row["heartbeat_at"])
        if not _pid_alive(row["pid"]) or (beat is not None and beat < cutoff):
          self.conn.execute(
            "UPDATE scans SET status = 'aborted', finished_at = COALESCE(finished_at, heartbeat_at) WHERE id = ?", (row["id"],)
          )
          aborted += 1
    return aborted

  def save_scan(self, report: ScanReport, presence: bool = True, presence_gap: timedelta = SESSION_GAP) -> int:
    """persist a finished scan atomically: devices, ports, coverage, presence, offline transitions and events."""
    finished = report.finished_at or report.started_at
    with self.conn:
      self._ensure_network(report.network_id, report.network, report.interface)
      scan_id = report.scan_id
      if scan_id is None:
        cursor = self.conn.execute(
          "INSERT INTO scans (started_at, status, network, network_id, trigger, pid) VALUES (?, 'running', ?, ?, ?, ?)",
          (ts(report.started_at), report.network, report.network_id, report.trigger, os.getpid()),
        )
        scan_id = int(cursor.lastrowid or 0)
      self.conn.execute(
        """UPDATE scans SET finished_at = ?, status = ?, network = ?, network_id = ?, target = ?, interface = ?, mode = ?,
                            ports_scanned = ?, port_spec = ?, device_count = ?, event_count = ?, stages = ?, issues = ?,
                            unobserved = ?, first_result_ms = ?, rules_version = ?, heartbeat_at = ?
           WHERE id = ?""",
        (
          ts(finished),
          str(report.status if report.status != ScanStatus.RUNNING else ScanStatus.COMPLETE),
          report.network,
          report.network_id,
          report.target or report.network,
          report.interface,
          str(report.mode),
          int(report.ports_scanned),
          str(report.port_spec) or None,
          len(report.devices),
          len(report.events),
          json.dumps({k: round(v, 3) for k, v in report.stages.items()}),
          json.dumps([i.to_dict() for i in report.issues]),
          len(report.unobserved),
          int(report.first_result_after * 1000) if report.first_result_after is not None else None,
          RULES_VERSION,
          ts(finished),
          scan_id,
        ),
      )

      failed_hosts = {i.host for i in report.issues if i.host and i.stage == "ports"}
      for device in report.devices:
        self._upsert_device(device)
        self._save_ports(device.key, device.ports, finished)
        if report.port_spec and device.ip not in failed_hosts:
          self._add_coverage(scan_id, device, report.port_spec, finished, report.port_counts.get(device.key, {}))

      offline = [(e.device_key,) for e in report.events if e.type == EventType.DEVICE_OFFLINE and e.device_key]
      self.conn.executemany("UPDATE devices SET status = 'offline' WHERE key = ?", offline)
      if presence:
        self._record_sessions(report.devices, [key for (key,) in offline], finished, presence_gap)

      self.conn.executemany(
        """INSERT INTO events (scan_id, timestamp, type, severity, device_key, ip, mac, message, details, network_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
          (scan_id, ts(e.timestamp), str(e.type), str(e.severity), e.device_key, e.ip, e.mac, e.message, json.dumps(e.details), report.network_id)
          for e in report.events
        ],
      )
      self.conn.execute(
        "UPDATE networks SET last_scan_at = ?, interface = COALESCE(?, interface) WHERE id = ?",
        (ts(finished), report.interface, report.network_id),
      )
      self._record_measurements(scan_id, report.devices, finished)
      self._change(
        "scan.finished",
        "scan",
        str(scan_id),
        report.network_id,
        status=str(report.status),
        devices=len(report.devices),
        events=len(report.events),
      )
    return scan_id

  def _upsert_device(self, d: Device) -> None:
    self.conn.execute(
      """INSERT INTO devices (key, mac, ip, ips, hostname, hostname_source, vendor, randomized_mac, ttl, os_guess,
                              alias, trusted, status, is_local, is_gateway, latency, first_seen, last_seen, services,
                              network_id, ips6)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
           ips6 = CASE WHEN excluded.ips6 = '[]' THEN devices.ips6 ELSE excluded.ips6 END,
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
        ts(d.first_seen or d.last_seen),
        ts(d.last_seen),
        json.dumps(d.services),
        d.network_id,
        json.dumps(d.ips6),
      ),
    )

  def _save_ports(self, key: str, ports: list[PortInfo], seen_at: datetime) -> None:
    """upsert the known ports of a device; nothing is deleted, a closed port stays as history."""
    self.conn.executemany(
      """INSERT INTO ports (device_key, port, protocol, service, banner, first_seen, last_seen, state, last_probe,
                            checked_at, open_seen_at, protocol_observed, tls)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (device_key, port, protocol) DO UPDATE SET
           service = COALESCE(excluded.service, ports.service),
           banner = COALESCE(excluded.banner, ports.banner),
           last_seen = excluded.last_seen, state = excluded.state, last_probe = excluded.last_probe,
           checked_at = COALESCE(excluded.checked_at, ports.checked_at),
           open_seen_at = COALESCE(excluded.open_seen_at, ports.open_seen_at),
           protocol_observed = COALESCE(excluded.protocol_observed, ports.protocol_observed),
           tls = COALESCE(excluded.tls, ports.tls)""",
      [
        (
          key,
          p.port,
          p.protocol,
          p.service,
          p.banner,
          ts(p.first_seen or p.checked_at or seen_at),
          ts(seen_at),
          str(p.state),
          str(p.last_probe or p.state),
          ts(p.checked_at or seen_at),
          ts(p.open_seen_at or (seen_at if p.state == "open" else None)),
          p.protocol_observed,
          json.dumps(p.tls) if p.tls else None,
        )
        for p in ports
      ],
    )

  def _add_coverage(self, scan_id: int, device: Device, spec: PortSet, at: datetime, counts: dict[str, int]) -> None:
    self.conn.execute(
      """INSERT INTO port_coverage (scan_id, device_key, protocol, spec, checked_at, open_count, closed_count,
                                    filtered_count, error_count)
         VALUES (?, ?, 'tcp', ?, ?, ?, ?, ?, ?)""",
      (
        scan_id,
        device.key,
        str(spec),
        ts(at),
        counts.get("open", len(device.open_ports)),
        counts.get("closed"),
        counts.get("filtered"),
        counts.get("error"),
      ),
    )

  def _record_measurements(self, scan_id: int, devices: Iterable[Device], at: datetime) -> None:  # pragma: no cover
    """overridden by the measurement store; kept here so the scan transaction owns the write."""

  # coverage ->
  def port_coverage(self, keys: Iterable[str] | None = None) -> dict[str, tuple[PortSet | None, datetime]]:
    """per device: every port ever examined (`None` when a legacy scan's port set is unknown) and the last check."""
    query = "SELECT device_key, spec, checked_at FROM port_coverage"
    params: list[Any] = []
    if keys is not None:
      wanted = list(keys)
      if not wanted:
        return {}
      query += f" WHERE device_key IN ({placeholders(wanted)})"
      params = wanted
    specs: dict[str, list[str | None]] = {}
    latest: dict[str, datetime] = {}
    for row in self.conn.execute(query + " ORDER BY checked_at", params):
      specs.setdefault(row["device_key"], []).append(row["spec"])
      latest[row["device_key"]] = datetime.fromisoformat(row["checked_at"])
    result: dict[str, tuple[PortSet | None, datetime]] = {}
    for key, values in specs.items():
      known = [_parse_spec(v) for v in dict.fromkeys(v for v in values if v)]
      merged = PortSet([p for s in known for p in s]) if len(known) > 1 else (known[0] if known else None)
      if None in values and merged is None:
        result[key] = (None, latest[key])
      else:
        result[key] = (merged, latest[key])
    return result

  def coverage_history(self, key: str, limit: int = 20) -> list[dict[str, Any]]:
    rows = self.conn.execute(
      """SELECT c.*, s.status AS scan_status, s.trigger FROM port_coverage c LEFT JOIN scans s ON s.id = c.scan_id
         WHERE c.device_key = ? ORDER BY c.checked_at DESC LIMIT ?""",
      (key, limit),
    )
    return [
      {
        "scan_id": r["scan_id"],
        "checked_at": r["checked_at"],
        "spec": r["spec"],
        "ports": len(PortSet.parse(r["spec"])) if r["spec"] else None,
        "open": r["open_count"],
        "closed": r["closed_count"],
        "filtered": r["filtered_count"],
        "errors": r["error_count"],
        "legacy": r["spec"] is None,
      }
      for r in rows
    ]

  def ports_ever_scanned(self) -> bool:
    """false until a scan included ports: without it an empty port list means unknown, not closed."""
    return self.conn.execute("SELECT 1 FROM port_coverage LIMIT 1").fetchone() is not None

  # queries ->
  def _scan_row(self, row) -> dict[str, Any]:
    data = dict(row)
    data["stages"] = json.loads(row["stages"] or "{}")
    data["issues"] = json.loads(row["issues"] or "[]")
    return data

  def list_scans(
    self, limit: int = 20, offset: int = 0, network_id: int | None = None, status: str | None = None
  ) -> list[dict[str, Any]]:
    query = "SELECT * FROM scans WHERE 1 = 1"
    params: list[Any] = []
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    if status:
      query += " AND status = ?"
      params.append(status)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    return [self._scan_row(r) for r in self.conn.execute(query, params)]

  def count_scans(self, network_id: int | None = None, status: str | None = None) -> int:
    query = "SELECT COUNT(*) FROM scans WHERE 1 = 1"
    params: list[Any] = []
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    if status:
      query += " AND status = ?"
      params.append(status)
    return self.conn.execute(query, params).fetchone()[0]

  def get_scan(self, scan_id: int) -> dict[str, Any] | None:
    row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return self._scan_row(row) if row else None

  def last_valid_scan(self, network_id: int | None = None) -> dict[str, Any] | None:
    """the newest scan whose discovery can be trusted (complete or partial)."""
    query = "SELECT * FROM scans WHERE status IN ('complete', 'partial')"
    params: list[Any] = []
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    row = self.conn.execute(query + " ORDER BY id DESC LIMIT 1", params).fetchone()
    return self._scan_row(row) if row else None

  def observation_windows(
    self, since: datetime, gap: timedelta, network_id: int | None = None, until: datetime | None = None
  ) -> list[tuple[datetime, datetime]]:
    """periods the network was actually watched: valid scans no more than `gap` apart form one window.

    outside these windows nothing is known, which is different from "the device was away".
    """
    query = "SELECT finished_at FROM scans WHERE status IN ('complete', 'partial') AND finished_at >= ?"
    params: list[Any] = [ts(since - gap)]
    if until is not None:
      query += " AND finished_at <= ?"
      params.append(ts(until))
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    windows: list[tuple[datetime, datetime]] = []
    for row in self.conn.execute(query + " ORDER BY finished_at", params):
      moment = datetime.fromisoformat(row["finished_at"])
      if windows and moment - windows[-1][1] <= gap:
        windows[-1] = (windows[-1][0], moment)
      else:
        windows.append((moment, moment))
    return windows
