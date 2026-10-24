 # import libraries ->
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import utcnow
from beacon.storage.base import Store, dt, placeholders, ts


 # constants ->
# events that ask for a decision from the user: informational ones never need review
PENDING_SEVERITIES = (str(Severity.ALERT), str(Severity.WARNING))


 # filters ->
@dataclass(slots=True)
class EventFilter:
  device_key: str | None = None
  device_keys: list[str] | None = None
  types: list[EventType] | None = None
  min_severity: Severity | None = None
  severities: list[Severity] | None = None
  pending_only: bool = False
  acked: bool | None = None
  network_id: int | None = None
  since: datetime | None = None
  until: datetime | None = None
  q: str | None = None
  scan_id: int | None = None
  before_id: int | None = None

  def where(self) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if self.device_key:
      clauses.append("device_key = ?")
      params.append(self.device_key)
    if self.device_keys is not None:
      clauses.append(f"device_key IN ({placeholders(self.device_keys) or 'NULL'})")
      params.extend(self.device_keys)
    if self.types:
      clauses.append(f"type IN ({placeholders(self.types)})")
      params.extend(str(t) for t in self.types)
    if self.min_severity:
      levels = list(Severity)[list(Severity).index(self.min_severity) :]
      clauses.append(f"severity IN ({placeholders(levels)})")
      params.extend(str(s) for s in levels)
    if self.severities:
      clauses.append(f"severity IN ({placeholders(self.severities)})")
      params.extend(str(s) for s in self.severities)
    if self.pending_only:
      clauses.append(f"acked_at IS NULL AND device_key IS NOT NULL AND severity IN ({placeholders(PENDING_SEVERITIES)})")
      params.extend(PENDING_SEVERITIES)
    if self.acked is not None:
      clauses.append("acked_at IS NOT NULL" if self.acked else "acked_at IS NULL")
    if self.network_id is not None:
      clauses.append("network_id = ?")
      params.append(self.network_id)
    if self.since is not None:
      clauses.append("timestamp >= ?")
      params.append(ts(self.since))
    if self.until is not None:
      clauses.append("timestamp < ?")
      params.append(ts(self.until))
    if self.scan_id is not None:
      clauses.append("scan_id = ?")
      params.append(self.scan_id)
    if self.before_id is not None:
      clauses.append("id < ?")
      params.append(self.before_id)
    if self.q:
      escaped = self.q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
      clauses.append("(LOWER(message) LIKE ? ESCAPE '\\' OR ip = ? OR mac = ?)")
      params.extend([f"%{escaped}%", self.q.strip(), self.q.strip().lower()])
    return (" AND ".join(clauses) or "1 = 1"), params


def row_to_event(row: sqlite3.Row) -> Event:
  return Event(
    type=EventType(row["type"]),
    severity=Severity(row["severity"]),
    message=row["message"],
    device_key=row["device_key"],
    ip=row["ip"],
    mac=row["mac"],
    details=json.loads(row["details"]),
    timestamp=datetime.fromisoformat(row["timestamp"]),
    id=row["id"],
    acked_at=dt(row["acked_at"]),
    network_id=row["network_id"],
    scan_id=row["scan_id"],
  )


 # event store ->
class EventStore(Store):
  def query_events(self, flt: EventFilter, limit: int = 50, offset: int = 0) -> list[Event]:
    """newest first; `limit=-1` returns every match. pagination by `before_id` is stable while events arrive."""
    where, params = flt.where()
    query = f"SELECT * FROM events WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?"
    return [row_to_event(row) for row in self.conn.execute(query, [*params, limit, offset])]

  def count_events(self, flt: EventFilter) -> int:
    where, params = flt.where()
    return self.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]

  def list_events(
    self,
    limit: int = 50,
    device_key: str | None = None,
    types: list[EventType] | None = None,
    min_severity: Severity | None = None,
    pending_only: bool = False,
    since: datetime | None = None,
    network_id: int | None = None,
  ) -> list[Event]:
    flt = EventFilter(
      device_key=device_key, types=types, min_severity=min_severity, pending_only=pending_only, since=since, network_id=network_id
    )
    return self.query_events(flt, limit)

  def get_event(self, event_id: int) -> Event | None:
    row = self.conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return row_to_event(row) if row else None

  def list_pending_events(self, network_id: int | None = None) -> list[Event]:
    """alerts and warnings tied to a device that nobody has reviewed yet, newest first."""
    return self.query_events(EventFilter(pending_only=True, network_id=network_id), limit=-1)

  def recent_port_openings(self, since: datetime, network_id: int | None = None, device_keys: list[str] | None = None) -> list[Event]:
    """the newest `port-opened` per device and port since `since`, first checks left out.

    the risk score only needs that much, so thousands of repeated events become one row each.
    """
    query = """SELECT e.*, ROW_NUMBER() OVER (
                 PARTITION BY device_key, json_extract(details, '$.port')
                 ORDER BY timestamp DESC, id DESC) AS rank
               FROM events e
               WHERE type = 'port-opened' AND timestamp >= ? AND device_key IS NOT NULL
                 AND COALESCE(json_extract(details, '$.first_check'), 0) = 0"""
    params: list[Any] = [ts(since)]
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    if device_keys is not None:
      if not device_keys:
        return []
      query += f" AND device_key IN ({placeholders(device_keys)})"
      params.extend(device_keys)
    return [row_to_event(r) for r in self.conn.execute(f"SELECT * FROM ({query}) WHERE rank = 1", params)]

  def port_change_counts(self, since: datetime, network_id: int | None = None) -> dict[tuple[str, int], int]:
    query = """SELECT type, json_extract(details, '$.port') AS port, COUNT(*) AS n
               FROM events WHERE type IN ('port-opened', 'port-closed') AND timestamp >= ?"""
    params: list[Any] = [ts(since)]
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    rows = self.conn.execute(query + " GROUP BY type, port", params)
    return {(r["type"], r["port"]): r["n"] for r in rows}

  def pending_by_device(self, network_id: int | None = None) -> dict[str, tuple[int, datetime]]:
    """per device with unreviewed alerts or warnings: how many and the newest one, in one grouped query."""
    query = (
      f"SELECT device_key, COUNT(*) AS n, MAX(timestamp) AS newest FROM events WHERE acked_at IS NULL AND device_key IS NOT NULL "
      f"AND severity IN ({placeholders(PENDING_SEVERITIES)})"
    )
    params: list[Any] = list(PENDING_SEVERITIES)
    if network_id is not None:
      query += " AND network_id = ?"
      params.append(network_id)
    rows = self.conn.execute(query + " GROUP BY device_key", params)
    return {r["device_key"]: (r["n"], datetime.fromisoformat(r["newest"])) for r in rows}

  def latest_pending(self, device_keys: list[str], per_device: int = 5) -> dict[str, list[Event]]:
    if not device_keys:
      return {}
    query = f"""SELECT * FROM (
                  SELECT e.*, ROW_NUMBER() OVER (PARTITION BY device_key ORDER BY id DESC) AS rank FROM events e
                  WHERE acked_at IS NULL AND severity IN ({placeholders(PENDING_SEVERITIES)}) AND device_key IN ({placeholders(device_keys)})
                ) WHERE rank <= ? ORDER BY id DESC"""
    found: dict[str, list[Event]] = {}
    for row in self.conn.execute(query, [*PENDING_SEVERITIES, *device_keys, per_device]):
      found.setdefault(row["device_key"], []).append(row_to_event(row))
    return found

  def count_pending_devices(self, network_id: int | None = None, now: datetime | None = None) -> int:
    """devices waiting for a review decision, leaving out the snoozed ones."""
    query = (
      "SELECT COUNT(DISTINCT e.device_key) FROM events e JOIN devices d ON d.key = e.device_key "
      "WHERE e.acked_at IS NULL AND e.severity IN ('alert', 'warning') AND (d.snoozed_until IS NULL OR d.snoozed_until <= ?)"
    )
    params: list[Any] = [ts(now or utcnow())]
    if network_id is not None:
      query += " AND d.network_id = ?"
      params.append(network_id)
    return self.conn.execute(query, params).fetchone()[0]

  def ack_events(self, device_key: str, actor: str = "cli") -> int:
    """mark every pending event of a device as reviewed; calling it again changes nothing."""
    with self.conn:
      return self._ack(device_key, actor)

  def ack_event(self, event_id: int, actor: str = "cli") -> bool:
    with self.conn:
      row = self.conn.execute("SELECT device_key, network_id FROM events WHERE id = ?", (event_id,)).fetchone()
      changed = self.conn.execute(
        "UPDATE events SET acked_at = ? WHERE id = ? AND acked_at IS NULL", (ts(utcnow()), event_id)
      ).rowcount > 0
      if changed and row is not None:
        self._audit(actor, "ack", "event", str(event_id), device=row["device_key"])
        self._change("event.acked", "event", str(event_id), row["network_id"], device=row["device_key"])
    return changed

  def _ack(self, device_key: str, actor: str = "cli") -> int:
    count = self.conn.execute(
      "UPDATE events SET acked_at = ? WHERE device_key = ? AND acked_at IS NULL", (ts(utcnow()), device_key)
    ).rowcount
    if count:
      self._audit(actor, "ack", "device-events", device_key, count=count)
      self._change("event.acked", "device", device_key, None, count=count)
    return count

  def has_event_since(self, device_key: str, kind: EventType, since: datetime) -> bool:
    row = self.conn.execute(
      "SELECT 1 FROM events WHERE device_key = ? AND type = ? AND timestamp >= ? LIMIT 1",
      (device_key, str(kind), ts(since)),
    ).fetchone()
    return row is not None

  def record_events(self, events: list[Event], scan_id: int | None = None, network_id: int | None = None) -> None:
    """events that do not come with a scan report (a failed scan, a passive sighting)."""
    with self.conn:
      self.conn.executemany(
        """INSERT INTO events (scan_id, timestamp, type, severity, device_key, ip, mac, message, details, network_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
          (scan_id, ts(e.timestamp), str(e.type), str(e.severity), e.device_key, e.ip, e.mac, e.message, json.dumps(e.details), network_id)
          for e in events
        ],
      )
      if events:
        self._change("event.created", None, None, network_id, count=len(events))

  def event_type_counts(self, flt: EventFilter) -> dict[str, int]:
    where, params = flt.where()
    rows = self.conn.execute(f"SELECT type, COUNT(*) AS n FROM events WHERE {where} GROUP BY type", params)
    return {r["type"]: r["n"] for r in rows}
