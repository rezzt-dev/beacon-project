 # import libraries ->
import json
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from beacon.core.models import utcnow
from beacon.storage.base import NotFoundError, Store, dt, ts


 # retention ->
@dataclass(slots=True)
class RetentionPolicy:
  """how long each kind of history is kept. `None` keeps it forever."""

  events_days: int | None = 365
  sessions_days: int | None = 180
  measurements_days: int | None = 90
  scans_days: int | None = 180
  audit_days: int | None = 730
  changes_days: int | None = 7

  def to_dict(self) -> dict[str, int | None]:
    return {
      "events_days": self.events_days,
      "sessions_days": self.sessions_days,
      "measurements_days": self.measurements_days,
      "scans_days": self.scans_days,
      "audit_days": self.audit_days,
      "changes_days": self.changes_days,
    }

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "RetentionPolicy":
    policy = cls()
    for name in policy.to_dict():
      if name in data:
        value = data[name]
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 36500):
          raise ValueError(f"{name} must be a number of days between 1 and 36500, or null")
        setattr(policy, name, value)
    return policy


def owner_id() -> str:
  return f"{socket.gethostname()}:{os.getpid()}"


 # admin store ->
class AdminStore(Store):
  # networks ->
  def resolve_network(
    self,
    cidr: str,
    interface: str | None = None,
    gateway_ip: str | None = None,
    gateway_mac: str | None = None,
    create: bool = True,
  ) -> int | None:
    """the network a scan belongs to. the same range behind another router is another network.

    a known gateway mac tells two `192.168.1.0/24` apart; without one, the range alone decides.
    with `create=False` (dry runs) nothing is written and an unknown network is `None`.
    """
    with self.conn:
      rows = self.conn.execute("SELECT * FROM networks WHERE cidr = ? ORDER BY last_scan_at DESC", (cidr,)).fetchall()
      if gateway_mac:
        exact = next((r for r in rows if r["gateway_mac"] == gateway_mac), None)
        if exact is not None:
          return exact["id"]
        unknown = next((r for r in rows if r["gateway_mac"] is None), None)
        if unknown is not None:
          if not create:
            return unknown["id"]
          self.conn.execute("UPDATE networks SET gateway_mac = ?, gateway_ip = ? WHERE id = ?", (gateway_mac, gateway_ip, unknown["id"]))
          return unknown["id"]
      elif rows:
        return rows[0]["id"]
      if not create:
        return None
      cursor = self.conn.execute(
        "INSERT INTO networks (cidr, interface, gateway_ip, gateway_mac, created_at) VALUES (?, ?, ?, ?, ?)",
        (cidr, interface, gateway_ip, gateway_mac, ts(utcnow())),
      )
      network_id = int(cursor.lastrowid or 0)
      self._change("network.created", "network", str(network_id), network_id, cidr=cidr)
      return network_id

  def list_networks(self) -> list[dict[str, Any]]:
    rows = self.conn.execute(
      """SELECT n.*, COUNT(d.key) AS devices, COALESCE(SUM(d.status = 'online'), 0) AS online
         FROM networks n LEFT JOIN devices d ON d.network_id = n.id GROUP BY n.id ORDER BY n.id"""
    )
    return [dict(r) for r in rows]

  def get_network(self, network_id: int) -> dict[str, Any] | None:
    row = self.conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone()
    return dict(row) if row else None

  def rename_network(self, network_id: int, name: str | None, actor: str = "cli") -> None:
    with self.conn:
      if not self.conn.execute("UPDATE networks SET name = ? WHERE id = ?", ((name or "").strip() or None, network_id)).rowcount:
        raise NotFoundError(f"network {network_id} not found")
      self._audit(actor, "rename", "network", str(network_id), name=name)
      self._change("network.updated", "network", str(network_id), network_id)

  # scan leases ->
  def acquire_lease(self, scope: str, kind: str, ttl: timedelta, owner: str | None = None) -> dict[str, Any] | None:
    """take (or renew) the scanning lease of a scope. returns `None` on success, else the current holder.

    one atomic upsert: two processes racing for an expired lease cannot both win.
    """
    owner = owner or owner_id()
    now = utcnow()
    with self.conn:
      self.conn.execute(
        """INSERT INTO leases (scope, owner, kind, pid, acquired_at, heartbeat_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (scope) DO UPDATE SET owner = excluded.owner, kind = excluded.kind, pid = excluded.pid,
             acquired_at = CASE WHEN leases.owner = excluded.owner THEN leases.acquired_at ELSE excluded.acquired_at END,
             heartbeat_at = excluded.heartbeat_at, expires_at = excluded.expires_at
           WHERE leases.owner = excluded.owner OR leases.expires_at < excluded.heartbeat_at""",
        (scope, owner, kind, os.getpid(), ts(now), ts(now), ts(now + ttl)),
      )
      row = self.conn.execute("SELECT * FROM leases WHERE scope = ?", (scope,)).fetchone()
    return None if row["owner"] == owner else dict(row)

  def release_lease(self, scope: str, owner: str | None = None) -> None:
    with self.conn:
      self.conn.execute("DELETE FROM leases WHERE scope = ? AND owner = ?", (scope, owner or owner_id()))

  def list_leases(self) -> list[dict[str, Any]]:
    now = ts(utcnow())
    return [{**dict(r), "active": r["expires_at"] >= now} for r in self.conn.execute("SELECT * FROM leases ORDER BY scope")]

  # settings ->
  def get_setting(self, key: str, default: Any = None) -> Any:
    row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default

  def set_setting(self, key: str, value: Any, actor: str = "cli") -> None:
    with self.conn:
      self.conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, json.dumps(value), ts(utcnow())),
      )
      self._audit(actor, "set", "setting", key)
      self._change("settings.updated", "setting", key, None)

  def all_settings(self) -> dict[str, Any]:
    return {r["key"]: json.loads(r["value"]) for r in self.conn.execute("SELECT key, value FROM settings")}

  # change feed ->
  def changes_since(self, after_id: int, limit: int = 200) -> list[dict[str, Any]]:
    rows = self.conn.execute("SELECT * FROM changes WHERE id > ? ORDER BY id LIMIT ?", (after_id, limit))
    return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

  def change_bounds(self) -> tuple[int, int]:
    """`(oldest, newest)` change ids still stored; `(0, 0)` when the feed is empty."""
    row = self.conn.execute("SELECT COALESCE(MIN(id), 0) AS low, COALESCE(MAX(id), 0) AS high FROM changes").fetchone()
    if row["high"] == 0:
      seq = self.conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'changes'").fetchone()
      return (seq[0] if seq else 0), (seq[0] if seq else 0)
    return row["low"], row["high"]

  # audit ->
  def record_audit(self, actor: str, action: str, entity: str, entity_id: str | None, **details: Any) -> None:
    with self.conn:
      self._audit(actor, action, entity, entity_id, **details)

  def list_audit(self, entity: str | None = None, entity_id: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    query = "SELECT * FROM audit WHERE 1 = 1"
    params: list[Any] = []
    if entity:
      query += " AND entity = ?"
      params.append(entity)
    if entity_id:
      query += " AND entity_id = ?"
      params.append(entity_id)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    return [{**dict(r), "details": json.loads(r["details"])} for r in self.conn.execute(query, params)]

  # retention ->
  def retention_preview(self, policy: RetentionPolicy, now: datetime | None = None) -> dict[str, int]:
    """how many rows each rule would delete, without deleting anything."""
    return self._retention(policy, now, apply=False)

  def apply_retention(self, policy: RetentionPolicy, actor: str = "cli", now: datetime | None = None) -> dict[str, int]:
    """delete expired history in one transaction. pending (unreviewed) events and open sessions are always kept,
    and the newest port coverage of each device survives so exposure never becomes "unknown" by accident."""
    counts = self._retention(policy, now, apply=True, actor=actor)
    return counts

  def _retention(self, policy: RetentionPolicy, now: datetime | None, apply: bool, actor: str = "cli") -> dict[str, int]:
    now = now or utcnow()

    def cutoff(days: int | None) -> str | None:
      return ts(now - timedelta(days=days)) if days else None

    rules: list[tuple[str, str | None, str]] = [
      (
        "events",
        cutoff(policy.events_days),
        "FROM events WHERE timestamp < :cut AND NOT (acked_at IS NULL AND device_key IS NOT NULL AND severity IN ('alert', 'warning'))",
      ),
      ("sessions", cutoff(policy.sessions_days), "FROM sessions WHERE ended_at IS NOT NULL AND ended_at < :cut"),
      ("measurements", cutoff(policy.measurements_days), "FROM measurements WHERE at < :cut"),
      (
        "port_coverage",
        cutoff(policy.scans_days),
        "FROM port_coverage WHERE checked_at < :cut AND id NOT IN (SELECT MAX(id) FROM port_coverage GROUP BY device_key)",
      ),
      ("scans", cutoff(policy.scans_days), "FROM scans WHERE COALESCE(finished_at, started_at) < :cut AND status != 'running' AND id NOT IN (SELECT DISTINCT scan_id FROM port_coverage WHERE scan_id IS NOT NULL)"),
      ("audit", cutoff(policy.audit_days), "FROM audit WHERE at < :cut"),
      ("deliveries", cutoff(policy.audit_days), "FROM deliveries WHERE created_at < :cut AND status != 'pending'"),
      ("changes", cutoff(policy.changes_days), "FROM changes WHERE at < :cut AND id < (SELECT MAX(id) FROM changes)"),
    ]
    counts: dict[str, int] = {}
    tables = {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    with self.conn:
      for name, cut, body in rules:
        table = body.split()[1]
        if cut is None or table not in tables:
          counts[name] = 0
          continue
        if apply:
          counts[name] = self.conn.execute(f"DELETE {body}", {"cut": cut}).rowcount
        else:
          counts[name] = self.conn.execute(f"SELECT COUNT(*) {body}", {"cut": cut}).fetchone()[0]
      if apply:
        self._audit(actor, "retention", "database", None, deleted=counts, policy=policy.to_dict())
        self._change("retention.applied", None, None, None, deleted=sum(counts.values()))
    return counts

  # stats ->
  def stats(self, network_id: int | None = None) -> dict[str, Any]:
    scope = "" if network_id is None else " WHERE network_id = ?"
    params: tuple[Any, ...] = () if network_id is None else (network_id,)
    row = self.conn.execute(
      f"""SELECT COUNT(*) AS total,
                COALESCE(SUM(status = 'online'), 0) AS online,
                COALESCE(SUM(trusted = 1), 0) AS trusted,
                COALESCE(SUM(randomized_mac = 1), 0) AS randomized
         FROM devices{scope}""",
      params,
    ).fetchone()
    valid = "WHERE status IN ('complete', 'partial')" + ("" if network_id is None else " AND network_id = ?")
    last = self.conn.execute(
      f"SELECT finished_at, network, status FROM scans {valid} ORDER BY id DESC LIMIT 1", params
    ).fetchone()
    return {
      **dict(row),
      "untrusted": row["total"] - row["trusted"],
      "scans": self.conn.execute(f"SELECT COUNT(*) FROM scans{scope}", params).fetchone()[0],
      "last_scan": dict(last) if last else None,
    }

  def table_sizes(self) -> dict[str, int]:
    names = [r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
    return {name: self.conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] for name in sorted(names)}

  def last_activity(self) -> datetime | None:
    row = self.conn.execute("SELECT MAX(heartbeat_at) AS beat FROM scans").fetchone()
    return dt(row["beat"])
