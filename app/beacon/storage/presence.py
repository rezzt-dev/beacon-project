 # import libraries ->
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from beacon.core.models import Device
from beacon.core.presence import Session
from beacon.storage.base import Store, dt, placeholders, ts


 # presence store ->
class PresenceStore(Store):
  def _record_sessions(
    self, devices: Iterable[Device], offline_keys: list[str], finished: datetime, gap: timedelta
  ) -> None:
    """extend the open session of every present device, start one when there is none and close the ones that went offline."""
    open_sessions = {
      row["device_key"]: (row["id"], dt(row["last_seen"]))
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
        self.conn.execute("UPDATE sessions SET last_seen = MAX(last_seen, ?) WHERE id = ?", (ts(seen), current[0]))
      else:
        self.conn.execute(
          "INSERT INTO sessions (device_key, started_at, last_seen) VALUES (?, ?, ?)", (device.key, ts(seen), ts(seen))
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
      params.append(ts(since))
    if device_keys is not None:
      keys = list(device_keys)
      if not keys:
        return {}
      query += f" AND device_key IN ({placeholders(keys)})"
      params.extend(keys)
    query += " ORDER BY started_at"
    sessions: dict[str, list[Session]] = {}
    for row in self.conn.execute(query, params):
      sessions.setdefault(row["device_key"], []).append(
        Session(
          device_key=row["device_key"],
          started_at=datetime.fromisoformat(row["started_at"]),
          last_seen=datetime.fromisoformat(row["last_seen"]),
          ended_at=dt(row["ended_at"]),
        )
      )
    return sessions

  def sessions_by_identity(self, devices: Iterable[Device], since: datetime | None = None) -> dict[str, list[Session]]:
    """sessions per device, pooling the macs of a linked identity so a rotating address keeps one history."""
    everyone = list(devices)
    ids = sorted({d.identity_id for d in everyone if d.identity_id is not None})
    members: dict[int, list[str]] = {}
    if ids:
      for row in self.conn.execute(f"SELECT key, identity_id FROM devices WHERE identity_id IN ({placeholders(ids)})", ids):
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
    return row["total"], dt(row["oldest"])

  def prune_sessions(self, before: datetime) -> int:
    """delete sessions that ended before `before`; open ones are never touched."""
    with self.conn:
      return self.conn.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?", (ts(before),)).rowcount
