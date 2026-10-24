 # import libraries ->
import json
from datetime import datetime
from typing import Any

from beacon.core.alerts import Policy, Silence
from beacon.core.events import Severity
from beacon.core.models import utcnow
from beacon.storage.base import ConflictError, NotFoundError, Store, dt, ts


 # constants ->
POLICY_FIELDS = (
  "name", "enabled", "network_id", "event_types", "min_severity", "device_filter", "min_risk",
  "window_seconds", "threshold", "cooldown_seconds", "channels",
)
_JSON = {"event_types", "device_filter", "channels"}


 # alert store ->
class AlertStore(Store):
  # policies ->
  @staticmethod
  def _policy_row(row) -> dict[str, Any]:
    data = dict(row)
    for key in _JSON:
      data[key] = json.loads(data[key])
    data["enabled"] = bool(data["enabled"])
    return data

  def list_policies(self) -> list[dict[str, Any]]:
    return [self._policy_row(r) for r in self.conn.execute("SELECT * FROM alert_policies ORDER BY name")]

  def get_policy(self, policy_id: int) -> dict[str, Any] | None:
    row = self.conn.execute("SELECT * FROM alert_policies WHERE id = ?", (policy_id,)).fetchone()
    return self._policy_row(row) if row else None

  def policies(self) -> list[Policy]:
    return [
      Policy(
        id=p["id"], name=p["name"], enabled=p["enabled"], network_id=p["network_id"], event_types=p["event_types"],
        min_severity=Severity(p["min_severity"]), device_filter=p["device_filter"], min_risk=p["min_risk"],
        window_seconds=p["window_seconds"], threshold=p["threshold"], cooldown_seconds=p["cooldown_seconds"],
        channels=p["channels"], last_fired_at=dt(p["last_fired_at"]),
      )
      for p in self.list_policies()
    ]

  def _encode(self, values: dict[str, Any]) -> dict[str, Any]:
    data = {k: v for k, v in values.items() if k in POLICY_FIELDS}
    for key in _JSON & data.keys():
      data[key] = json.dumps(data[key])
    if "enabled" in data:
      data["enabled"] = int(data["enabled"])
    return data

  def create_policy(self, values: dict[str, Any], actor: str = "cli") -> dict[str, Any]:
    data = self._encode(values)
    now = ts(utcnow())
    with self.conn:
      columns = ", ".join(data)
      cursor = self.conn.execute(
        f"INSERT INTO alert_policies ({columns}, created_at, updated_at) VALUES ({', '.join('?' * len(data))}, ?, ?)",
        (*data.values(), now, now),
      )
      policy_id = int(cursor.lastrowid or 0)
      self._audit(actor, "create", "policy", str(policy_id), name=values.get("name"))
      self._change("policy.created", "policy", str(policy_id), None)
    created = self.get_policy(policy_id)
    assert created is not None
    return created

  def update_policy(self, policy_id: int, values: dict[str, Any], expected_version: int | None, actor: str = "cli") -> dict[str, Any]:
    data = self._encode(values)
    with self.conn:
      row = self.conn.execute("SELECT version FROM alert_policies WHERE id = ?", (policy_id,)).fetchone()
      if row is None:
        raise NotFoundError(f"policy {policy_id} not found")
      if expected_version is not None and row["version"] != expected_version:
        raise ConflictError("policy", str(policy_id), row["version"])
      if data:
        assignments = ", ".join(f"{k} = ?" for k in data)
        self.conn.execute(
          f"UPDATE alert_policies SET {assignments}, version = version + 1, updated_at = ? WHERE id = ?",
          (*data.values(), ts(utcnow()), policy_id),
        )
        self._audit(actor, "edit", "policy", str(policy_id), fields=sorted(data))
        self._change("policy.updated", "policy", str(policy_id), None)
    updated = self.get_policy(policy_id)
    assert updated is not None
    return updated

  def delete_policy(self, policy_id: int, actor: str = "cli") -> bool:
    with self.conn:
      deleted = self.conn.execute("DELETE FROM alert_policies WHERE id = ?", (policy_id,)).rowcount > 0
      if deleted:
        self._audit(actor, "delete", "policy", str(policy_id))
        self._change("policy.deleted", "policy", str(policy_id), None)
    return deleted

  def mark_fired(self, policy_id: int, at: datetime) -> None:
    with self.conn:
      self.conn.execute("UPDATE alert_policies SET last_fired_at = ? WHERE id = ?", (ts(at), policy_id))

  # silences ->
  def list_silences(self, include_expired: bool = False, now: datetime | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM silences"
    params: list[Any] = []
    if not include_expired:
      query += " WHERE ends_at > ?"
      params.append(ts(now or utcnow()))
    return [{**dict(r), "event_types": json.loads(r["event_types"])} for r in self.conn.execute(query + " ORDER BY starts_at", params)]

  def silences(self, now: datetime | None = None) -> list[Silence]:
    return [
      Silence(
        id=s["id"], starts_at=datetime.fromisoformat(s["starts_at"]), ends_at=datetime.fromisoformat(s["ends_at"]),
        network_id=s["network_id"], device_key=s["device_key"], event_types=s["event_types"], reason=s["reason"],
      )
      for s in self.list_silences(now=now)
    ]

  def create_silence(self, values: dict[str, Any], actor: str = "cli") -> dict[str, Any]:
    with self.conn:
      cursor = self.conn.execute(
        """INSERT INTO silences (reason, network_id, device_key, event_types, starts_at, ends_at, created_at, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
          values.get("reason"), values.get("network_id"), values.get("device_key"), json.dumps(values.get("event_types") or []),
          ts(values["starts_at"]), ts(values["ends_at"]), ts(utcnow()), actor,
        ),
      )
      silence_id = int(cursor.lastrowid or 0)
      self._audit(actor, "create", "silence", str(silence_id), reason=values.get("reason"))
      self._change("silence.created", "silence", str(silence_id), values.get("network_id"))
    return next(s for s in self.list_silences(include_expired=True) if s["id"] == silence_id)

  def delete_silence(self, silence_id: int, actor: str = "cli") -> bool:
    with self.conn:
      deleted = self.conn.execute("DELETE FROM silences WHERE id = ?", (silence_id,)).rowcount > 0
      if deleted:
        self._audit(actor, "delete", "silence", str(silence_id))
        self._change("silence.deleted", "silence", str(silence_id), None)
    return deleted

  # channels ->
  @staticmethod
  def _channel_row(row, with_secret: bool = False) -> dict[str, Any]:
    data = {**dict(row), "config": json.loads(row["config"]), "enabled": bool(row["enabled"]), "has_secret": bool(row["secret"])}
    if not with_secret:
      data.pop("secret")
    return data

  def list_channels(self) -> list[dict[str, Any]]:
    """channels without their secrets: those never leave the database through the api or exports."""
    return [self._channel_row(r) for r in self.conn.execute("SELECT * FROM channels ORDER BY id")]

  def get_channel(self, channel_id: int, with_secret: bool = False) -> dict[str, Any] | None:
    row = self.conn.execute("SELECT * FROM channels WHERE id = ?", (channel_id,)).fetchone()
    return self._channel_row(row, with_secret) if row else None

  def create_channel(self, kind: str, name: str, config: dict[str, Any], secret: str | None, actor: str = "cli") -> dict[str, Any]:
    with self.conn:
      cursor = self.conn.execute(
        "INSERT INTO channels (kind, name, config, secret, created_at) VALUES (?, ?, ?, ?, ?)",
        (kind, name, json.dumps(config), secret, ts(utcnow())),
      )
      channel_id = int(cursor.lastrowid or 0)
      self._audit(actor, "create", "channel", str(channel_id), kind=kind)
      self._change("channel.created", "channel", str(channel_id), None)
    created = self.get_channel(channel_id)
    assert created is not None
    return created

  def update_channel(self, channel_id: int, values: dict[str, Any], actor: str = "cli") -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if "name" in values:
      fields["name"] = values["name"]
    if "config" in values:
      fields["config"] = json.dumps(values["config"])
    if "enabled" in values:
      fields["enabled"] = int(values["enabled"])
    if "secret" in values:
      fields["secret"] = values["secret"]
    with self.conn:
      if fields:
        changed = self.conn.execute(
          f"UPDATE channels SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?", (*fields.values(), channel_id)
        ).rowcount
        if not changed:
          raise NotFoundError(f"channel {channel_id} not found")
        self._audit(actor, "edit", "channel", str(channel_id), fields=sorted(k for k in fields if k != "secret"))
        self._change("channel.updated", "channel", str(channel_id), None)
    updated = self.get_channel(channel_id)
    if updated is None:
      raise NotFoundError(f"channel {channel_id} not found")
    return updated

  def delete_channel(self, channel_id: int, actor: str = "cli") -> bool:
    with self.conn:
      deleted = self.conn.execute("DELETE FROM channels WHERE id = ?", (channel_id,)).rowcount > 0
      if deleted:
        self._audit(actor, "delete", "channel", str(channel_id))
        self._change("channel.deleted", "channel", str(channel_id), None)
    return deleted

  # deliveries ->
  def enqueue_delivery(self, key: str, policy_id: int | None, channel_id: int, payload: dict[str, Any], now: datetime | None = None) -> bool:
    """queue one notification; the same idempotency key is only ever queued once."""
    with self.conn:
      inserted = self.conn.execute(
        """INSERT OR IGNORE INTO deliveries (idempotency_key, policy_id, channel_id, created_at, status, next_attempt_at, payload)
           VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
        (key, policy_id, channel_id, ts(now or utcnow()), ts(now or utcnow()), json.dumps(payload)),
      ).rowcount > 0
      if inserted:
        self._change("delivery.queued", "channel", str(channel_id), None)
    return inserted

  def due_deliveries(self, now: datetime | None = None, limit: int = 20) -> list[dict[str, Any]]:
    rows = self.conn.execute(
      "SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY id LIMIT ?", (ts(now or utcnow()), limit)
    )
    return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]

  def finish_delivery(self, delivery_id: int, status: str, attempts: int, next_attempt_at: datetime | None, error: str | None) -> None:
    with self.conn:
      self.conn.execute(
        "UPDATE deliveries SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ? WHERE id = ?",
        (status, attempts, ts(next_attempt_at), error, delivery_id),
      )
      self._change("delivery.updated", "delivery", str(delivery_id), None, status=status)

  def list_deliveries(self, limit: int = 50) -> list[dict[str, Any]]:
    rows = self.conn.execute(
      """SELECT d.id, d.idempotency_key, d.policy_id, d.channel_id, d.created_at, d.status, d.attempts, d.next_attempt_at,
                d.last_error, d.payload, c.name AS channel, c.kind, p.name AS policy
         FROM deliveries d LEFT JOIN channels c ON c.id = d.channel_id LEFT JOIN alert_policies p ON p.id = d.policy_id
         ORDER BY d.id DESC LIMIT ?""",
      (limit,),
    )
    return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]
