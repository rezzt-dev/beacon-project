 # import libraries ->
import json
import sqlite3
from datetime import datetime
from typing import Any

from beacon.core.models import utcnow
from beacon.storage.database import Database


 # helpers ->
def ts(value: datetime | None) -> str | None:
  return value.isoformat() if value else None


def dt(value: str | None) -> datetime | None:
  return datetime.fromisoformat(value) if value else None


def placeholders(values: list[Any] | tuple[Any, ...]) -> str:
  return ",".join("?" * len(values))


class ConflictError(RuntimeError):
  """an edit was based on an older version of the record (optimistic concurrency)."""

  def __init__(self, entity: str, entity_id: str, current: int) -> None:
    super().__init__(f"{entity} {entity_id} changed since it was read (now version {current})")
    self.entity = entity
    self.entity_id = entity_id
    self.current = current


class NotFoundError(LookupError):
  pass


 # base store ->
class Store:
  """shared plumbing of the repository parts: the connection, the change feed and the audit trail.

  callers own the transaction: helpers prefixed with `_` never commit on their own.
  """

  def __init__(self, db: Database) -> None:
    self.db = db

  @property
  def conn(self) -> sqlite3.Connection:
    return self.db.conn

  def _change(
    self,
    kind: str,
    entity: str | None = None,
    entity_id: str | None = None,
    network_id: int | None = None,
    **data: Any,
  ) -> None:
    """append to the monotonic change feed that live clients follow (and resume from)."""
    self.conn.execute(
      "INSERT INTO changes (at, kind, entity, entity_id, network_id, data) VALUES (?, ?, ?, ?, ?, ?)",
      (ts(utcnow()), kind, entity, entity_id, network_id, json.dumps(data, default=str)),
    )

  def _audit(self, actor: str, action: str, entity: str, entity_id: str | None, **details: Any) -> None:
    self.conn.execute(
      "INSERT INTO audit (at, actor, action, entity, entity_id, details) VALUES (?, ?, ?, ?, ?, ?)",
      (ts(utcnow()), actor, action, entity, entity_id, json.dumps(details, default=str)),
    )
