 # import libraries ->
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from beacon.core.models import utcnow


log = logging.getLogger(__name__)


 # enums ->
class EventType(StrEnum):
  NEW_DEVICE = "new-device"
  DEVICE_ONLINE = "device-online"
  DEVICE_OFFLINE = "device-offline"
  IP_CHANGED = "ip-changed"
  PORT_OPENED = "port-opened"
  PORT_CLOSED = "port-closed"
  IP_CONFLICT = "ip-conflict"


class Severity(StrEnum):
  INFO = "info"
  WARNING = "warning"
  ALERT = "alert"


 # event ->
@dataclass(frozen=True, slots=True)
class Event:
  type: EventType
  severity: Severity
  message: str
  device_key: str | None = None
  ip: str | None = None
  mac: str | None = None
  details: dict[str, Any] = field(default_factory=dict)
  timestamp: datetime = field(default_factory=utcnow)

  def to_dict(self) -> dict[str, Any]:
    return {
      "type": str(self.type),
      "severity": str(self.severity),
      "message": self.message,
      "device_key": self.device_key,
      "ip": self.ip,
      "mac": self.mac,
      "details": self.details,
      "timestamp": self.timestamp.isoformat(),
    }


 # event bus ->
Subscriber = Callable[[Event], None]


class EventBus:
  """minimal synchronous pub/sub: ui, exporters and storage react to the same events."""

  def __init__(self) -> None:
    self._subscribers: list[Subscriber] = []

  def subscribe(self, callback: Subscriber) -> Callable[[], None]:
    self._subscribers.append(callback)
    return lambda: self._subscribers.remove(callback)

  def publish(self, event: Event) -> None:
    for callback in list(self._subscribers):
      try:
        callback(event)
      except Exception:  # a broken subscriber must never stop a scan
        log.exception("event subscriber failed for %s", event.type)

  def publish_many(self, events: Iterable[Event]) -> None:
    for event in events:
      self.publish(event)
