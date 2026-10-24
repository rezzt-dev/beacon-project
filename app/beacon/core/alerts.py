 # import libraries ->
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import Device


 # policies ->
@dataclass(slots=True)
class Policy:
  """when a group of events deserves a notification. pure data; evaluation lives below."""

  id: int
  name: str
  enabled: bool = True
  network_id: int | None = None
  event_types: list[str] = field(default_factory=list)
  min_severity: Severity = Severity.WARNING
  device_filter: dict[str, Any] = field(default_factory=dict)
  min_risk: int | None = None
  window_seconds: int = 0
  threshold: int = 1
  cooldown_seconds: int = 900
  channels: list[int] = field(default_factory=list)
  last_fired_at: datetime | None = None


@dataclass(slots=True)
class Silence:
  """a maintenance window or a mute: matching events are kept, only their notification is held back."""

  id: int
  starts_at: datetime
  ends_at: datetime
  network_id: int | None = None
  device_key: str | None = None
  event_types: list[str] = field(default_factory=list)
  reason: str | None = None

  def active(self, now: datetime) -> bool:
    return self.starts_at <= now < self.ends_at

  def covers(self, event: Event, network_id: int | None) -> bool:
    if self.network_id is not None and self.network_id != network_id:
      return False
    if self.device_key is not None and self.device_key != event.device_key:
      return False
    return not self.event_types or str(event.type) in self.event_types


@dataclass(slots=True)
class Decision:
  """the outcome of evaluating one policy: notify these events, or why not."""

  policy: Policy
  events: list[Event]
  notify: bool
  reason: str
  silenced: int = 0


 # evaluation ->
_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ALERT: 2}


def matches(policy: Policy, event: Event, network_id: int | None, device: Device | None, risk: int | None) -> bool:
  if policy.network_id is not None and policy.network_id != network_id:
    return False
  if policy.event_types and str(event.type) not in policy.event_types:
    return False
  if _SEVERITY_RANK[event.severity] < _SEVERITY_RANK[Severity(policy.min_severity)]:
    return False
  flt = policy.device_filter
  if flt:
    if device is None:
      return False
    if "trusted" in flt and flt["trusted"] is not None and device.trusted != flt["trusted"]:
      return False
    if flt.get("essential") and not device.essential:
      return False
    if flt.get("tag") and flt["tag"] not in device.tags:
      return False
  return not (policy.min_risk is not None and (risk is None or risk < policy.min_risk))


def evaluate(
  policies: Iterable[Policy],
  events: Sequence[Event],
  network_id: int | None,
  now: datetime,
  devices: Mapping[str, Device],
  risks: Mapping[str, int],
  silences: Iterable[Silence] = (),
  recent_counts: Mapping[int, int] | None = None,
) -> list[Decision]:
  """decide, per enabled policy, whether the new events trigger a notification. pure: no io.

  - silences hold back matching events (maintenance windows included) without deleting anything.
  - `threshold` events within `window_seconds` are needed (`recent_counts` brings the ones already
    stored before this batch); a single event is enough with the defaults.
  - `cooldown_seconds` after a notification, the same policy only records, it does not notify again.
  """
  active = [s for s in silences if s.active(now)]
  decisions: list[Decision] = []
  for policy in policies:
    if not policy.enabled:
      continue
    hits = [
      e for e in events
      if e.type not in (EventType.SCAN_PARTIAL,)
      and matches(policy, e, network_id, devices.get(e.device_key or ""), risks.get(e.device_key or ""))
    ]
    if not hits:
      continue
    kept = [e for e in hits if not any(s.covers(e, network_id) for s in active)]
    silenced = len(hits) - len(kept)
    if not kept:
      decisions.append(Decision(policy, [], False, "silenced", silenced))
      continue
    seen = len(kept) + (recent_counts or {}).get(policy.id, 0)
    if seen < policy.threshold:
      decisions.append(Decision(policy, kept, False, f"{seen} of {policy.threshold} events in the window", silenced))
      continue
    if policy.last_fired_at is not None and now - policy.last_fired_at < timedelta(seconds=policy.cooldown_seconds):
      decisions.append(Decision(policy, kept, False, "cooling down", silenced))
      continue
    decisions.append(Decision(policy, kept, True, "notify", silenced))
  return decisions


def summary(decision: Decision, device_names: Mapping[str, str]) -> dict[str, Any]:
  """the minimal payload a channel receives: what happened, where, how serious. no presence, no fingerprints."""
  events = decision.events
  worst = max((e.severity for e in events), key=lambda s: _SEVERITY_RANK[s])
  return {
    "policy": decision.policy.name,
    "severity": str(worst),
    "count": len(events),
    "title": f"beacon: {len(events)} {'event' if len(events) == 1 else 'events'} · {decision.policy.name}",
    "events": [
      {
        "type": str(e.type),
        "severity": str(e.severity),
        "message": e.message[:300],
        "device": device_names.get(e.device_key or "") if e.device_key else None,
        "ip": e.ip,
        "at": e.timestamp.isoformat(),
      }
      for e in events[:20]
    ],
  }
