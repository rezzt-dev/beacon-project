 # import libraries ->
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from beacon.core.events import Event
from beacon.core.models import Device
from beacon.core.risk import RiskAssessment
from beacon.services.serialize import device_summary, event_dict
from beacon.storage import Repository


 # review cases ->
class ReviewAction(StrEnum):
  TRUST = "t"
  TRUST_ALIAS = "a"
  IGNORE = "i"
  FORGET = "f"
  SKIP = "s"
  QUIT = "q"


@dataclass(slots=True)
class ReviewCase:
  """a device with events nobody has looked at yet, and why it matters."""

  device: Device
  risk: RiskAssessment
  events: list[Event]
  snoozed_until: datetime | None = None
  pending: int = 0

  def to_dict(self) -> dict[str, Any]:
    return {
      "device": device_summary(self.device, self.risk, self.snoozed_until),
      "events": [event_dict(e) for e in self.events],
      "pending": self.pending or len(self.events),
      "snoozed_until": self.snoozed_until.isoformat() if self.snoozed_until else None,
    }


def review_page(
  repo: Repository,
  network_id: int | None = None,
  include_snoozed: bool = False,
  page: int = 1,
  size: int = 20,
  per_case: int = 5,
  now: datetime | None = None,
) -> tuple[list[ReviewCase], int]:
  """one page of devices waiting for a decision, riskiest first, with their latest pending events.

  counting is one grouped query and risk comes from the shared (cached) assessment, so a queue of
  thousands of devices costs as much as one page of it.
  """
  from beacon.services.inventory import DeviceQuery, _match

  counts = repo.pending_by_device(network_id)
  snoozed = repo.snoozed(now)
  if not include_snoozed:
    counts = {k: v for k, v in counts.items() if k not in snoozed}
  if not counts:
    return [], 0
  devices, risks = _match(repo, DeviceQuery(network_id=network_id, size=1), now)
  waiting = [d for d in devices if d.key in counts]
  waiting.sort(key=lambda d: (-risks[d.key].score, -counts[d.key][1].timestamp(), d.ip))
  chosen = waiting[(page - 1) * size : page * size]
  events = repo.latest_pending([d.key for d in chosen], per_case)
  cases = [ReviewCase(d, risks[d.key], events.get(d.key, []), snoozed.get(d.key), counts[d.key][0]) for d in chosen]
  return cases, len(waiting)


def pending_cases(
  repo: Repository, network_id: int | None = None, include_snoozed: bool = False, now: datetime | None = None
) -> list[ReviewCase]:
  """every device waiting for a decision (the cli walks through all of them)."""
  cases, _total = review_page(repo, network_id, include_snoozed, 1, 1_000_000, per_case=50, now=now)
  return cases


def apply_action(repo: Repository, device: Device, action: ReviewAction, alias: str | None = None, actor: str = "cli") -> str:
  """carry out one decision on exactly one device and say what happened. an empty alias is a plain trust."""
  if action == ReviewAction.TRUST_ALIAS:
    if name := (alias or "").strip():
      repo.set_alias(device.key, name, actor)
    action = ReviewAction.TRUST
  if action == ReviewAction.TRUST:
    repo.set_trusted(device.key, True, actor)
    return "trusted"
  if action == ReviewAction.IGNORE:
    repo.ack_events(device.key, actor)
    return "ignored"
  if action == ReviewAction.FORGET:
    repo.delete_device(device.key, actor)
    return "forgotten"
  return "skipped"
