 # import libraries ->
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.exposure import Basis, Exposure, profile_for
from beacon.core.models import Device, PortInfo, utcnow


 # constants ->
# bump it whenever a weight, a window or a rule changes: stored assessments say which rules made them
RULES_VERSION = "2"
# every weight and window lives here so the model can be tuned without touching the logic
POINTS: dict[str, int] = {
  "untrusted": 30,
  "unknown_vendor": 10,
  "admin_plaintext": 25,
  "admin_encrypted": 10,
  "database": 20,
  "file_sharing": 15,
  "extra_exposure": 5,
  "plaintext_service": 10,
  "new_port": 15,
  "recent": 10,
  "ip_conflict": 40,
}
RECENT_WINDOW = timedelta(hours=24)
NEW_PORT_WINDOW = timedelta(days=7)
CONFLICT_WINDOW = timedelta(hours=24)
# port data older than this is still shown, but the assessment says it may be outdated
STALE_PORTS = timedelta(days=7)
MAX_SCORE = 100
_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")


 # enums ->
class RiskLevel(StrEnum):
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"

  @property
  def rank(self) -> int:
    return list(RiskLevel).index(self)

  @classmethod
  def from_score(cls, score: int) -> "RiskLevel":
    return cls.HIGH if score >= 55 else cls.MEDIUM if score >= 25 else cls.LOW


 # assessment ->
@dataclass(frozen=True, slots=True)
class RiskReason:
  text: str
  points: int
  code: str = ""
  basis: Basis = Basis.CONTEXT
  at: datetime | None = None
  port: int | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "code": self.code,
      "text": self.text,
      "points": self.points,
      "basis": str(self.basis),
      "at": self.at.isoformat() if self.at else None,
      "port": self.port,
    }


@dataclass(slots=True)
class RiskAssessment:
  score: int = 0
  reasons: list[RiskReason] = field(default_factory=list)
  ports_known: bool = True
  # limits of what the score could see: never examined ports, outdated data...
  notes: list[str] = field(default_factory=list)
  ports_checked_at: datetime | None = None
  rules_version: str = RULES_VERSION

  @property
  def level(self) -> RiskLevel:
    return RiskLevel.from_score(self.score)

  @property
  def complete(self) -> bool:
    """false when exposure could not be judged: a low score then means "unknown", never "safe"."""
    return self.ports_known

  @property
  def label(self) -> str:
    return str(self.level) if self.complete else f"{self.level} · incomplete"

  def to_dict(self) -> dict[str, Any]:
    return {
      "risk": self.score,
      "risk_level": str(self.level),
      "risk_complete": self.complete,
      "risk_reasons": [r.text for r in self.reasons],
      "risk_details": [r.to_dict() for r in self.reasons],
      "risk_notes": list(self.notes),
      "risk_rules": self.rules_version,
      "ports_scanned": self.ports_known,
      "ports_checked_at": self.ports_checked_at.isoformat() if self.ports_checked_at else None,
    }


def _exposure_findings(ports: Sequence[PortInfo]) -> list[RiskReason]:
  """one reason per exposed service, most serious first; plaintext services count once."""
  serious: list[RiskReason] = []
  plaintext: list[RiskReason] = []
  for port in sorted(ports, key=lambda p: p.port):
    profile, basis = profile_for(port)
    if profile is None:
      continue
    how = "seen in the banner" if basis == Basis.OBSERVED else "inferred from the port number"
    at = port.open_seen_at or port.checked_at
    if profile.exposure == Exposure.REMOTE_ADMIN:
      if profile.encrypted:
        text = f"remote administration exposed: {profile.service} on {port.port} (encrypted, {how})"
        serious.append(RiskReason(text, POINTS["admin_encrypted"], "admin-encrypted", basis, at, port.port))
      else:
        crypto = "unencrypted" if profile.encrypted is False else "encryption depends on its configuration"
        text = f"remote administration exposed: {profile.service} on {port.port} ({crypto}, {how})"
        serious.append(RiskReason(text, POINTS["admin_plaintext"], "admin-plaintext", basis, at, port.port))
    elif profile.exposure == Exposure.DATABASE:
      text = f"database reachable: {profile.service} on {port.port} ({how})"
      serious.append(RiskReason(text, POINTS["database"], "database", basis, at, port.port))
    elif profile.exposure == Exposure.FILE_SHARING:
      text = f"file sharing exposed: {profile.service} on {port.port} ({how})"
      serious.append(RiskReason(text, POINTS["file_sharing"], "file-sharing", basis, at, port.port))
    elif profile.encrypted is False:
      text = f"unencrypted service: {profile.service} on {port.port} ({how})"
      plaintext.append(RiskReason(text, POINTS["plaintext_service"], "plaintext", basis, at, port.port))

  serious.sort(key=lambda r: (-r.points, r.port or 0))
  found = [
    r if index == 0 else RiskReason(r.text, POINTS["extra_exposure"], r.code, r.basis, r.at, r.port)
    for index, r in enumerate(serious)
  ]
  return found + plaintext[:1]


def assess(
  device: Device,
  events: Iterable[Event] = (),
  ports_known: bool = True,
  now: datetime | None = None,
  ports_checked_at: datetime | None = None,
) -> RiskAssessment:
  """explainable 0-100 risk score from what beacon already knows about a device. pure: no io.

  `events` are recent events of the network; only those inside each rule's window count, and
  reviewing (acknowledging) them does not hide the evidence. `ports_known` is false when this
  device's ports were never examined, so no open port means "unknown" and not "closed".
  the local host and the gateway are assessed like any other device: their role changes the
  starting trust, not what is exposed on them.
  """
  now = now or utcnow()
  result = RiskAssessment(ports_known=ports_known, ports_checked_at=ports_checked_at)

  def add(text: str, points: int, code: str, basis: Basis = Basis.CONTEXT, at: datetime | None = None) -> None:
    result.reasons.append(RiskReason(text, points, code, basis, at))

  if not device.trusted:
    add("not trusted", POINTS["untrusted"], "untrusted")
  if not device.vendor and not device.randomized_mac and device.mac:
    add("unknown vendor", POINTS["unknown_vendor"], "unknown-vendor", Basis.INFERRED)

  open_ports = device.open_ports
  result.reasons.extend(_exposure_findings(open_ports))
  open_now = {p.port for p in open_ports}

  events = list(events)
  for event in sorted(events, key=lambda e: e.timestamp, reverse=True):
    if (
      event.type == EventType.PORT_OPENED
      and event.device_key == device.key
      and not event.details.get("first_check")
      and now - event.timestamp <= NEW_PORT_WINDOW
      and event.details.get("port") in open_now
    ):
      reviewed = " (reviewed)" if event.acked_at else ""
      # one opening per port is enough evidence; events come newest first
      add(
        f"port {event.details.get('port')} opened on {event.timestamp:%Y-%m-%d}{reviewed}",
        POINTS["new_port"],
        "new-port",
        Basis.HISTORY,
        event.timestamp,
      )
      break
  if device.mac:
    conflict = next(
      (
        e
        for e in events
        if e.type == EventType.IP_CONFLICT and device.mac in e.details.get("macs", ()) and now - e.timestamp <= CONFLICT_WINDOW
      ),
      None,
    )
    if conflict is not None:
      add(f"involved in an ip conflict on {conflict.timestamp:%Y-%m-%d %H:%M} utc", POINTS["ip_conflict"], "ip-conflict", Basis.OBSERVED, conflict.timestamp)

  if not device.is_local and (device.first_seen is None or now - device.first_seen < RECENT_WINDOW):
    add("first seen in the last 24 h", POINTS["recent"], "recent", Basis.HISTORY, device.first_seen)

  if not ports_known:
    result.notes.append("ports were never examined on this device: exposure is unknown, not absent")
  elif ports_checked_at is not None and now - ports_checked_at > STALE_PORTS:
    result.notes.append(f"port data is from {ports_checked_at:%Y-%m-%d}: it may be outdated")
  if any(p.last_probe is not None and p.last_probe != p.state for p in open_ports):
    result.notes.append("some open ports did not answer the last probe: kept as open until a refusal confirms they closed")

  result.score = min(MAX_SCORE, sum(r.points for r in result.reasons))
  return result


def events_at_risk(
  devices: Sequence[Device], events: Sequence[Event], threshold: int, ports_known: bool = True
) -> list[Event]:
  """warnings and alerts that affect a device whose risk score reaches `threshold`."""
  by_key = {d.key: d for d in devices}
  cache: dict[str, RiskAssessment] = {}
  found: list[Event] = []
  for event in events:
    device = by_key.get(event.device_key or "")
    if device is None or event.severity == Severity.INFO:
      continue
    if device.key not in cache:
      cache[device.key] = assess(device, events, ports_known)
    if cache[device.key].score >= threshold:
      found.append(event)
  return found


 # aliases ->
def suggest_alias(device: Device) -> str:
  """a readable alias: the host part of the hostname, or `vendor-<last octet>`."""
  if device.hostname:
    return device.hostname.split(".")[0]
  last_octet = device.ip.rsplit(".", 1)[-1]
  vendor = _NON_ALPHANUMERIC.sub("-", (device.vendor or "").lower().split(" ")[0]).strip("-")
  return f"{vendor or 'device'}-{last_octet}"
