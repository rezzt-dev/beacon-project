 # import libraries ->
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import Device, utcnow


 # constants ->
# every weight and port list lives here so the model can be tuned without touching the logic
POINTS: dict[str, int] = {
  "untrusted": 30,
  "unknown_vendor": 10,
  "admin_port": 25,
  "extra_admin_port": 5,
  "cleartext_port": 10,
  "new_port": 15,
  "recent": 10,
  "ip_conflict": 40,
}
# most serious first: the first one found scores `admin_port`, the rest `extra_admin_port`
ADMIN_PORTS: dict[int, str] = {
  23: "telnet exposed (23)",
  3389: "remote desktop exposed (3389)",
  5900: "vnc exposed (5900)",
  445: "smb exposed (445)",
  139: "netbios session exposed (139)",
  5985: "winrm exposed (5985)",
  5986: "winrm exposed (5986)",
}
CLEARTEXT_PORTS: dict[int, str] = {22: "ssh", 21: "ftp", 554: "rtsp", 80: "unencrypted http"}
RECENT_WINDOW = timedelta(hours=24)
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


@dataclass(slots=True)
class RiskAssessment:
  score: int = 0
  reasons: list[RiskReason] = field(default_factory=list)
  ports_known: bool = True

  @property
  def level(self) -> RiskLevel:
    return RiskLevel.from_score(self.score)

  def to_dict(self) -> dict[str, Any]:
    return {
      "risk": self.score,
      "risk_level": str(self.level),
      "risk_reasons": [r.text for r in self.reasons],
      "ports_scanned": self.ports_known,
    }


def assess(
  device: Device,
  events: Iterable[Event] = (),
  ports_known: bool = True,
  now: datetime | None = None,
) -> RiskAssessment:
  """explainable 0-100 risk score from what beacon already knows about a device. pure: no io.

  `events` are the recent events of the network (new open ports and ip conflicts are read
  from them). `ports_known` is false when no scan ever included ports, so an empty port list
  means "unknown" and not "closed". the local host and the gateway are exempt.
  """
  result = RiskAssessment(ports_known=ports_known)
  if device.is_local or device.is_gateway:
    return result

  def add(text: str, points: int) -> None:
    result.reasons.append(RiskReason(text, points))

  if not device.trusted:
    add("not trusted", POINTS["untrusted"])
  if not device.vendor and not device.randomized_mac:
    add("unknown vendor", POINTS["unknown_vendor"])

  open_ports = {p.port for p in device.open_ports}
  admin = [port for port in ADMIN_PORTS if port in open_ports]
  for index, port in enumerate(admin):
    add(ADMIN_PORTS[port], POINTS["admin_port"] if index == 0 else POINTS["extra_admin_port"])
  if cleartext := [port for port in CLEARTEXT_PORTS if port in open_ports]:
    add(f"{CLEARTEXT_PORTS[cleartext[0]]} open ({cleartext[0]})", POINTS["cleartext_port"])

  for event in events:
    if event.type == EventType.PORT_OPENED and event.device_key == device.key:
      add(f"new open port {event.details.get('port', '?')} since the baseline", POINTS["new_port"])
      break
  if any(e.type == EventType.IP_CONFLICT and device.mac in e.details.get("macs", ()) for e in events if device.mac):
    add("involved in an ip conflict", POINTS["ip_conflict"])

  now = now or utcnow()
  if device.first_seen is None or now - device.first_seen < RECENT_WINDOW:
    add("first seen in the last 24 h", POINTS["recent"])

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
