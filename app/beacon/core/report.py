 # import libraries ->
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from beacon.core.engine import IpConflict
from beacon.core.events import Event, Severity
from beacon.core.models import DEFAULT_NETWORK_ID, Device, ScanMode
from beacon.core.ports import PortSet


 # enums ->
class ScanStatus(StrEnum):
  """how much of the scan can be trusted. only a complete discovery may mark devices offline."""

  RUNNING = "running"
  COMPLETE = "complete"
  PARTIAL = "partial"  # discovery finished but some hosts or stages failed
  FAILED = "failed"  # nothing usable: interface gone, permission error...
  CANCELLED = "cancelled"
  ABORTED = "aborted"  # the process died while scanning (found on the next start)


 # scan report ->
@dataclass(frozen=True, slots=True)
class ScanIssue:
  stage: str
  message: str
  host: str | None = None

  def to_dict(self) -> dict[str, Any]:
    return {"stage": self.stage, "message": self.message, "host": self.host}


@dataclass(slots=True)
class ScanReport:
  network: str
  mode: ScanMode
  started_at: datetime
  interface: str | None = None
  local_ip: str | None = None
  finished_at: datetime | None = None
  devices: list[Device] = field(default_factory=list)
  events: list[Event] = field(default_factory=list)
  conflicts: list[IpConflict] = field(default_factory=list)
  discarded: int = 0
  port_spec: PortSet = field(default_factory=PortSet)
  first_run: bool = False
  scan_id: int | None = None
  network_id: int = DEFAULT_NETWORK_ID
  target: str | None = None
  status: ScanStatus = ScanStatus.COMPLETE
  issues: list[ScanIssue] = field(default_factory=list)
  # seconds per stage, in the order they ran
  stages: dict[str, float] = field(default_factory=dict)
  trigger: str = "cli"
  profile_id: int | None = None
  # addresses discovery could not probe (send failures): their absence proves nothing
  unobserved: set[str] = field(default_factory=set)
  # seconds from the start until the first device was known
  first_result_after: float | None = None
  # probe outcomes per device key: {"open": n, "closed": n, "filtered": n, "error": n}
  port_counts: dict[str, dict[str, int]] = field(default_factory=dict)

  @property
  def ports_scanned(self) -> bool:
    return bool(self.port_spec)

  @property
  def duration(self) -> float:
    if self.finished_at is None:
      return 0.0
    return (self.finished_at - self.started_at).total_seconds()

  @property
  def alerts(self) -> list[Event]:
    return [e for e in self.events if e.severity == Severity.ALERT]

  def to_dict(self) -> dict[str, Any]:
    return {
      "scan_id": self.scan_id,
      "status": str(self.status),
      "network": self.network,
      "network_id": self.network_id,
      "target": self.target or self.network,
      "interface": self.interface,
      "local_ip": self.local_ip,
      "mode": str(self.mode),
      "started_at": self.started_at.isoformat(),
      "finished_at": self.finished_at.isoformat() if self.finished_at else None,
      "duration_seconds": round(self.duration, 2),
      "ports_scanned": self.ports_scanned,
      "port_spec": str(self.port_spec) or None,
      "stages": {name: round(value, 3) for name, value in self.stages.items()},
      "issues": [i.to_dict() for i in self.issues],
      "discarded_observations": self.discarded,
      "devices": [d.to_dict() for d in self.devices],
      "events": [e.to_dict() for e in self.events],
    }
