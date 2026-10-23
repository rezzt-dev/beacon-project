 # import libraries ->
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from beacon.core.engine import IpConflict
from beacon.core.events import Event, Severity
from beacon.core.models import Device, ScanMode


 # scan report ->
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
  ports_scanned: bool = False
  first_run: bool = False
  scan_id: int | None = None

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
      "network": self.network,
      "interface": self.interface,
      "local_ip": self.local_ip,
      "mode": str(self.mode),
      "started_at": self.started_at.isoformat(),
      "finished_at": self.finished_at.isoformat() if self.finished_at else None,
      "duration_seconds": round(self.duration, 2),
      "ports_scanned": self.ports_scanned,
      "discarded_observations": self.discarded,
      "devices": [d.to_dict() for d in self.devices],
      "events": [e.to_dict() for e in self.events],
    }
