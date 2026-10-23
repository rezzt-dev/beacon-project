 # import libraries ->
import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


 # helpers ->
def utcnow() -> datetime:
  return datetime.now(UTC).replace(microsecond=0)


 # enums ->
class DiscoverySource(StrEnum):
  ARP_SWEEP = "arp-sweep"
  ARP_TABLE = "arp-table"
  ICMP = "icmp"
  TCP = "tcp"
  LOCAL = "local"


class ScanMode(StrEnum):
  AUTO = "auto"
  PRIVILEGED = "privileged"
  UNPRIVILEGED = "unprivileged"


class DeviceStatus(StrEnum):
  ONLINE = "online"
  OFFLINE = "offline"


class PortState(StrEnum):
  OPEN = "open"
  CLOSED = "closed"
  FILTERED = "filtered"


 # raw scanner output ->
@dataclass(frozen=True, slots=True)
class Observation:
  """a single raw sighting produced by a scanner, before any cleaning."""

  ip: str
  source: DiscoverySource
  mac: str | None = None
  ttl: int | None = None
  rtt_ms: float | None = None
  fresh: bool = True


 # enrichment data ->
@dataclass(slots=True)
class Latency:
  method: str
  sent: int
  samples: list[float] = field(default_factory=list)

  @property
  def received(self) -> int:
    return len(self.samples)

  @property
  def loss(self) -> float:
    return 0.0 if self.sent == 0 else round(100 * (self.sent - self.received) / self.sent, 1)

  @property
  def avg(self) -> float | None:
    return round(statistics.fmean(self.samples), 2) if self.samples else None

  @property
  def min(self) -> float | None:
    return round(min(self.samples), 2) if self.samples else None

  @property
  def max(self) -> float | None:
    return round(max(self.samples), 2) if self.samples else None

  @property
  def jitter(self) -> float | None:
    """mean absolute difference between consecutive samples (rfc 3550 style, unsmoothed)."""
    if len(self.samples) < 2:
      return None
    deltas = [abs(b - a) for a, b in zip(self.samples, self.samples[1:], strict=False)]
    return round(statistics.fmean(deltas), 2)

  def to_dict(self) -> dict[str, Any]:
    return {
      "method": self.method,
      "sent": self.sent,
      "received": self.received,
      "loss": self.loss,
      "avg": self.avg,
      "min": self.min,
      "max": self.max,
      "jitter": self.jitter,
      "samples": [round(s, 3) for s in self.samples],
    }

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "Latency":
    return cls(method=data["method"], sent=data["sent"], samples=list(data.get("samples", [])))


@dataclass(slots=True)
class PortInfo:
  port: int
  state: PortState
  protocol: str = "tcp"
  service: str | None = None
  banner: str | None = None
  rtt_ms: float | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "port": self.port,
      "protocol": self.protocol,
      "state": str(self.state),
      "service": self.service,
      "banner": self.banner,
    }


 # device ->
@dataclass(slots=True)
class Device:
  """a cleaned, merged view of one host. identity is the mac; the ip may change."""

  ip: str
  mac: str | None = None
  ips: list[str] = field(default_factory=list)
  hostname: str | None = None
  hostname_source: str | None = None
  vendor: str | None = None
  randomized_mac: bool = False
  ttl: int | None = None
  os_guess: str | None = None
  ports: list[PortInfo] = field(default_factory=list)
  latency: Latency | None = None
  sources: set[str] = field(default_factory=set)
  is_local: bool = False
  is_gateway: bool = False
  alias: str | None = None
  trusted: bool = False
  status: DeviceStatus = DeviceStatus.ONLINE
  first_seen: datetime | None = None
  last_seen: datetime | None = None

  @property
  def key(self) -> str:
    return self.mac or f"ip:{self.ip}"

  @property
  def open_ports(self) -> list[PortInfo]:
    return sorted((p for p in self.ports if p.state == PortState.OPEN), key=lambda p: p.port)

  @property
  def display_name(self) -> str:
    return self.alias or self.hostname or self.ip

  @property
  def display_vendor(self) -> str:
    if self.vendor:
      return self.vendor
    if self.randomized_mac:
      return "randomized (private mac)"
    return "unknown"

  def to_dict(self) -> dict[str, Any]:
    return {
      "key": self.key,
      "ip": self.ip,
      "ips": self.ips,
      "mac": self.mac,
      "hostname": self.hostname,
      "hostname_source": self.hostname_source,
      "vendor": self.vendor,
      "randomized_mac": self.randomized_mac,
      "ttl": self.ttl,
      "os_guess": self.os_guess,
      "alias": self.alias,
      "trusted": self.trusted,
      "status": str(self.status),
      "is_local": self.is_local,
      "is_gateway": self.is_gateway,
      "first_seen": self.first_seen.isoformat() if self.first_seen else None,
      "last_seen": self.last_seen.isoformat() if self.last_seen else None,
      "latency": self.latency.to_dict() if self.latency else None,
      "open_ports": [p.to_dict() for p in self.open_ports],
      "sources": sorted(self.sources),
    }
