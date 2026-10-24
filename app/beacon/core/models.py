 # import libraries ->
import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


 # helpers ->
# the first network an inventory knew keeps the historical, unscoped device keys
DEFAULT_NETWORK_ID = 1


def utcnow() -> datetime:
  return datetime.now(UTC).replace(microsecond=0)


def _iso(value: datetime | None) -> str | None:
  return value.isoformat() if value else None


def scoped_key(network_id: int, base: str) -> str:
  """device key inside a network. two networks may reuse the same private range (and a locally
  administered mac), so every network but the first prefixes its keys with `n<id>:`."""
  return base if network_id == DEFAULT_NETWORK_ID else f"n{network_id}:{base}"


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
  """what one probe learned about a port. "not examined" is not a state: it is a port outside the scan's port set."""

  OPEN = "open"
  CLOSED = "closed"  # the host refused the connection: a confirmed close
  FILTERED = "filtered"  # no answer before the timeout: unknown, never a confirmed close
  ERROR = "error"  # the probe itself failed (no route, no buffer): says nothing about the port


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
  """a port of a device: its current state plus when and how it was last measured.

  `service` is inferred from the port number; `protocol_observed` is what the banner proved.
  """

  port: int
  state: PortState
  protocol: str = "tcp"
  service: str | None = None
  banner: str | None = None
  rtt_ms: float | None = None
  protocol_observed: str | None = None
  last_probe: PortState | None = None
  checked_at: datetime | None = None
  open_seen_at: datetime | None = None
  first_seen: datetime | None = None
  tls: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "port": self.port,
      "protocol": self.protocol,
      "state": str(self.state),
      "service": self.service,
      "protocol_observed": self.protocol_observed,
      "banner": self.banner,
      "last_probe": str(self.last_probe) if self.last_probe else None,
      "checked_at": _iso(self.checked_at),
      "open_seen_at": _iso(self.open_seen_at),
      "first_seen": _iso(self.first_seen),
      "tls": self.tls,
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
  services: list[str] = field(default_factory=list)
  identity_id: int | None = None
  network_id: int = DEFAULT_NETWORK_ID
  ips6: list[str] = field(default_factory=list)
  category: str | None = None
  tags: list[str] = field(default_factory=list)
  notes: str | None = None
  owner: str | None = None
  essential: bool = False
  version: int = 0

  @property
  def key(self) -> str:
    return scoped_key(self.network_id, self.mac or f"ip:{self.ip}")

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

  def to_dict(self, fingerprint: bool = False) -> dict[str, Any]:
    """serialize the device; `services` is part of the identity fingerprint and only included on request."""
    data = {
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
      "identity_id": self.identity_id,
      "network_id": self.network_id,
      "ips6": self.ips6,
      "category": self.category,
      "tags": self.tags,
      "owner": self.owner,
      "essential": self.essential,
    }
    if fingerprint:
      data["services"] = list(self.services)
    return data
