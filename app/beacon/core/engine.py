 # import libraries ->
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address, IPv4Network

from beacon.core.mac import is_randomized, is_valid_unicast, normalize_mac
from beacon.core.models import Device, DiscoverySource, Observation
from beacon.core.osguess import guess_os
from beacon.core.vendors import VendorDatabase


 # constants ->
# lower value wins when choosing the primary ip of a device
SOURCE_PRIORITY: dict[DiscoverySource, int] = {
  DiscoverySource.LOCAL: 0,
  DiscoverySource.ARP_SWEEP: 1,
  DiscoverySource.ARP_TABLE: 2,
  DiscoverySource.ICMP: 3,
  DiscoverySource.TCP: 4,
}
MAX_BANNER_LENGTH = 160
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_WHITESPACE = re.compile(r"\s+")
_HOSTNAME = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")


 # results ->
@dataclass(frozen=True, slots=True)
class IpConflict:
  """one ip answered from several macs in the same scan: misconfiguration or arp spoofing."""

  ip: str
  macs: tuple[str, ...]


@dataclass(slots=True)
class MergeResult:
  devices: dict[str, Device] = field(default_factory=dict)
  conflicts: list[IpConflict] = field(default_factory=list)
  discarded: int = 0


 # text cleaning ->
def clean_hostname(name: str | None, ip: str | None = None) -> str | None:
  """normalize a resolved name and drop values that carry no information."""
  if not name:
    return None
  value = _CONTROL_CHARS.sub("", name).strip().rstrip(".").lower()
  if not value or value == ip or value.endswith(".in-addr.arpa") or value.endswith(".ip6.arpa"):
    return None
  try:
    IPv4Address(value)
    return None
  except ValueError:
    pass
  return value if _HOSTNAME.match(value) else None


def clean_banner(data: bytes | str | None) -> str | None:
  """turn raw service bytes into a single printable line."""
  if not data:
    return None
  text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
  text = text.replace("�", "")
  first = next((line for line in text.splitlines() if line.strip()), "")
  first = _WHITESPACE.sub(" ", _CONTROL_CHARS.sub("", first)).strip()
  if not first:
    return None
  return first if len(first) <= MAX_BANNER_LENGTH else first[: MAX_BANNER_LENGTH - 1] + "…"


 # cleaning engine ->
class CleaningEngine:
  """turns raw, noisy observations from every scanner into one device per real host.

  - normalizes macs and merges by mac (an ip can change, the mac does not).
  - drops invalid, broadcast, multicast and out-of-network addresses.
  - drops stale arp cache entries that nothing else confirmed during the scan.
  - flags randomized (locally administered) macs instead of reporting an unknown vendor.
  - detects ips claimed by several macs.
  """

  def __init__(self, vendors: VendorDatabase | None = None, network: IPv4Network | None = None) -> None:
    self.vendors = vendors or VendorDatabase()
    self.network = network

  def clean_ip(self, value: str) -> str | None:
    try:
      addr = IPv4Address(value.strip())
    except ValueError:
      return None
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback or addr.is_reserved:
      return None
    if self.network is not None:
      if addr not in self.network:
        return None
      edges = (self.network.network_address, self.network.broadcast_address)
      if self.network.prefixlen < 31 and addr in edges:
        return None
    return str(addr)

  def merge(self, observations: Iterable[Observation]) -> MergeResult:
    result = MergeResult()
    cleaned: list[Observation] = []

    for obs in observations:
      ip = self.clean_ip(obs.ip)
      if ip is None:
        result.discarded += 1
        continue
      mac = normalize_mac(obs.mac)
      if obs.mac is not None and not is_valid_unicast(mac):
        # incomplete or broadcast arp entries carry no identity at all
        if obs.source in (DiscoverySource.ARP_TABLE, DiscoverySource.ARP_SWEEP):
          result.discarded += 1
          continue
        mac = None
      cleaned.append(replace(obs, ip=ip, mac=mac))

    confirmed_ips = {obs.ip for obs in cleaned if obs.fresh}
    by_mac: dict[str, list[Observation]] = defaultdict(list)
    ip_only: list[Observation] = []
    for obs in cleaned:
      if not obs.fresh and obs.ip not in confirmed_ips:
        result.discarded += 1
        continue
      if obs.mac:
        by_mac[obs.mac].append(obs)
      else:
        ip_only.append(obs)

    owners: dict[str, set[str]] = defaultdict(set)
    for mac, group in by_mac.items():
      device = self._build(mac, group)
      result.devices[mac] = device
      for ip in device.ips:
        owners[ip].add(mac)

    for obs in ip_only:
      macs = owners.get(obs.ip)
      if macs and len(macs) > 1:
        continue
      if macs:
        device = result.devices[next(iter(macs))]
      else:
        device = result.devices.setdefault(f"ip:{obs.ip}", Device(ip=obs.ip, ips=[obs.ip]))
      self._absorb(device, obs)

    result.conflicts = [
      IpConflict(ip=ip, macs=tuple(sorted(macs))) for ip, macs in sorted(owners.items()) if len(macs) > 1
    ]
    return result

  def _build(self, mac: str, group: list[Observation]) -> Device:
    ordered = sorted(group, key=lambda o: SOURCE_PRIORITY.get(o.source, 99))
    primary = ordered[0].ip
    ips = [primary, *sorted({o.ip for o in group} - {primary}, key=IPv4Address)]
    device = Device(ip=primary, mac=mac, ips=ips, randomized_mac=is_randomized(mac))
    device.vendor = self.vendors.lookup(mac)
    for obs in group:
      self._absorb(device, obs)
    return device

  @staticmethod
  def _absorb(device: Device, obs: Observation) -> None:
    device.sources.add(str(obs.source))
    if obs.source == DiscoverySource.LOCAL:
      device.is_local = True
    apply_ttl(device, obs.ttl)


 # enrichment helpers ->
def apply_ttl(device: Device, ttl: int | None) -> None:
  """keep the highest ttl seen (closest to the initial value) and refresh the os estimate."""
  if ttl is not None and (device.ttl is None or ttl > device.ttl):
    device.ttl = ttl
    device.os_guess = guess_os(ttl)
