 # import libraries ->
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from beacon.core.models import Device


 # constants ->
# weights and thresholds are a starting hypothesis: calibrate them with real captures of several phones
WEIGHT_HOSTNAME = 0.55
WEIGHT_SERVICES = 0.25
WEIGHT_PORTS = 0.10
WEIGHT_TTL = 0.05
WEIGHT_NETWORK = 0.05
PROBABLE_THRESHOLD = 0.80
POSSIBLE_THRESHOLD = 0.50
# the best candidate must beat the runner-up by this much, otherwise the link is ambiguous
AMBIGUITY_MARGIN = 0.15
# names shared by countless devices say nothing about which one this is
GENERIC_HOSTNAMES = frozenset(
  {"android", "localhost", "iphone", "ipad", "ipod", "unknown", "host", "phone", "mobile", "galaxy", "pixel", "oneplus", "lwip"}
)
_COPY_SUFFIX = re.compile(r"(?:-\d{1,2}|\(\d{1,2}\))$")
_EPSILON = 1e-9


 # enums ->
class LinkLevel(StrEnum):
  PROBABLE = "probable"
  POSSIBLE = "possible"


 # fingerprint ->
@dataclass(frozen=True, slots=True)
class Fingerprint:
  hostname: str | None
  services: frozenset[str]
  ports: frozenset[int]
  ttl_family: int | None
  network: str | None


def normalize_hostname(name: str | None) -> str | None:
  """lowercase host part without `.local`-style domains and `-2` / `(2)` duplicate suffixes."""
  if not name:
    return None
  host = _COPY_SUFFIX.sub("", name.strip().lower().split(".")[0])
  return host if host and host not in GENERIC_HOSTNAMES else None


def ttl_family(ttl: int | None) -> int | None:
  """initial ttl the stack probably started from: 64 (linux, macos, ios, android), 128 (windows), 255."""
  if ttl is None:
    return None
  return 64 if ttl <= 64 else 128 if ttl <= 128 else 255


def fingerprint(device: Device) -> Fingerprint:
  return Fingerprint(
    hostname=normalize_hostname(device.hostname),
    services=frozenset(device.services),
    ports=frozenset(p.port for p in device.open_ports),
    ttl_family=ttl_family(device.ttl),
    network=device.ip.rsplit(".", 1)[0],
  )


 # scoring ->
@dataclass(frozen=True, slots=True)
class IdentityMatch:
  """how likely `new_key` is the same physical device as `candidate_key`, with the reasons why."""

  new_key: str
  candidate_key: str
  score: float
  evidence: tuple[str, ...]

  @property
  def level(self) -> LinkLevel | None:
    if self.score >= PROBABLE_THRESHOLD - _EPSILON:
      return LinkLevel.PROBABLE
    if self.score >= POSSIBLE_THRESHOLD - _EPSILON:
      return LinkLevel.POSSIBLE
    return None

  def summary(self) -> str:
    return f"{self.score:.2f}: {', '.join(self.evidence)}"


def score(a: Fingerprint, b: Fingerprint) -> tuple[float, tuple[str, ...]]:
  """weighted similarity of two fingerprints and one plain-language reason per matching trait."""
  total = 0.0
  evidence: list[str] = []
  if a.hostname and a.hostname == b.hostname:
    total += WEIGHT_HOSTNAME
    evidence.append(f"same hostname {a.hostname}")
  if a.services and b.services:
    shared = a.services & b.services
    if shared:
      total += WEIGHT_SERVICES * len(shared) / len(a.services | b.services)
      evidence.append(
        f"same {len(shared)} mdns services" if a.services == b.services else f"{len(shared)} mdns services in common"
      )
  if a.ports and a.ports == b.ports:
    total += WEIGHT_PORTS
    evidence.append(f"same open ports ({', '.join(str(p) for p in sorted(a.ports))})")
  if a.ttl_family is not None and a.ttl_family == b.ttl_family:
    total += WEIGHT_TTL
    evidence.append(f"same ttl family ({a.ttl_family})")
  if a.network and a.network == b.network:
    total += WEIGHT_NETWORK
    evidence.append("same /24 network")
  return round(total, 2), tuple(evidence)


 # resolver ->
class IdentityResolver:
  """decides which offline randomized device a newly seen one most likely is. pure: no network, no database.

  only randomized, non-local devices that are not the same device and not already linked are
  compared, and a weak match (below `POSSIBLE_THRESHOLD`) is never reported.
  """

  def match(self, new: Device, candidates: Iterable[Device]) -> list[IdentityMatch]:
    target = fingerprint(new)
    matches: list[IdentityMatch] = []
    for old in candidates:
      if old.key == new.key or old.is_local or not old.randomized_mac:
        continue
      if new.identity_id is not None and new.identity_id == old.identity_id:
        continue
      value, evidence = score(target, fingerprint(old))
      found = IdentityMatch(new.key, old.key, value, evidence)
      if found.level is not None:
        matches.append(found)
    return sorted(matches, key=lambda m: (-m.score, m.candidate_key))

  def best(self, new: Device, candidates: Iterable[Device]) -> IdentityMatch | None:
    """the single probable match, or none when the best one is weak or too close to the runner-up."""
    matches = self.match(new, candidates)
    if not matches or matches[0].level != LinkLevel.PROBABLE:
      return None
    if len(matches) > 1 and matches[0].score - matches[1].score < AMBIGUITY_MARGIN - _EPSILON:
      return None
    return matches[0]


def suggest_links(devices: Iterable[Device], resolver: IdentityResolver | None = None) -> list[IdentityMatch]:
  """every stored pair that could be one device: the newer randomized mac against older ones.

  a candidate is only valid if it was last seen before the newer device first appeared, because
  two devices online at the same time cannot be the same one.
  """
  resolver = resolver or IdentityResolver()
  randomized = [d for d in devices if d.randomized_mac and not d.is_local]
  found: list[IdentityMatch] = []
  for new in randomized:
    if new.first_seen is None:
      continue
    earlier = [d for d in randomized if d.last_seen is not None and d.last_seen <= new.first_seen]
    found.extend(resolver.match(new, earlier))
  return sorted(found, key=lambda m: (-m.score, m.new_key))
