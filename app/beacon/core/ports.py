 # import libraries ->
from bisect import bisect_right
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime

from beacon.core.models import PortInfo, PortState


 # port sets ->
class PortSet:
  """an immutable set of tcp/udp ports stored as sorted ranges, cheap even for 1-65535.

  scans record which ports they examined with it, so a port outside the set is "not examined"
  instead of "closed".
  """

  __slots__ = ("_ranges", "_starts")

  def __init__(self, ports: Iterable[int] = ()) -> None:
    ranges: list[tuple[int, int]] = []
    for port in sorted(set(ports)):
      if ranges and port == ranges[-1][1] + 1:
        ranges[-1] = (ranges[-1][0], port)
      else:
        ranges.append((port, port))
    self._ranges = tuple(ranges)
    self._starts = tuple(start for start, _ in ranges)

  @classmethod
  def parse(cls, spec: str | None) -> "PortSet":
    """inverse of `str()`: `22,80-90`. an empty or missing spec is the empty set."""
    ports: list[int] = []
    for token in (spec or "").split(","):
      token = token.strip()
      if not token:
        continue
      start, _, end = token.partition("-")
      first, last = int(start), int(end or start)
      if not 1 <= first <= last <= 65535:
        raise ValueError(f"invalid port range {token!r}")
      ports.extend(range(first, last + 1))
    return cls(ports)

  def __contains__(self, port: object) -> bool:
    if not isinstance(port, int):
      return False
    index = bisect_right(self._starts, port) - 1
    return index >= 0 and self._ranges[index][0] <= port <= self._ranges[index][1]

  def __len__(self) -> int:
    return sum(end - start + 1 for start, end in self._ranges)

  def __bool__(self) -> bool:
    return bool(self._ranges)

  def __iter__(self):
    for start, end in self._ranges:
      yield from range(start, end + 1)

  def __eq__(self, other: object) -> bool:
    return isinstance(other, PortSet) and self._ranges == other._ranges

  def __hash__(self) -> int:
    return hash(self._ranges)

  def __str__(self) -> str:
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in self._ranges)

  def __repr__(self) -> str:
    return f"PortSet({str(self)!r})"

  def union(self, other: "PortSet") -> "PortSet":
    if not other:
      return self
    if not self:
      return other
    return PortSet([*self, *other])


 # merging measurements ->
def merge_ports(
  known: Iterable[PortInfo],
  results: Mapping[int, PortInfo],
  examined: PortSet,
  now: datetime,
) -> list[PortInfo]:
  """fold the probe results of one scan into the ports already known for a device.

  `results` holds what the scanner reported: every open port plus every known port it probed.
  - a port outside `examined` keeps its previous state untouched: it was not measured.
  - a refused connection is a confirmed close; a timeout is not, so a known open port keeps
    its state and only records that the last probe got no answer.
  - a measurement error never changes the state and does not count as a check.
  """
  merged: dict[int, PortInfo] = {p.port: replace(p) for p in known}
  for port, result in sorted(results.items()):
    if port not in examined:
      continue
    old = merged.get(port)
    if result.state == PortState.OPEN:
      merged[port] = replace(
        result,
        state=PortState.OPEN,
        last_probe=PortState.OPEN,
        checked_at=now,
        open_seen_at=now,
        first_seen=old.first_seen if old and old.first_seen else now,
        banner=result.banner or (old.banner if old else None),
        protocol_observed=result.protocol_observed or (old.protocol_observed if old else None),
        tls=result.tls or (old.tls if old else None),
      )
    elif result.state == PortState.CLOSED:
      if old is None:
        continue
      old.state, old.last_probe, old.checked_at = PortState.CLOSED, PortState.CLOSED, now
    elif result.state == PortState.FILTERED:
      if old is None:
        continue
      if old.state != PortState.OPEN:
        old.state = PortState.FILTERED
      old.last_probe, old.checked_at = PortState.FILTERED, now
    elif old is not None:  # error: keep the state and the last valid check
      old.last_probe = PortState.ERROR
  return sorted(merged.values(), key=lambda p: (p.protocol, p.port))
