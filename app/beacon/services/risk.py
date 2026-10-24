 # import libraries ->
from collections.abc import Iterable
from datetime import datetime

from beacon.core.events import EventType
from beacon.core.models import Device, utcnow
from beacon.core.risk import CONFLICT_WINDOW, NEW_PORT_WINDOW, RiskAssessment, assess
from beacon.storage import Repository


 # risk from stored state ->
def assess_devices(repo: Repository, devices: Iterable[Device], now: datetime | None = None) -> dict[str, RiskAssessment]:
  """risk per device from the stored state: recent new ports and conflicts (reviewed or not) and each
  device's own port coverage, so a device whose ports were never examined is "unknown", not "safe".

  the one implementation used by the cli, the api and the exports.
  """
  devices = list(devices)
  if not devices:
    return {}
  now = now or utcnow()
  networks = {d.network_id for d in devices}
  network_id = next(iter(networks)) if len(networks) == 1 else None
  # a few devices only need their own openings; many, one grouped pass over the network
  keys = [d.key for d in devices] if len(devices) <= 200 else None
  events = [
    *repo.recent_port_openings(now - NEW_PORT_WINDOW, network_id, keys),
    *repo.list_events(limit=-1, types=[EventType.IP_CONFLICT], since=now - CONFLICT_WINDOW, network_id=network_id),
  ]
  # beyond a few hundred keys one full read is cheaper than a huge `IN (...)`
  coverage = repo.port_coverage(None if len(devices) > 500 else (d.key for d in devices))
  # each device only needs its own events plus the network-wide ones (conflicts name macs, not keys)
  shared = [e for e in events if e.device_key is None]
  own: dict[str, list] = {}
  for event in events:
    if event.device_key is not None:
      own.setdefault(event.device_key, []).append(event)
  return {
    d.key: assess(d, own.get(d.key, []) + [e for e in shared if e.network_id in (None, d.network_id)],
                  d.key in coverage, now, coverage[d.key][1] if d.key in coverage else None)
    for d in devices
  }
