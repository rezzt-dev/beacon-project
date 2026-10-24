 # import libraries ->
from typing import Any

from beacon.core.events import EventType
from beacon.core.ports import PortSet
from beacon.services.serialize import event_dict
from beacon.storage import NotFoundError, Repository
from beacon.storage.events import EventFilter


 # history ->
def scan_detail(repo: Repository, scan_id: int) -> dict[str, Any]:
  scan = repo.get_scan(scan_id)
  if scan is None:
    raise NotFoundError(f"scan {scan_id} not found")
  events = repo.query_events(EventFilter(scan_id=scan_id), limit=200)
  return {**scan, "events": [event_dict(e) for e in events]}


 # comparison ->
_CHANGE_KINDS = {
  EventType.NEW_DEVICE: "added",
  EventType.DEVICE_ONLINE: "returned",
  EventType.DEVICE_OFFLINE: "absent",
  EventType.IP_CHANGED: "address",
  EventType.PORT_OPENED: "exposure",
  EventType.PORT_CLOSED: "exposure",
  EventType.IDENTITY_CANDIDATE: "added",
}


def compare(repo: Repository, before_id: int, after_id: int) -> dict[str, Any]:
  """what changed between two scans of the same network, and why the comparison may be uneven.

  changes are the events recorded by the scans after `before_id` up to `after_id`; differences in
  target, mode, port set and status are listed so a "missing" port or device can be explained.
  """
  if before_id >= after_id:
    raise ValueError("the first scan must be older than the second")
  before, after = repo.get_scan(before_id), repo.get_scan(after_id)
  if before is None or after is None:
    raise NotFoundError("both scans must exist")
  if before["network_id"] != after["network_id"]:
    raise ValueError("scans of different networks are not comparable")
  rows = repo.conn.execute(
    "SELECT id FROM scans WHERE network_id = ? AND id > ? AND id <= ? AND status IN ('complete', 'partial')",
    (after["network_id"], before_id, after_id),
  ).fetchall()
  scan_ids = [r["id"] for r in rows]
  changes: dict[str, list[dict[str, Any]]] = {"added": [], "returned": [], "absent": [], "address": [], "exposure": []}
  for scan_id in scan_ids:
    for event in repo.query_events(EventFilter(scan_id=scan_id), limit=-1):
      kind = _CHANGE_KINDS.get(event.type)
      if kind:
        changes[kind].append(event_dict(event))
  caveats: list[str] = []
  if before["target"] != after["target"]:
    caveats.append(f"different targets: {before['target']} vs {after['target']}")
  if before["mode"] != after["mode"]:
    caveats.append(f"different discovery modes: {before['mode']} vs {after['mode']}")
  a, b = PortSet.parse(before["port_spec"]), PortSet.parse(after["port_spec"])
  if a != b:
    only_a, only_b = len(PortSet([p for p in a if p not in b])), len(PortSet([p for p in b if p not in a]))
    caveats.append(
      f"different port sets ({len(a)} vs {len(b)} ports; {only_a} only in the first, {only_b} only in the second): "
      "a port outside a scan's set was not examined"
    )
  for scan in (before, after):
    if scan["status"] != "complete":
      caveats.append(f"scan {scan['id']} was {scan['status']}: {', '.join(i['message'] for i in scan['issues'][:2]) or 'no details'}")
    if scan["unobserved"]:
      caveats.append(f"scan {scan['id']} could not probe {scan['unobserved']} addresses")
  skipped = repo.count_scans(after["network_id"]) and repo.conn.execute(
    "SELECT COUNT(*) FROM scans WHERE network_id = ? AND id > ? AND id <= ? AND status NOT IN ('complete', 'partial')",
    (after["network_id"], before_id, after_id),
  ).fetchone()[0]
  if skipped:
    caveats.append(f"{skipped} scans in between failed or were cancelled")
  return {
    "before": before,
    "after": after,
    "scans_between": len(scan_ids),
    "changes": changes,
    "device_count": {"before": before["device_count"], "after": after["device_count"]},
    "caveats": caveats,
    "comparable": not any(c.startswith("different targets") for c in caveats),
  }
