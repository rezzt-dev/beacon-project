 # import libraries ->
import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from beacon.core.events import EventType
from beacon.core.exposure import Basis, profile_for
from beacon.core.models import PortInfo, PortState, utcnow
from beacon.core.ports import PortSet
from beacon.storage import Repository
from beacon.storage.devices import port_rows


MAX_LISTED = 50


 # services inventory ->
def services_overview(repo: Repository, network_id: int | None = None, q: str | None = None, now: datetime | None = None) -> dict[str, Any]:
  """every port seen on the network: on how many devices it is open, how many were checked for it,
  how it was identified (observed or inferred), certificates and recent changes."""
  now = now or utcnow()
  rows = port_rows(repo.conn, network_id)
  coverage = repo.port_coverage()
  devices_in_scope = repo.device_keys(network_id)
  # devices usually share a handful of port profiles: count per distinct set, not per device
  specs = Counter(spec for key, (spec, _) in coverage.items() if key in devices_in_scope and spec is not None)
  legacy = sum(1 for key, (spec, _) in coverage.items() if key in devices_in_scope and spec is None)
  changes = repo.port_change_counts(now - timedelta(days=7), network_id)

  grouped: dict[tuple[int, str], dict[str, Any]] = {}
  for row in rows:
    port = PortInfo(
      row["port"],
      PortState(row["state"]),
      row["protocol"],
      service=row["service"],
      protocol_observed=row["protocol_observed"],
      tls=json.loads(row["tls"]) if row["tls"] else None,
    )
    profile, basis = profile_for(port)
    entry = grouped.setdefault(
      (row["port"], row["protocol"]),
      {
        "port": row["port"],
        "protocol": row["protocol"],
        "service": profile.service if profile else row["service"],
        "exposure": str(profile.exposure) if profile else None,
        "encrypted": profile.encrypted if profile else None,
        "observed_protocols": set(),
        "states": Counter(),
        "devices": [],
        "last_checked": None,
        "certificates": [],
      },
    )
    entry["states"][row["state"]] += 1
    if basis == Basis.OBSERVED and port.protocol_observed:
      entry["observed_protocols"].add(port.protocol_observed)
    if row["checked_at"] and (entry["last_checked"] is None or row["checked_at"] > entry["last_checked"]):
      entry["last_checked"] = row["checked_at"]
    if row["state"] == "open":
      entry["devices"].append(
        {
          "key": row["device_key"],
          "ip": row["ip"],
          "name": row["alias"] or row["hostname"] or row["ip"],
          "banner": row["banner"],
          "checked_at": row["checked_at"],
          "last_probe": row["last_probe"],
        }
      )
    if port.tls and port.tls.get("sha256"):
      entry["certificates"].append(
        {
          "device": row["device_key"],
          "subject": port.tls.get("subject"),
          "issuer": port.tls.get("issuer"),
          "not_after": port.tls.get("not_after"),
          "self_signed": port.tls.get("self_signed"),
          "expired": bool(port.tls.get("not_after") and port.tls["not_after"] < now.isoformat()),
        }
      )

  needle = (q or "").strip().lower()
  items = []
  for (port, _protocol), entry in sorted(grouped.items()):
    examined = sum(count for spec, count in specs.items() if port in spec)
    item = {
      **entry,
      # a port open on thousands of devices lists the first ones; `open` keeps the full count
      "devices": entry["devices"][:MAX_LISTED],
      "certificates": entry["certificates"][:MAX_LISTED],
      "devices_truncated": len(entry["devices"]) > MAX_LISTED,
      "certificates_total": len(entry["certificates"]),
      "observed_protocols": sorted(entry["observed_protocols"]),
      "states": dict(entry["states"]),
      "open": entry["states"].get("open", 0),
      "examined_devices": examined,
      "devices_in_scope": len(devices_in_scope),
      "legacy_unknown": legacy,
      "opened_7d": changes.get((EventType.PORT_OPENED, port), 0),
      "closed_7d": changes.get((EventType.PORT_CLOSED, port), 0),
    }
    if needle and needle not in f"{port} {item['service'] or ''} {' '.join(item['observed_protocols'])}".lower():
      continue
    items.append(item)
  union = PortSet()
  for spec in specs:
    union = union.union(spec)
  return {
    "items": items,
    "examined_ports": str(union) or None,
    "devices_examined": sum(specs.values()),
    "devices_in_scope": len(devices_in_scope),
  }
