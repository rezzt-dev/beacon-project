 # import libraries ->
from datetime import timedelta
from typing import Any

from beacon.core.models import DeviceStatus, utcnow
from beacon.export import render
from beacon.export.anonymize import pseudonymize
from beacon.services import settings as app_settings
from beacon.services.risk import assess_devices
from beacon.storage import EventFilter, Repository


 # constants ->
MEDIA = {"json": "application/json", "csv": "text/csv; charset=utf-8", "html": "text/html; charset=utf-8"}
PRESENCE_DAYS = 7


 # collection ->
def _collect(repo: Repository, options: dict[str, Any]) -> tuple[list, list, dict[str, Any], list[str]]:
  """devices, events and meta for a report, applying every privacy choice in one place."""
  warnings: list[str] = []
  network_id = options.get("network_id")
  devices = repo.list_devices(status=DeviceStatus.ONLINE if options.get("online") else None, network_id=network_id)
  events = repo.query_events(EventFilter(network_id=network_id, since=options.get("since")), limit=options.get("events") or 0) if options.get("events") else []
  risks = assess_devices(repo, devices)
  network = repo.get_network(network_id) if network_id is not None else None
  last = repo.last_valid_scan(network_id)
  meta: dict[str, Any] = {
    "network": (network or {}).get("cidr") or (last or {}).get("network"),
    "risks": risks,
    "ports_known": repo.ports_ever_scanned(),
    "include_fingerprint": bool(options.get("include_fingerprint")),
    "fields": options.get("fields"),
    "last_valid_scan": (last or {}).get("finished_at"),
  }
  if options.get("include_presence"):
    if not app_settings.load(repo)["presence"]["enabled"]:
      warnings.append("presence recording is disabled: the report has no presence data")
    since = utcnow() - timedelta(days=PRESENCE_DAYS)
    sessions = repo.sessions_by_identity(devices, since=since)
    meta["presence"] = {key: [s.to_dict() for s in items] for key, items in sessions.items()}
    warnings.append("presence shows when people are home: share this report only with people you trust")
  if options.get("include_fingerprint"):
    warnings.append("the identity fingerprint (mdns services) helps recognize devices across networks")
  if options.get("anonymize"):
    original = devices
    devices, events, _names = pseudonymize(devices, events)
    # a device key derives from its mac or ip, so everything keyed by it follows the new labels
    renamed = {old.key: new.key for old, new in zip(original, devices, strict=True)}
    meta["risks"] = {renamed[key]: risk for key, risk in risks.items() if key in renamed}
    if "presence" in meta:
      meta["presence"] = {
        renamed[key]: [{k: v for k, v in s.items() if k != "device_key"} for s in items]
        for key, items in meta["presence"].items()
        if key in renamed
      }
    meta["anonymized"] = True
    meta.pop("network", None)
    warnings.append("pseudonymized identifiers hide addresses and names; vendors, ports and timing can still identify devices")
  return devices, events, meta, warnings


def preview(repo: Repository, options: dict[str, Any]) -> dict[str, Any]:
  """what a report would contain, before generating it."""
  devices, events, meta, warnings = _collect(repo, options)
  sample = devices[0].to_dict(fingerprint=bool(options.get("include_fingerprint"))) if devices else None
  if sample and options.get("fields"):
    sample = {k: v for k, v in sample.items() if k == "key" or k in options["fields"]}
  return {
    "format": options["format"],
    "devices": len(devices),
    "events": len(events),
    "fields": options.get("fields"),
    "includes_presence": "presence" in meta,
    "includes_fingerprint": bool(options.get("include_fingerprint")),
    "anonymized": bool(meta.get("anonymized")),
    "warnings": warnings,
    "sample": sample,
  }


def build(repo: Repository, options: dict[str, Any]) -> tuple[str, str, str]:
  """`(content, media type, file name)` of a standalone report."""
  devices, events, meta, _warnings = _collect(repo, options)
  fmt = options["format"]
  content = render(fmt, devices, events, meta)
  return content, MEDIA[fmt], f"beacon-{utcnow():%Y%m%d-%H%M}.{fmt}"
