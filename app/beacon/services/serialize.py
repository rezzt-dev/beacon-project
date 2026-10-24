 # import libraries ->
from datetime import datetime
from typing import Any

from beacon.core.events import Event
from beacon.core.exposure import Basis, describe, is_sensitive, profile_for
from beacon.core.models import Device, PortInfo
from beacon.core.risk import RiskAssessment


 # helpers ->
def iso(value: datetime | None) -> str | None:
  return value.isoformat() if value else None


 # serializers ->
def port_dict(port: PortInfo) -> dict[str, Any]:
  profile, basis = profile_for(port)
  return {
    **port.to_dict(),
    "inferred_service": profile.service if profile and basis == Basis.INFERRED else None,
    "exposure": str(profile.exposure) if profile else None,
    "encrypted": profile.encrypted if profile else None,
    "basis": str(basis),
    "sensitive": is_sensitive(port),
    "description": describe(port),
  }


def risk_dict(risk: RiskAssessment | None) -> dict[str, Any] | None:
  if risk is None:
    return None
  return {
    "score": risk.score,
    "level": str(risk.level),
    "complete": risk.complete,
    "reasons": [r.to_dict() for r in risk.reasons],
    "notes": list(risk.notes),
    "rules_version": risk.rules_version,
    "ports_checked_at": iso(risk.ports_checked_at),
  }


def device_summary(device: Device, risk: RiskAssessment | None = None, snoozed_until: datetime | None = None) -> dict[str, Any]:
  """the row of a device list: enough to filter, sort and decide without opening the detail."""
  latency = device.latency
  return {
    "key": device.key,
    "network_id": device.network_id,
    "ip": device.ip,
    "ips": device.ips,
    "ips6": device.ips6,
    "mac": device.mac,
    "hostname": device.hostname,
    "hostname_source": device.hostname_source,
    "vendor": device.vendor,
    "randomized_mac": device.randomized_mac,
    "os_guess": device.os_guess,
    "ttl": device.ttl,
    "alias": device.alias,
    "name": device.display_name,
    "category": device.category,
    "tags": device.tags,
    "owner": device.owner,
    "essential": device.essential,
    "trusted": device.trusted,
    "status": str(device.status),
    "is_local": device.is_local,
    "is_gateway": device.is_gateway,
    "identity_id": device.identity_id,
    "first_seen": iso(device.first_seen),
    "last_seen": iso(device.last_seen),
    "latency": latency.to_dict() if latency else None,
    "open_ports": [{"port": p.port, "protocol": p.protocol, "service": p.protocol_observed or p.service, "sensitive": is_sensitive(p)} for p in device.open_ports],
    "risk": risk_dict(risk),
    "snoozed_until": iso(snoozed_until),
    "version": device.version,
  }


def device_detail(device: Device, risk: RiskAssessment | None = None, snoozed_until: datetime | None = None) -> dict[str, Any]:
  return {
    **device_summary(device, risk, snoozed_until),
    "notes": device.notes,
    "services": device.services,
    "sources": sorted(device.sources),
    "ports": [port_dict(p) for p in sorted(device.ports, key=lambda p: (str(p.state) != "open", p.port))],
  }


def event_dict(event: Event) -> dict[str, Any]:
  return {**event.to_dict(), "scan_id": event.scan_id}
