 # import libraries ->
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

from beacon.core.engine import IpConflict
from beacon.core.events import Event, EventType, Severity
from beacon.core.identity import IdentityMatch
from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.risk import RiskLevel, assess


 # helpers ->
def _label(device: Device) -> str:
  name = device.alias or device.hostname
  base = f"{device.ip} ({device.mac})" if device.mac else device.ip
  return f"{name} [{base}]" if name else base


def _event(kind: EventType, severity: Severity, message: str, device: Device, **details) -> Event:
  return Event(
    type=kind,
    severity=severity,
    message=message,
    device_key=device.key,
    ip=device.ip,
    mac=device.mac,
    details=details,
  )


 # change detection ->
def detect_changes(
  previous: dict[str, Device],
  current: dict[str, Device],
  conflicts: Iterable[IpConflict] = (),
  network: IPv4Network | None = None,
  ports_scanned: bool = False,
  offline_grace: timedelta = timedelta(0),
  now: datetime | None = None,
  identity_candidates: Mapping[str, IdentityMatch] | None = None,
) -> list[Event]:
  """compare the stored state with a fresh scan and emit change events.

  devices outside the scanned network are never reported offline, so scanning
  another subnet does not flip the state of the rest of the inventory. a device
  missing for less than `offline_grace` is kept online: phones in power saving
  skip probes now and then, and flapping events are just noise.

  an empty inventory means this is the first scan: every host is "new" by definition, so
  they are warnings (to be reviewed) and only an obviously risky one is an alert. a randomized
  device that probably is a known one with a new private mac (`identity_candidates`, by new
  key) is reported as an identity candidate instead of an unknown intruder.
  """
  events: list[Event] = []
  now = now or utcnow()
  baseline = not previous
  identity_candidates = identity_candidates or {}

  for key, device in sorted(current.items(), key=lambda item: IPv4Address(item[1].ip)):
    old = previous.get(key)
    if old is None and device.is_local:
      events.append(_event(EventType.NEW_DEVICE, Severity.INFO, f"this host registered: {_label(device)}", device))
      continue
    match = identity_candidates.get(key) if old is None else None
    if match is not None and (known := previous.get(match.candidate_key)) is not None:
      events.append(
        _event(
          EventType.IDENTITY_CANDIDATE,
          Severity.WARNING,
          f"probably {known.alias or known.hostname or known.ip} with a new private mac ({match.summary()}): {_label(device)}",
          device,
          candidate_key=match.candidate_key,
          score=match.score,
          evidence=list(match.evidence),
        )
      )
      continue
    if old is None:
      kind = "randomized mac" if device.randomized_mac else device.display_vendor
      risk = assess(device)
      alert = not baseline or risk.level == RiskLevel.HIGH
      headline = "unknown device joined the network" if not baseline else "device found in the first scan"
      events.append(
        _event(
          EventType.NEW_DEVICE,
          Severity.ALERT if alert else Severity.WARNING,
          f"{headline}: {_label(device)} - {kind}",
          device,
          vendor=device.vendor,
          randomized_mac=device.randomized_mac,
          open_ports=[p.port for p in device.open_ports],
          risk=risk.score,
          baseline=baseline,
        )
      )
      continue

    if old.status == DeviceStatus.OFFLINE:
      severity = Severity.INFO if old.trusted else Severity.WARNING
      trust = "" if old.trusted else " (untrusted)"
      events.append(
        _event(EventType.DEVICE_ONLINE, severity, f"device back online{trust}: {_label(device)}", device)
      )

    if old.ip != device.ip:
      events.append(
        _event(
          EventType.IP_CHANGED,
          Severity.INFO,
          f"{_label(device)} changed ip from {old.ip} to {device.ip}",
          device,
          old_ip=old.ip,
          new_ip=device.ip,
        )
      )

    if ports_scanned:
      before = {p.port for p in old.open_ports}
      after = {p.port: p for p in device.open_ports}
      for port in sorted(after.keys() - before):
        service = after[port].service or "unknown"
        events.append(
          _event(
            EventType.PORT_OPENED,
            Severity.WARNING,
            f"new open port {port}/tcp ({service}) on {_label(device)}",
            device,
            port=port,
            service=after[port].service,
          )
        )
      for port in sorted(before - after.keys()):
        events.append(
          _event(EventType.PORT_CLOSED, Severity.INFO, f"port {port}/tcp closed on {_label(device)}", device, port=port)
        )

  for key, old in previous.items():
    if key in current or old.status != DeviceStatus.ONLINE:
      continue
    if network is not None and IPv4Address(old.ip) not in network:
      continue
    if old.last_seen is not None and now - old.last_seen < offline_grace:
      continue
    events.append(_event(EventType.DEVICE_OFFLINE, Severity.INFO, f"device went offline: {_label(old)}", old))

  for conflict in conflicts:
    events.append(
      Event(
        type=EventType.IP_CONFLICT,
        severity=Severity.ALERT,
        message=f"ip {conflict.ip} answered from {len(conflict.macs)} macs ({', '.join(conflict.macs)}): possible arp spoofing",
        ip=conflict.ip,
        details={"macs": list(conflict.macs)},
      )
    )

  return events
