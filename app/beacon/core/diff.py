 # import libraries ->
from collections.abc import Collection, Iterable, Mapping
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

from beacon.core.engine import IpConflict
from beacon.core.events import Event, EventType, Severity
from beacon.core.identity import IdentityMatch
from beacon.core.models import Device, DeviceStatus, PortState, utcnow
from beacon.core.ports import PortSet
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
  port_spec: PortSet | None = None,
  offline_grace: timedelta = timedelta(0),
  now: datetime | None = None,
  identity_candidates: Mapping[str, IdentityMatch] | None = None,
  examined_before: Mapping[str, PortSet | None] | None = None,
  unobserved: Collection[str] = (),
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

  ports: `current` devices carry this scan's probe results (open ports plus every known port that
  was probed again) and `port_spec` is what was examined. a port outside it says nothing; a known
  open port is reported closed only after a refused connection, never after a timeout. an open port
  on a port never examined before (`examined_before`, by key; `None` = a legacy scan whose port set
  is unknown) is a first check, not a change.

  `unobserved` addresses could not be probed at all (send failures), so their silence is not an absence.
  """
  events: list[Event] = []
  now = now or utcnow()
  baseline = not previous
  identity_candidates = identity_candidates or {}
  port_spec = port_spec or PortSet()
  examined_before = examined_before or {}

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
      risk = assess(device, ports_known=bool(port_spec), now=now)
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

    if port_spec:
      events.extend(_port_events(old, device, port_spec, examined_before))

  for key, old in previous.items():
    if key in current or old.status != DeviceStatus.ONLINE:
      continue
    if network is not None and IPv4Address(old.ip) not in network:
      continue
    if old.ip in unobserved:
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


def _port_events(old: Device, device: Device, port_spec: PortSet, examined_before: Mapping[str, PortSet | None]) -> list[Event]:
  events: list[Event] = []
  known = {p.port: p for p in old.ports}
  results = {p.port: p for p in device.ports if p.port in port_spec}
  legacy = device.key in examined_before and examined_before[device.key] is None
  history = examined_before.get(device.key) or PortSet()
  for port, result in sorted(results.items()):
    before = known.get(port)
    if result.state == PortState.OPEN and (before is None or before.state != PortState.OPEN):
      service = result.protocol_observed or result.service or "unknown"
      first_check = before is None and not legacy and port not in history
      if first_check:
        message = f"open port {port}/{result.protocol} ({service}) found on {_label(device)}: first time this port was checked"
      else:
        message = f"new open port {port}/{result.protocol} ({service}) on {_label(device)}"
      events.append(
        _event(
          EventType.PORT_OPENED,
          Severity.INFO if first_check else Severity.WARNING,
          message,
          device,
          port=port,
          service=result.service,
          protocol_observed=result.protocol_observed,
          first_check=first_check,
        )
      )
    elif result.state == PortState.CLOSED and before is not None and before.state == PortState.OPEN:
      events.append(
        _event(
          EventType.PORT_CLOSED,
          Severity.INFO,
          f"port {port}/{result.protocol} closed on {_label(device)} (connection refused)",
          device,
          port=port,
        )
      )
  return events
