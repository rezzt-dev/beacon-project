 # import libraries ->
import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import replace

from beacon.core.events import Event
from beacon.core.models import Device


 # pseudonyms ->
class Pseudonymizer:
  """replaces identifiers with stable, meaningless labels for one report.

  the key is random per report, so two reports cannot be joined on their labels. this hides
  addresses and names from a casual reader; it does not make a report anonymous: vendors, open
  ports, timing and the number of devices can still identify a household or a person.
  """

  def __init__(self, key: bytes | None = None) -> None:
    self._key = key or secrets.token_bytes(32)

  def label(self, kind: str, value: str | None) -> str | None:
    if not value:
      return None
    digest = hmac.new(self._key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"{kind}-{digest}"

  def device(self, device: Device) -> Device:
    return replace(
      device,
      ip=self.label("ip", device.ip) or "",
      ips=[self.label("ip", ip) or "" for ip in device.ips],
      ips6=[self.label("ip6", ip) or "" for ip in device.ips6],
      mac=self.label("mac", device.mac),
      hostname=self.label("host", device.hostname),
      alias=self.label("name", device.alias),
      owner=None,
      notes=None,
      services=[],
      ports=[replace(p, banner=None, tls=None) for p in device.ports],
    )

  def event(self, event: Event, devices: dict[str, Device]) -> Event:
    """event messages embed names and addresses, so they are rebuilt from the type alone."""
    target = devices.get(event.device_key or "")
    subject = self.label("dev", event.device_key) if event.device_key else None
    message = f"{event.type}" + (f" on {subject}" if subject else "")
    if target is not None and target.alias:
      message += f" ({self.label('name', target.alias)})"
    return replace(
      event,
      message=message,
      device_key=subject,
      ip=self.label("ip", event.ip),
      mac=self.label("mac", event.mac),
      details={k: v for k, v in event.details.items() if k in ("port", "risk", "first_check", "score")},
    )


def pseudonymize(devices: Sequence[Device], events: Sequence[Event]) -> tuple[list[Device], list[Event], Pseudonymizer]:
  names = Pseudonymizer()
  by_key = {d.key: d for d in devices}
  return [names.device(d) for d in devices], [names.event(e, by_key) for e in events], names
