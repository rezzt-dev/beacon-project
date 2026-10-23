 # import libraries ->
import csv
import io
from collections.abc import Sequence
from typing import Any

from beacon.core.events import Event
from beacon.core.models import Device


 # constants ->
COLUMNS = (
  "ip",
  "mac",
  "hostname",
  "alias",
  "vendor",
  "randomized_mac",
  "os_guess",
  "ttl",
  "status",
  "trusted",
  "gateway",
  "latency_avg_ms",
  "latency_jitter_ms",
  "packet_loss_pct",
  "open_ports",
  "first_seen",
  "last_seen",
)
# cells starting with these characters are interpreted as formulas by spreadsheet apps
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


 # csv renderer ->
def _safe(value: Any) -> Any:
  if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
    return "'" + value
  return value


def render_csv(devices: Sequence[Device], _events: Sequence[Event], _meta: dict[str, Any]) -> str:
  buffer = io.StringIO()
  writer = csv.writer(buffer, lineterminator="\n")
  writer.writerow(COLUMNS)
  for d in devices:
    latency = d.latency
    writer.writerow(
      _safe(value)
      for value in (
        d.ip,
        d.mac or "",
        d.hostname or "",
        d.alias or "",
        d.vendor or "",
        d.randomized_mac,
        d.os_guess or "",
        d.ttl if d.ttl is not None else "",
        str(d.status),
        d.trusted,
        d.is_gateway,
        latency.avg if latency and latency.avg is not None else "",
        latency.jitter if latency and latency.jitter is not None else "",
        latency.loss if latency else "",
        " ".join(f"{p.port}/{p.protocol}" for p in d.open_ports),
        d.first_seen.isoformat() if d.first_seen else "",
        d.last_seen.isoformat() if d.last_seen else "",
      )
    )
  return buffer.getvalue()
