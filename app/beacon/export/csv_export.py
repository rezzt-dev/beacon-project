 # import libraries ->
import csv
import io
from collections.abc import Sequence
from typing import Any

from beacon.core.events import Event
from beacon.core.models import Device


 # constants ->
# the default columns, in order; `REPORT_FIELDS` adds the optional ones a report may select
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
REPORT_FIELDS = (
  *COLUMNS,
  "network_id",
  "ips6",
  "category",
  "tags",
  "owner",
  "essential",
  "risk",
  "risk_level",
  "risk_complete",
)
# cells starting with these characters are interpreted as formulas by spreadsheet apps
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


 # csv renderer ->
def _safe(value: Any) -> Any:
  if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
    return "'" + value
  return value


def _values(d: Device, risk: Any) -> dict[str, Any]:
  latency = d.latency
  return {
    "ip": d.ip,
    "mac": d.mac or "",
    "hostname": d.hostname or "",
    "alias": d.alias or "",
    "vendor": d.vendor or "",
    "randomized_mac": d.randomized_mac,
    "os_guess": d.os_guess or "",
    "ttl": d.ttl if d.ttl is not None else "",
    "status": str(d.status),
    "trusted": d.trusted,
    "gateway": d.is_gateway,
    "latency_avg_ms": latency.avg if latency and latency.avg is not None else "",
    "latency_jitter_ms": latency.jitter if latency and latency.jitter is not None else "",
    "packet_loss_pct": latency.loss if latency else "",
    "open_ports": " ".join(f"{p.port}/{p.protocol}" for p in d.open_ports),
    "first_seen": d.first_seen.isoformat() if d.first_seen else "",
    "last_seen": d.last_seen.isoformat() if d.last_seen else "",
    "network_id": d.network_id,
    "ips6": " ".join(d.ips6),
    "category": d.category or "",
    "tags": " ".join(d.tags),
    "owner": d.owner or "",
    "essential": d.essential,
    "risk": risk.score if risk else "",
    "risk_level": str(risk.level) if risk else "",
    "risk_complete": risk.complete if risk else "",
  }


def render_csv(devices: Sequence[Device], _events: Sequence[Event], meta: dict[str, Any]) -> str:
  columns = tuple(meta.get("fields") or COLUMNS)
  risks = meta.get("risks") or {}
  buffer = io.StringIO()
  writer = csv.writer(buffer, lineterminator="\n")
  writer.writerow(columns)
  for d in devices:
    values = _values(d, risks.get(d.key))
    writer.writerow(_safe(values[column]) for column in columns)
  return buffer.getvalue()
