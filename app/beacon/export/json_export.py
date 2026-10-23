 # import libraries ->
import json
from collections.abc import Sequence
from typing import Any

from beacon import __version__
from beacon.core.events import Event
from beacon.core.models import Device, utcnow


 # json renderer ->
def render_json(devices: Sequence[Device], events: Sequence[Event], meta: dict[str, Any]) -> str:
  document = {
    "generator": f"beacon {__version__}",
    "generated_at": utcnow().isoformat(),
    **meta,
    "device_count": len(devices),
    "devices": [d.to_dict() for d in devices],
    "events": [e.to_dict() for e in events],
  }
  return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
