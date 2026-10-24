 # import libraries ->
import json
from collections.abc import Sequence
from typing import Any

from beacon import __version__
from beacon.core.events import Event
from beacon.core.models import Device, utcnow


# meta keys that tune the renderers and are not facts about the scan
_RENDER_OPTIONS = {"include_fingerprint", "ports_known"}


 # json renderer ->
def render_json(devices: Sequence[Device], events: Sequence[Event], meta: dict[str, Any]) -> str:
  fingerprint = bool(meta.get("include_fingerprint"))
  document = {
    "generator": f"beacon {__version__}",
    "generated_at": utcnow().isoformat(),
    **{k: v for k, v in meta.items() if k not in _RENDER_OPTIONS},
    "device_count": len(devices),
    "devices": [d.to_dict(fingerprint=fingerprint) for d in devices],
    "events": [e.to_dict() for e in events],
  }
  return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
