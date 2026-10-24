 # import libraries ->
import json
from collections.abc import Sequence
from typing import Any

from beacon import __version__
from beacon.core.events import Event
from beacon.core.models import Device, utcnow


# meta keys that tune the renderers and are not facts about the scan
_RENDER_OPTIONS = {"include_fingerprint", "ports_known", "risks", "fields", "presence"}


 # json renderer ->
def _device(d: Device, meta: dict[str, Any]) -> dict[str, Any]:
  data = d.to_dict(fingerprint=bool(meta.get("include_fingerprint")))
  risk = (meta.get("risks") or {}).get(d.key)
  if risk is not None:
    data.update(risk.to_dict())
  presence = meta.get("presence")
  if presence is not None:
    data["presence"] = presence.get(d.key, [])
  fields = meta.get("fields")
  if fields:
    data = {k: v for k, v in data.items() if k == "key" or k in fields}
  return data


def render_json(devices: Sequence[Device], events: Sequence[Event], meta: dict[str, Any]) -> str:
  document = {
    "generator": f"beacon {__version__}",
    "generated_at": utcnow().isoformat(),
    **{k: v for k, v in meta.items() if k not in _RENDER_OPTIONS},
    "device_count": len(devices),
    "devices": [_device(d, meta) for d in devices],
    "events": [e.to_dict() for e in events],
  }
  return json.dumps(document, indent=2, ensure_ascii=False, default=str) + "\n"
