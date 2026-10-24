"""export: render devices and events to json, csv or a standalone html report."""

 # import libraries ->
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from beacon.core.events import Event
from beacon.core.models import Device
from beacon.export.csv_export import REPORT_FIELDS, render_csv
from beacon.export.html_export import render_html
from beacon.export.json_export import render_json


 # registry ->
RENDERERS = {
  "json": render_json,
  "csv": render_csv,
  "html": render_html,
}
FORMATS = tuple(RENDERERS)


def detect_format(path: Path, explicit: str | None = None) -> str:
  fmt = (explicit or path.suffix.lstrip(".")).lower()
  if fmt == "htm":
    fmt = "html"
  if fmt not in RENDERERS:
    raise ValueError(f"unknown export format {fmt!r} (use one of: {', '.join(FORMATS)})")
  return fmt


def render(fmt: str, devices: Sequence[Device], events: Sequence[Event] = (), meta: dict[str, Any] | None = None) -> str:
  return RENDERERS[fmt](devices, events, meta or {})


def export_to_file(
  path: Path,
  devices: Sequence[Device],
  events: Sequence[Event] = (),
  meta: dict[str, Any] | None = None,
  fmt: str | None = None,
) -> Path:
  """write atomically, so a live viewer never reads a half-written file."""
  fmt = detect_format(path, fmt)
  content = render(fmt, devices, events, meta)
  path.parent.mkdir(parents=True, exist_ok=True)
  fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
  try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
      handle.write(content)
    os.replace(tmp_name, path)
  except BaseException:
    Path(tmp_name).unlink(missing_ok=True)
    raise
  return path


__all__ = ["FORMATS", "REPORT_FIELDS", "detect_format", "export_to_file", "render"]
