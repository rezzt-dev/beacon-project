 # import libraries ->
import time
from collections import deque
from collections.abc import Sequence

from rich.console import Group, RenderableType
from rich.text import Text

from beacon.core.events import Event, Severity
from beacon.core.models import Device, DeviceStatus
from beacon.core.report import ScanReport
from beacon.ui.render import devices_table, events_table, report_summary


 # watch view ->
class WatchView:
  """state behind `beacon watch`: re-rendered by `rich.live.Live` on every refresh.

  it is also the progress reporter and an event bus subscriber of the pipeline,
  so the screen reflects the scan stage and new events as they happen.
  """

  def __init__(self, interval: float, max_events: int = 10) -> None:
    self.interval = interval
    self.cycle = 0
    self.devices: list[Device] = []
    self.report: ScanReport | None = None
    self.events: deque[Event] = deque(maxlen=max_events)
    self.alerts = 0
    self.stage_name = "starting"
    self.stage_total: int | None = None
    self.stage_done = 0
    self.next_scan_at: float | None = None

  # progress reporter protocol ->
  def stage(self, name: str, total: int | None = None) -> None:
    self.stage_name, self.stage_total, self.stage_done = name, total, 0
    self.next_scan_at = None

  def advance(self, amount: int = 1) -> None:
    self.stage_done += amount

  # event bus subscriber ->
  def on_event(self, event: Event) -> None:
    self.events.appendleft(event)
    if event.severity == Severity.ALERT:
      self.alerts += 1

  def update(self, report: ScanReport, inventory: Sequence[Device]) -> None:
    self.cycle += 1
    self.report = report
    self.devices = sorted(inventory, key=lambda d: d.status != DeviceStatus.ONLINE)
    self.stage_name = "idle"
    self.next_scan_at = time.monotonic() + self.interval

  # rendering ->
  def _header(self) -> Text:
    text = Text("BEACON WATCH", style="accent")
    text.append(f"  cycle {self.cycle}", style="bold")
    if self.next_scan_at is not None:
      text.append(f"  next scan in {max(0, self.next_scan_at - time.monotonic()):.0f}s", style="muted")
    else:
      progress = f" {self.stage_done}/{self.stage_total}" if self.stage_total else ""
      text.append(f"  {self.stage_name}{progress}…", style="warning")
    if self.alerts:
      text.append(f"  {self.alerts} alerts", style="alert")
    text.append("  ctrl+c to stop", style="muted")
    return text

  def __rich__(self) -> RenderableType:
    parts: list[RenderableType] = [self._header()]
    if self.report is not None:
      parts.append(report_summary(self.report))
    parts.append(devices_table(self.devices))
    if self.events:
      parts.append(events_table(list(self.events), title="latest events"))
    return Group(*parts)
