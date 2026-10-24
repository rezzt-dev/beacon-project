 # import libraries ->
import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path

from rich import box
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import Device, DeviceStatus
from beacon.core.report import ScanReport
from beacon.ui.render import devices_table, events_table, fmt_duration, plural


 # constants ->
# events that make a device worth a second look on the next screen refresh
_FRESH_EVENTS = {EventType.NEW_DEVICE, EventType.IDENTITY_CANDIDATE}
# rows the header, the table chrome and the events block take, so the device table never
# pushes the events off a small terminal
_HEADER_ROWS = 6
_TABLE_CHROME = 5
_EVENTS_CHROME = 4


 # watch view ->
class WatchView:
  """state behind `beacon watch`: re-rendered by `rich.live.Live` on every refresh.

  it is also the progress reporter and an event bus subscriber of the pipeline,
  so the screen reflects the scan stage and new events as they happen.
  """

  def __init__(self, interval: float, max_events: int = 8, output: Path | None = None) -> None:
    self.interval = interval
    self.output = output
    self.cycle = 0
    self.devices: list[Device] = []
    self.report: ScanReport | None = None
    self.events: deque[Event] = deque(maxlen=max_events)
    self.alerts = 0
    self.fresh: set[str] = set()
    self._incoming: set[str] = set()
    self.stage_name = "starting"
    self.stage_total: int | None = None
    self.stage_done = 0
    self.started_at = time.monotonic()
    self.next_scan_at: float | None = None
    self.last_error: str | None = None

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
    if event.type in _FRESH_EVENTS and event.device_key:
      self._incoming.add(event.device_key)

  def update(self, report: ScanReport, inventory: Sequence[Device]) -> None:
    self.cycle += 1
    self.last_error = None
    self.report = report
    # what needs a decision first: untrusted online, then the rest online, then offline
    self.devices = sorted(inventory, key=lambda d: (d.status != DeviceStatus.ONLINE, d.trusted))
    self.fresh, self._incoming = self._incoming, set()
    self.stage_name = "idle"
    self.next_scan_at = time.monotonic() + self.interval

  def fail(self, message: str) -> None:
    """a scan failed (network down, interface gone): keep the last results and retry next cycle."""
    self.cycle += 1
    self.last_error = message
    self.stage_name = "idle"
    self.next_scan_at = time.monotonic() + self.interval

  # counters ->
  @property
  def online(self) -> int:
    return sum(d.status == DeviceStatus.ONLINE for d in self.devices)

  @property
  def untrusted_online(self) -> int:
    return sum(d.status == DeviceStatus.ONLINE and not d.trusted for d in self.devices)

  @property
  def uptime(self) -> float:
    return time.monotonic() - self.started_at

  # rendering ->
  def _state_row(self) -> tuple[RenderableType, RenderableType]:
    """the countdown to the next scan, or the stage the running scan is in, with a bar."""
    if self.next_scan_at is not None:
      left = max(0.0, self.next_scan_at - time.monotonic())
      label = Text.assemble(("next scan in ", "muted"), (f"{left:.0f}s", "bold"))
      bar = ProgressBar(total=self.interval, completed=self.interval - left, width=28, complete_style="cyan", finished_style="cyan")
      return label, bar
    progress = f" {self.stage_done}/{self.stage_total}" if self.stage_total else ""
    label = Text.assemble(("scanning · ", "warning"), (f"{self.stage_name}{progress}", "bold"))
    bar = ProgressBar(total=self.stage_total, completed=self.stage_done, width=28, complete_style="yellow", pulse_style="yellow")
    return label, bar

  def _header(self) -> Panel:
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(justify="right", no_wrap=True)

    scope = Text()
    if self.report is not None:
      scope.append(self.report.network, style="bold")
      if self.report.interface:
        scope.append(f" via {self.report.interface}", style="muted")
      scope.append(f" · {self.report.mode} mode", style="muted")
    else:
      scope.append("waiting for the first scan", style="muted")
    grid.add_row(scope, Text.assemble(("cycle ", "muted"), (str(self.cycle), "bold"), ("  up ", "muted"), fmt_duration(self.uptime)))

    counters = Text()
    counters.append("● ", style="ok")
    counters.append(f"{self.online} online", style="bold")
    counters.append(f"  ○ {len(self.devices) - self.online} offline", style="muted")
    if self.untrusted_online:
      counters.append(f"  ✗ {self.untrusted_online} untrusted", style="alert")
    elif self.devices:
      counters.append("  ✓ all trusted", style="ok")
    if self.alerts:
      counters.append(f"  {plural(self.alerts, 'alert')}", style="alert")
    last = Text(f"last scan {fmt_duration(self.report.duration)}", style="muted") if self.report else Text("")
    grid.add_row(counters, last)

    label, bar = self._state_row()
    state = Table.grid(padding=(0, 2))
    state.add_row(bar, label)
    grid.add_row(state, Text("ctrl+c to stop", style="muted"))
    if self.output is not None:
      grid.add_row(Text.assemble(("live web  ", "muted"), (str(self.output), "accent")), "")

    title = Text.assemble(("◉ ", "ok" if not self.untrusted_online else "alert"), ("beacon watch", "brand"))
    return Panel(grid, title=title, title_align="left", box=box.ROUNDED, border_style="alert" if self.untrusted_online else "grey50", padding=(0, 1))

  def _budget(self, height: int) -> tuple[int, int]:
    """how many device rows and events fit on a terminal `height` lines tall."""
    events = min(len(self.events), 3 if height < 30 else 5 if height < 45 else 8)
    used = _HEADER_ROWS + (1 if self.output else 0) + (1 if self.last_error else 0) + _TABLE_CHROME
    used += events + _EVENTS_CHROME if events else 0
    return max(3, height - used), events

  def _visible_devices(self, rows: int) -> tuple[list[Device], str | None]:
    """drop offline devices first, then the trusted tail, and say what was left out."""
    if len(self.devices) <= rows:
      return self.devices, None
    online = [d for d in self.devices if d.status == DeviceStatus.ONLINE]
    shown = online[:rows] if len(online) > rows else online + [d for d in self.devices if d.status != DeviceStatus.ONLINE][: rows - len(online)]
    hidden = len(self.devices) - len(shown)
    offline_hidden = sum(d.status != DeviceStatus.ONLINE for d in self.devices) - sum(d.status != DeviceStatus.ONLINE for d in shown)
    detail = f" ({offline_hidden} offline)" if offline_hidden else ""
    where = " or open the live web" if self.output else ""
    return shown, f"+{hidden} more not shown{detail} · enlarge the terminal{where}"

  def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
    rows, event_count = self._budget(options.height or options.size.height)
    parts: list[RenderableType] = [self._header()]
    if self.last_error:
      parts.append(Text(f"✗ last scan failed: {self.last_error} (retrying)", style="alert"))
    shown, caption = self._visible_devices(rows)
    parts.append(
      devices_table(
        shown,
        show_ports=any(d.open_ports for d in self.devices),
        width=options.max_width,
        fresh=self.fresh,
        caption=caption,
      )
    )
    if event_count:
      parts.append(events_table(list(self.events)[:event_count], title="latest events", relative=True))
    yield Group(*parts)

  def summary(self) -> RenderableType:
    """printed once when the user stops watching."""
    text = Text("■ ", style="muted")
    text.append("watch stopped", style="bold")
    text.append(f" after {plural(self.cycle, 'scan')} in {fmt_duration(self.uptime)}", style="muted")
    text.append(f" · {plural(self.alerts, 'alert')}", style="alert" if self.alerts else "muted")
    if self.devices:
      text.append(f" · {self.online} of {len(self.devices)} devices online", style="muted")
    lines: list[RenderableType] = [text]
    if self.output is not None:
      lines.append(Text.assemble(("→ ", "muted"), ("live web left at ", "muted"), (str(self.output), "accent")))
    if self.untrusted_online:
      lines.append(Text.assemble(("→ ", "muted"), ("beacon review", "cmd"), (f"  decide on the {plural(self.untrusted_online, 'untrusted device')}", "muted")))
    return Group(*lines)
