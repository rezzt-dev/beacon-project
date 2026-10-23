 # import libraries ->
from collections.abc import Sequence
from datetime import datetime

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from beacon.core.events import Event, Severity
from beacon.core.models import Device, DeviceStatus, Latency
from beacon.core.report import ScanReport
from beacon.scanners.network import InterfaceInfo
from beacon.ui.console import console


 # formatting helpers ->
def fmt_time(value: datetime | None) -> str:
  return value.astimezone().strftime("%Y-%m-%d %H:%M:%S") if value else "—"


def fmt_latency(latency: Latency | None) -> Text:
  if latency is None:
    return Text("—", style="muted")
  if latency.avg is None:
    return Text("no reply", style="muted")
  style = "ok" if latency.avg < 20 else "warning" if latency.avg < 100 else "alert"
  text = Text(f"{latency.avg:.1f} ms", style=style)
  if latency.jitter is not None:
    text.append(f" ±{latency.jitter:.1f}", style="muted")
  if latency.loss:
    text.append(f" {latency.loss:.0f}% loss", style="warning")
  return text


def fmt_ports(device: Device, limit: int = 8) -> Text:
  ports = device.open_ports
  if not ports:
    return Text("—", style="muted")
  shown = ", ".join(str(p.port) for p in ports[:limit])
  return Text(shown + (f" +{len(ports) - limit}" if len(ports) > limit else ""))


def fmt_name(device: Device) -> Text:
  text = Text(device.alias or device.hostname or "—", style="bold" if device.alias else "")
  if device.is_gateway:
    text.append(" gateway", style="accent")
  if device.is_local:
    text.append(" this host", style="accent")
  return text


def status_marker(device: Device) -> Text:
  if device.status == DeviceStatus.OFFLINE:
    return Text("○", style="muted")
  return Text("●", style="ok" if device.trusted else "alert")


SEVERITY_STYLE = {Severity.INFO: "info", Severity.WARNING: "warning", Severity.ALERT: "alert"}


 # tables ->
# optional columns are dropped, in this order, as the terminal gets narrower; ip, mac and name always stay
_COLUMN_DROP_ORDER: tuple[tuple[str, int], ...] = (
  ("last seen", 150),
  ("os", 135),
  ("open ports", 120),
  ("latency", 105),
  ("vendor", 90),
)


def visible_columns(width: int, show_ports: bool = True) -> set[str]:
  """optional device table columns that fit a terminal `width` without truncating ips or macs."""
  hidden = {name for name, minimum in _COLUMN_DROP_ORDER if width < minimum}
  columns = {"last seen", "os", "latency", "vendor"} | ({"open ports"} if show_ports else set())
  return columns - hidden


def devices_table(
  devices: Sequence[Device], title: str | None = None, show_ports: bool = True, width: int | None = None
) -> Table:
  shown = visible_columns(width or console.width, show_ports)
  table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold", title_justify="left", expand=False)
  table.add_column("", width=1, no_wrap=True)
  table.add_column("ip", style="ip", no_wrap=True, min_width=15)
  table.add_column("mac", style="mac", no_wrap=True, min_width=17)
  table.add_column("name", overflow="fold")
  if "vendor" in shown:
    table.add_column("vendor", overflow="ellipsis", no_wrap=True, max_width=30)
  if "os" in shown:
    table.add_column("os (ttl)", overflow="ellipsis", no_wrap=True, max_width=20)
  if "latency" in shown:
    table.add_column("latency", no_wrap=True)
  if "open ports" in shown:
    table.add_column("open ports", overflow="fold", max_width=30)
  if "last seen" in shown:
    table.add_column("last seen", style="muted", no_wrap=True)

  for d in devices:
    row: list[RenderableType] = [status_marker(d), d.ip, d.mac or "—", fmt_name(d)]
    if "vendor" in shown:
      row.append(Text(d.display_vendor, style="" if d.vendor else "muted"))
    if "os" in shown:
      row.append(Text(d.os_guess or "—", style="" if d.os_guess else "muted"))
    if "latency" in shown:
      row.append(fmt_latency(d.latency))
    if "open ports" in shown:
      row.append(fmt_ports(d))
    if "last seen" in shown:
      row.append(fmt_time(d.last_seen))
    table.add_row(*row)
  if not devices:
    table.caption = "no devices"
  return table


def events_table(events: Sequence[Event], title: str | None = "events") -> Table:
  table = Table(title=title, box=box.SIMPLE, header_style="bold", title_justify="left")
  table.add_column("time", style="muted", no_wrap=True)
  table.add_column("severity", no_wrap=True)
  table.add_column("type", no_wrap=True)
  table.add_column("message", overflow="fold")
  for e in events:
    style = SEVERITY_STYLE[e.severity]
    table.add_row(fmt_time(e.timestamp), Text(str(e.severity), style=style), str(e.type), Text(e.message, style=style if e.severity != Severity.INFO else ""))
  return table


def interfaces_table(interfaces: Sequence[InterfaceInfo], default: InterfaceInfo | None) -> Table:
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
  for column in ("", "interface", "address", "network", "mac", "gateway"):
    table.add_column(column, no_wrap=True)
  for i in interfaces:
    marker = Text("★", style="accent") if default and i.name == default.name and i.ip == default.ip else ""
    table.add_row(marker, i.name, str(i.ip), str(i.network), i.mac or "—", str(i.gateway) if i.gateway else "—")
  return table


def device_detail(device: Device, events: Sequence[Event]) -> RenderableType:
  info = Table.grid(padding=(0, 2))
  info.add_column(style="muted", no_wrap=True)
  info.add_column()
  rows: list[tuple[str, RenderableType]] = [
    ("key", device.key),
    ("ip", ", ".join(device.ips) if len(device.ips) > 1 else device.ip),
    ("mac", device.mac or "—"),
    ("alias", device.alias or "—"),
    ("hostname", f"{device.hostname} ({device.hostname_source})" if device.hostname else "—"),
    ("vendor", device.display_vendor),
    ("os estimate", f"{device.os_guess} (ttl {device.ttl})" if device.os_guess else "—"),
    ("latency", fmt_latency(device.latency)),
    ("status", Text(str(device.status), style="ok" if device.status == DeviceStatus.ONLINE else "muted")),
    ("trusted", Text("yes", style="ok") if device.trusted else Text("no", style="alert")),
    ("first seen", fmt_time(device.first_seen)),
    ("last seen", fmt_time(device.last_seen)),
  ]
  for label, value in rows:
    info.add_row(label, value)

  parts: list[RenderableType] = [Panel(info, title=f"[bold]{device.display_name}[/bold]", title_align="left")]
  if device.open_ports:
    ports = Table(box=box.SIMPLE, header_style="bold", title="open ports", title_justify="left")
    ports.add_column("port", justify="right")
    ports.add_column("service")
    ports.add_column("banner", overflow="fold")
    for p in device.open_ports:
      ports.add_row(f"{p.port}/{p.protocol}", p.service or "—", p.banner or "—")
    parts.append(ports)
  if events:
    parts.append(events_table(events, title="recent events"))
  return Group(*parts)


 # summaries ->
def report_summary(report: ScanReport) -> Text:
  online = len(report.devices)
  untrusted = sum(not d.trusted for d in report.devices)
  text = Text()
  text.append(f"{online} devices", style="bold")
  text.append(f" on {report.network} via {report.interface} ({report.mode} mode) in {report.duration:.1f}s")
  if untrusted:
    text.append(f" · {untrusted} untrusted", style="alert")
  if report.discarded:
    text.append(f" · {report.discarded} raw observations discarded", style="muted")
  return text
