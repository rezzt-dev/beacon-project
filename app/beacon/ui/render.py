 # import libraries ->
import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from beacon.core.events import Event, Severity
from beacon.core.identity import IdentityMatch, fingerprint, score
from beacon.core.models import Device, DeviceStatus, Latency
from beacon.core.presence import (
  DAY_NAMES,
  MIN_PROFILE_DAYS,
  MIN_PROFILE_SESSIONS,
  Cell,
  PresenceProfile,
)
from beacon.core.report import ScanReport
from beacon.core.risk import RiskAssessment, RiskLevel
from beacon.scanners.network import InterfaceInfo
from beacon.ui.console import console


 # formatting helpers ->
def fmt_time(value: datetime | None, short: bool = False) -> str:
  if value is None:
    return "—"
  return value.astimezone().strftime("%m-%d %H:%M" if short else "%Y-%m-%d %H:%M:%S")


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
  if device.identity_id is not None:
    text.append(" ⛓", style="accent")
  return text


RISK_STYLE = {RiskLevel.LOW: "ok", RiskLevel.MEDIUM: "warning", RiskLevel.HIGH: "alert"}


def risk_text(assessment: RiskAssessment | None) -> Text:
  """`● high 65`: the level is spelled out so it reads without color."""
  if assessment is None:
    return Text("—", style="muted")
  return Text(f"● {assessment.level} {assessment.score}", style=RISK_STYLE[assessment.level])


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
  ("risk", 70),  # only present when asked for, so it outlasts the rest
)


def visible_columns(width: int, show_ports: bool = True, show_risk: bool = False) -> set[str]:
  """optional device table columns that fit a terminal `width` without truncating ips or macs."""
  hidden = {name for name, minimum in _COLUMN_DROP_ORDER if width < minimum}
  columns = {"last seen", "os", "latency", "vendor"} | ({"open ports"} if show_ports else set())
  columns |= {"risk"} if show_risk else set()
  return columns - hidden


def devices_table(
  devices: Sequence[Device],
  title: str | None = None,
  show_ports: bool = True,
  width: int | None = None,
  risks: Mapping[str, RiskAssessment] | None = None,
) -> Table:
  shown = visible_columns(width or console.width, show_ports, show_risk=risks is not None)
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
  if "risk" in shown:
    table.add_column("risk", no_wrap=True)
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
    if "risk" in shown:
      row.append(risk_text((risks or {}).get(d.key)))
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


def device_info(device: Device, risk: RiskAssessment | None = None) -> Table:
  """the label/value grid shared by `devices show` and the review card."""
  info = Table.grid(padding=(0, 2))
  info.add_column(style="muted", no_wrap=True)
  info.add_column()
  rows: list[tuple[str, RenderableType]] = [
    ("key", device.key),
    ("ip", ", ".join(device.ips) if len(device.ips) > 1 else device.ip),
    ("mac", device.mac or "—"),
    ("alias", Text(device.alias or "—")),
    ("hostname", f"{device.hostname} ({device.hostname_source})" if device.hostname else "—"),
    ("vendor", device.display_vendor),
    ("os estimate", f"{device.os_guess} (ttl {device.ttl})" if device.os_guess else "—"),
    ("latency", fmt_latency(device.latency)),
    ("status", Text(str(device.status), style="ok" if device.status == DeviceStatus.ONLINE else "muted")),
    ("trusted", Text("yes", style="ok") if device.trusted else Text("no", style="alert")),
    ("first seen", fmt_time(device.first_seen)),
    ("last seen", fmt_time(device.last_seen)),
  ]
  if device.services:
    rows.insert(5, ("services", Text(", ".join(device.services))))
  if risk is not None:
    rows.append(("risk", risk_reasons(risk)))
  for label, value in rows:
    info.add_row(label, value)
  return info


def risk_reasons(assessment: RiskAssessment) -> Text:
  text = risk_text(assessment)
  if assessment.reasons:
    text.append("  " + " · ".join(r.text for r in assessment.reasons), style="muted")
  if not assessment.ports_known:
    text.append("  (ports not scanned)", style="muted")
  return text


def identity_block(device: Device, members: Sequence[Device]) -> RenderableType:
  """the macs of one physical device with when each was used, and why the others were linked."""
  table = Table(box=box.SIMPLE, header_style="bold", title="identity", title_justify="left")
  table.add_column("mac", style="mac", no_wrap=True)
  table.add_column("ip", no_wrap=True)
  table.add_column("name", overflow="fold")
  table.add_column("first seen", style="muted", no_wrap=True)
  table.add_column("last seen", style="muted", no_wrap=True)
  own = fingerprint(device)
  everyone = sorted([device, *members], key=lambda d: d.first_seen.timestamp() if d.first_seen else math.inf)
  notes: list[RenderableType] = []
  for member in everyone:
    table.add_row(
      member.mac or member.ip,
      member.ip,
      Text(member.alias or member.hostname or "—"),
      fmt_time(member.first_seen, short=True),
      fmt_time(member.last_seen, short=True),
    )
    if member.key != device.key and (evidence := score(own, fingerprint(member))[1]):
      notes.append(Text(f"{member.mac or member.ip}: {', '.join(evidence)}", style="muted"))
  return Group(table, *notes)


def device_detail(
  device: Device,
  events: Sequence[Event],
  risk: RiskAssessment | None = None,
  members: Sequence[Device] = (),
  presence: RenderableType | None = None,
) -> RenderableType:
  parts: list[RenderableType] = [
    Panel(device_info(device, risk), title=Text(device.display_name, style="bold"), title_align="left")
  ]
  if members:
    parts.append(identity_block(device, members))
  if device.open_ports:
    ports = Table(box=box.SIMPLE, header_style="bold", title="open ports", title_justify="left")
    ports.add_column("port", justify="right")
    ports.add_column("service")
    ports.add_column("banner", overflow="fold")
    for p in device.open_ports:
      ports.add_row(f"{p.port}/{p.protocol}", p.service or "—", p.banner or "—")
    parts.append(ports)
  if presence is not None:
    parts.append(presence)
  if events:
    parts.append(events_table(events, title="recent events"))
  return Group(*parts)


def review_card(device: Device, risk: RiskAssessment, pending: Sequence[Event], position: int, total: int) -> Panel:
  """one device to decide on: facts, why it is risky and the events that raised it."""
  body: list[RenderableType] = [device_info(device, risk)]
  if pending:
    body.append(Text(""))
    body.extend(Text(f"{e.severity}  {e.message}", style=SEVERITY_STYLE[e.severity]) for e in pending[:3])
  title = Text(f"{position}/{total}  ", style="muted")
  title.append(device.display_name, style="bold")
  return Panel(Group(*body), title=title, title_align="left")


def review_table(rows: Sequence[tuple[Device, RiskAssessment]]) -> Table:
  """pending devices with their risk and the reasons, sized so the reasons keep most of the width."""
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
  table.add_column("risk", no_wrap=True)
  table.add_column("ip", style="ip", no_wrap=True, min_width=15)
  table.add_column("name", overflow="fold", max_width=22)
  table.add_column("why", overflow="fold", ratio=1)
  for device, risk in rows:
    reasons = " · ".join(r.text for r in risk.reasons) or "nothing notable"
    if not risk.ports_known:
      reasons += " · ports not scanned"
    table.add_row(risk_text(risk), device.ip, Text(device.alias or device.hostname or "—"), Text(reasons, style="muted"))
  return table


 # identity candidates ->
def candidates_table(matches: Sequence[IdentityMatch], devices: Mapping[str, Device]) -> Table:
  table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
  for column in ("new mac", "candidate", "score", "link", "evidence"):
    table.add_column(column, overflow="fold", no_wrap=column in ("new mac", "score", "link"))
  for m in matches:
    old = devices[m.candidate_key]
    style = "accent" if m.level == "probable" else "warning"
    candidate = Text(m.candidate_key, style="mac")
    if old.alias or old.hostname:
      candidate.append(f"  {old.alias or old.hostname}")
    table.add_row(Text(m.new_key, style="mac"), candidate, f"{m.score:.2f}", Text(str(m.level), style=style), Text("; ".join(m.evidence)))
  return table


 # presence ->
_HEAT = ((0.75, "█"), (0.5, "▓"), (0.25, "▒"), (0.0001, "░"))


def learning_text(profile: PresenceProfile) -> Text:
  """how far a device is from having a usable profile, so an empty heatmap is never a mystery."""
  return Text(
    f"still learning: {max(0, min(profile.days, MIN_PROFILE_DAYS))}/{MIN_PROFILE_DAYS} days · "
    f"{min(profile.sessions, MIN_PROFILE_SESSIONS)}/{MIN_PROFILE_SESSIONS} sessions "
    f"(anomalies need {MIN_PROFILE_DAYS} days and {MIN_PROFILE_SESSIONS} sessions)",
    style="muted",
  )


def presence_heatmap(profile: PresenceProfile) -> RenderableType:
  """7 weekdays x 24 hours: how often the device was present in each cell, readable without color."""
  grid = Table.grid(padding=(0, 1))
  grid.add_column(style="muted")
  grid.add_column(no_wrap=True)
  grid.add_row("", Text("".join(f"{h:02d}" if h % 3 == 0 else "  " for h in range(24)), style="muted"))
  for day, name in enumerate(DAY_NAMES):
    line = Text()
    for hour in range(24):
      freq = profile.frequency(day, hour) or 0.0
      mark = next((char for floor, char in _HEAT if freq >= floor), "·")
      line.append(mark + " ", style="ok" if freq else "muted")
    grid.add_row(name, line)
  parts: list[RenderableType] = [Text("presence", style="bold"), grid]
  if not profile.ready:
    parts.append(learning_text(profile))
  return Group(*parts)


def timeline_table(
  rows: Sequence[tuple[Device, Sequence[Cell]]], start: datetime, end: datetime, name_width: int = 24
) -> Table:
  """one row per device, one character per time slice: █ present, ▒ partly, · absent."""
  buckets = len(rows[0][1]) if rows else 0
  table = Table(box=box.SIMPLE, header_style="bold", show_header=True, pad_edge=False)
  table.add_column("", width=1, no_wrap=True)
  table.add_column("device", max_width=name_width, overflow="ellipsis", no_wrap=True)
  table.add_column(_axis(start, end, buckets), no_wrap=True)
  marks = {Cell.PRESENT: ("█", "ok"), Cell.PARTIAL: ("▒", "info"), Cell.ABSENT: ("·", "muted")}
  for device, cells in rows:
    line = Text()
    for cell in cells:
      char, style = marks[cell]
      line.append(char, style=style)
    table.add_row(status_marker(device), Text(device.alias or device.hostname or device.ip), line)
  return table


def _axis(start: datetime, end: datetime, buckets: int) -> str:
  """time labels every few columns, as `hh:mm` for a day or so and `dd/mm` for longer windows."""
  if buckets <= 0:
    return ""
  fmt = "%H:%M" if end - start <= timedelta(hours=36) else "%d/%m"
  slot = (end - start) / buckets
  axis = [" "] * buckets
  for index in range(0, buckets, 8):
    label = (start + index * slot).astimezone().strftime(fmt)
    axis[index : index + len(label)] = list(label)[: buckets - index]
  return "".join(axis)[:buckets]


def bucket_count(window: timedelta, step: timedelta, available: int) -> int:
  """as many slices as `step` asks for, merged until they fit the terminal (never fewer than 8)."""
  return max(8, min(math.ceil(window / step), available))


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
