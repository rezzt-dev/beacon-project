 # import libraries ->
import math
from collections.abc import Collection, Mapping, Sequence
from datetime import datetime, timedelta

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from beacon.core.events import Event, EventType, Severity
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


def fmt_name(device: Device, fresh: bool = False) -> Text:
  """the alias and the tags; the hostname has a column of its own."""
  text = Text(device.alias or "—", style="bold" if device.alias else "muted")
  if device.is_gateway:
    text.append(" gateway", style="accent")
  if device.is_local:
    text.append(" this host", style="accent")
  if device.identity_id is not None:
    text.append(" ⛓", style="accent")
  if fresh:
    text.append(" ")
    text.append(" new ", style="new")
  return text


def fmt_hostname(device: Device) -> Text:
  return Text(device.hostname) if device.hostname else Text("—", style="muted")


def fmt_ago(value: datetime | None, now: datetime | None = None) -> str:
  """`just now`, `45s ago`, `12m ago`, `3h ago` or `2d ago`."""
  if value is None:
    return "—"
  seconds = max(0, int(((now or datetime.now(value.tzinfo)) - value).total_seconds()))
  if seconds < 10:
    return "just now"
  for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
    if seconds >= size:
      return f"{seconds // size}{unit} ago"
  return f"{seconds}s ago"


def plural(count: int, word: str) -> str:
  """`1 alert`, `3 alerts`."""
  return f"{count} {word}" + ("" if count == 1 else "s")


def fmt_duration(seconds: float) -> str:
  """`8.2s`, `4m 05s` or `2h 13m`."""
  if seconds < 60:
    return f"{seconds:.1f}s"
  minutes, secs = divmod(int(seconds), 60)
  if minutes < 60:
    return f"{minutes}m {secs:02d}s"
  return f"{minutes // 60}h {minutes % 60:02d}m"


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
SEVERITY_MARK = {Severity.INFO: "·", Severity.WARNING: "!", Severity.ALERT: "✗"}


def severity_text(severity: Severity) -> Text:
  """`✗ alert`, `! warning` or `· info`: the symbol keeps it readable without color."""
  return Text(f"{SEVERITY_MARK[severity]} {severity}", style=SEVERITY_STYLE[severity])


 # tables ->
# optional columns are dropped, in this order, as the terminal gets narrower; ip, mac, hostname and name always stay
_COLUMN_DROP_ORDER: tuple[tuple[str, int], ...] = (
  ("last seen", 175),
  ("os", 155),
  ("open ports", 140),
  ("latency", 125),
  ("vendor", 110),
  ("risk", 80),  # only present when asked for, so it outlasts the rest
)
# long enough for most dhcp names (`galaxy-a31-de-ramona`) without folding them
_HOSTNAME_WIDTH = 22


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
  fresh: Collection[str] = (),
  caption: str | None = None,
) -> Table:
  width = width or console.width
  shown = visible_columns(width, show_ports, show_risk=risks is not None)
  table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold", title_justify="left", expand=False)
  table.add_column("", width=1, no_wrap=True)
  table.add_column("ip", style="ip", no_wrap=True, min_width=15)
  table.add_column("mac", style="mac", no_wrap=True, min_width=17)
  longest = max((len(d.hostname) for d in devices if d.hostname), default=1)
  # on a narrow terminal the hostname folds instead of squeezing the risk column out
  table.add_column("hostname", style="host", overflow="fold", min_width=min(longest, _HOSTNAME_WIDTH if width >= 100 else 12))
  table.add_column("name", overflow="fold", min_width=9)
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
    row: list[RenderableType] = [status_marker(d), d.ip, d.mac or "—", fmt_hostname(d), fmt_name(d, fresh=d.key in fresh)]
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
  table.caption = caption or (None if devices else "no devices")
  table.caption_justify = "left"
  table.caption_style = "muted"
  return table


def events_table(events: Sequence[Event], title: str | None = "events", relative: bool = False) -> Table:
  """events with the severity spelled out; `relative` shows `3m ago` instead of the date (watch)."""
  table = Table(title=title, box=box.SIMPLE, header_style="bold", title_justify="left", title_style="bold")
  table.add_column("when" if relative else "time", style="muted", no_wrap=True, justify="right" if relative else "left")
  table.add_column("severity", no_wrap=True)
  table.add_column("type", no_wrap=True, style="muted")
  table.add_column("message", overflow="fold")
  for e in events:
    style = SEVERITY_STYLE[e.severity]
    when = fmt_ago(e.timestamp) if relative else fmt_time(e.timestamp)
    table.add_row(when, severity_text(e.severity), str(e.type), Text(e.message, style=style if e.severity != Severity.INFO else ""))
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
  """one line: how many devices, where, how and how long; problems are appended in color."""
  untrusted = sum(not d.trusted for d in report.devices)
  text = Text()
  text.append(plural(len(report.devices), "device"), style="bold")
  text.append(f" on {report.network}", style="")
  if report.interface:
    text.append(f" via {report.interface}")
  text.append(f" · {report.mode} mode · {fmt_duration(report.duration)}", style="muted")
  if untrusted:
    text.append(f" · {untrusted} untrusted", style="alert")
  if report.alerts:
    text.append(f" · {plural(len(report.alerts), 'alert')}", style="alert")
  if report.discarded:
    text.append(f" · {report.discarded} raw observations discarded", style="muted")
  return text


def scan_summary(report: ScanReport) -> RenderableType:
  """the closing block of `beacon scan`: what was found and the next command worth running."""
  ok = not report.alerts and not any(not d.trusted for d in report.devices)
  line = Text("✓ " if ok else "! ", style="ok" if ok else "warning")
  line.append_text(report_summary(report))
  steps: list[tuple[str, str]] = []
  untrusted = sum(not d.trusted for d in report.devices)
  if report.first_run:
    steps.append(("beacon review", "go through the devices above and build your known baseline"))
    steps.append(("beacon devices trust-all", "or accept every device as it is now"))
  elif untrusted:
    steps.append(("beacon review", f"decide on the {plural(untrusted, 'untrusted device')}, riskiest first"))
  if any(e.type == EventType.IDENTITY_CANDIDATE for e in report.events):
    steps.append(("beacon devices candidates", "a phone seems to be back with a new private mac"))
  if report.first_run and not report.ports_scanned:
    steps.append(("beacon scan -p top", "add the most common open ports and their risk"))
  if not steps:
    return line
  grid = Table.grid(padding=(0, 2))
  grid.add_column(no_wrap=True)
  grid.add_column(style="muted")
  for command, why in steps[:3]:
    grid.add_row(Text.assemble(("→ ", "muted"), (command, "cmd")), why)
  return Group(line, Text(""), grid)
