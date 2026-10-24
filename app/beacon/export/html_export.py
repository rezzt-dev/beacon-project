 # import libraries ->
import base64
import hashlib
import ipaddress
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from html import escape
from importlib import resources
from typing import Any
from urllib.parse import quote

from beacon import __version__
from beacon.core.events import Event, Severity
from beacon.core.exposure import is_sensitive
from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.risk import RiskAssessment, RiskLevel, assess


 # template ->
# self-contained on purpose: no fonts, scripts or images from the network, so the page works
# offline and a hostile hostname can never pull in a remote resource. the stylesheet and the
# script live in `assets/` and are inlined (and pinned by hash in the csp) when a report is written
_ASSETS = resources.files("beacon.export") / "assets"
_STYLE = (_ASSETS / "report.css").read_text(encoding="utf-8")
_SCRIPT = (_ASSETS / "report.js").read_text(encoding="utf-8")


def _csp_hash(source: str) -> str:
  return "'sha256-" + base64.b64encode(hashlib.sha256(source.encode()).digest()).decode() + "'"


# only the exact inline style and script above may run: an injected tag would be blocked even
# if an escaping bug ever let one through
_CSP = (
  f"default-src 'none'; style-src {_csp_hash(_STYLE)}; script-src {_csp_hash(_SCRIPT)}; "
  "img-src data:; base-uri 'none'; form-action 'none'"
)
_LOGO = (
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">'
  '<circle cx="12" cy="12" r="2.2" fill="currentColor" stroke="none"/><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4"/>'
  '<path d="M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2"/></svg>'
)
_RISK_BADGE = {RiskLevel.LOW: "ok", RiskLevel.MEDIUM: "warn", RiskLevel.HIGH: "alert"}
_SEVERITY_BADGE = {Severity.INFO: "", Severity.WARNING: "warn", Severity.ALERT: "alert"}
_PORTS_SHOWN = 8
_EMPTY = '<span class="faint">—</span>'


 # html helpers ->
def _e(value: object) -> str:
  return escape(str(value), quote=True)


def _iso(value: datetime | None) -> str:
  return value.isoformat() if value else ""


def _utc(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
  return value.strftime(fmt) + " utc" if value else "—"


def _ip_order(ip: str) -> int:
  try:
    return int(ipaddress.ip_address(ip))
  except ValueError:
    return 0


def _favicon(attention: bool) -> str:
  color = "#d1453b" if attention else "#3d8bfd"
  svg = (
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.5" fill="none" '
    f'stroke="{color}" stroke-width="1.6"/><circle cx="8" cy="8" r="2.6" fill="{color}"/></svg>'
  )
  return "data:image/svg+xml," + quote(svg)


def _plural(count: int, word: str) -> str:
  return f"{count} {word}" + ("" if count == 1 else "s")


 # device rows ->
def _sort_devices(devices: Sequence[Device]) -> list[Device]:
  return sorted(devices, key=lambda d: (d.status != DeviceStatus.ONLINE, _ip_order(d.ip)))


def _hostname_cell(d: Device) -> str:
  """the resolved name and, below, where it came from (dns, router, mdns, netbios)."""
  if not d.hostname:
    return _EMPTY
  source = f'<div class="second">via {_e(d.hostname_source)}</div>' if d.hostname_source else ""
  return f'<div class="host">{_e(d.hostname)}</div>{source}'


def _device_cell(d: Device) -> str:
  """alias and tags on the first line, the vendor below; a device without alias leads with its vendor."""
  name = d.alias
  vendor = f'<span class="{"" if d.vendor else "muted"}">{_e(d.display_vendor)}</span>'
  line = f'<span class="name">{_e(name)}</span>' if name else vendor
  for flag, label in ((d.is_gateway, "gateway"), (d.is_local, "this host"), (d.identity_id is not None, "linked")):
    if flag:
      line += f'<span class="tag">{label}</span>'
  return f'<div class="line">{line}</div>' + (f'<div class="second">{vendor}</div>' if name else "")


def _latency_cell(d: Device) -> tuple[str, str]:
  latency = d.latency
  if latency is None:
    return _EMPTY, "1e9"
  if latency.avg is None:
    return '<span class="muted">no reply</span>', "1e8"
  css = "lat-ok" if latency.avg < 20 else "lat-warn" if latency.avg < 100 else "lat-bad"
  text = f'<span class="{css}">{latency.avg:.1f} ms</span>'
  if latency.jitter is not None:
    text += f' <span class="muted">±{latency.jitter:.1f}</span>'
  if latency.loss:
    text += f' <span class="lat-warn">{latency.loss:.0f}% loss</span>'
  return text, f"{latency.avg}"


def _ports_cell(d: Device) -> str:
  ports = d.open_ports
  if not ports:
    return _EMPTY
  chips = "".join(
    f'<span class="chip{" risky" if is_sensitive(p) else ""}" title="{_e(p.service or "unknown service")}">{p.port}</span>'
    for p in ports[:_PORTS_SHOWN]
  )
  if len(ports) > _PORTS_SHOWN:
    chips += f'<span class="chip">+{len(ports) - _PORTS_SHOWN}</span>'
  return f'<div class="ports">{chips}</div>'


def _risk_badge(risk: RiskAssessment) -> str:
  reasons = " · ".join([*(r.text for r in risk.reasons), *risk.notes]) or "nothing notable"
  # without port data a low score is "unknown", never a clean bill of health
  unknown = "" if risk.complete else ' <abbr title="ports never examined: exposure unknown">?</abbr>'
  return f'<span class="badge {_RISK_BADGE[risk.level]}" title="{_e(reasons)}">{risk.level} {risk.score}{unknown}</span>'


def _device_row(d: Device, risk: RiskAssessment, order: int) -> str:
  online = d.status == DeviceStatus.ONLINE
  dot = "on" if online and d.trusted else "bad" if online else ""
  latency, latency_order = _latency_cell(d)
  os_text = (
    f'{_e(d.os_guess)}{f" <span class=muted>ttl {d.ttl}</span>" if d.ttl else ""}' if d.os_guess else _EMPTY
  )
  search = " ".join(
    str(part)
    for part in (d.ip, *d.ips, d.mac, d.alias, d.hostname, d.display_vendor, d.os_guess, *(p.port for p in d.open_ports), *(p.service for p in d.open_ports))
    if part
  ).lower()
  classes = " ".join(c for c in ("is-offline" if not online else "", "is-untrusted" if not d.trusted else "") if c)
  state = f'<span class="status"><span class="dot {dot}"></span>{d.status}</span>'
  if not d.trusted:
    state += ' <span class="badge alert">untrusted</span>'
  cells = (
    ("state", state, str(0 if online and not d.trusted else 1 if online else 2)),
    ("address", f'<div class="mono">{_e(d.ip)}</div><div class="second mono">{_e(d.mac or "no mac")}</div>', str(_ip_order(d.ip))),
    ("hostname", _hostname_cell(d), d.hostname or "~"),
    ("device", _device_cell(d), None),
    ("os", os_text, None),
    ("latency", latency, latency_order),
    ("open ports", _ports_cell(d), str(len(d.open_ports))),
    ("risk", _risk_badge(risk), str(risk.score)),
    (
      "last seen",
      f'<time datetime="{_iso(d.last_seen)}" data-rel>{_utc(d.last_seen)}</time>' if d.last_seen else _EMPTY,
      str(int(d.last_seen.timestamp())) if d.last_seen else "0",
    ),
  )
  tds = "".join(
    f'<td data-label="{label}"'
    + (f' data-v="{_e(sort_value)}"' if sort_value is not None else "")
    + (' class="is-empty"' if body == _EMPTY else "")
    + f'><div class="cell">{body}</div></td>'
    for label, body, sort_value in cells
  )
  return (
    f'<tr data-key="{_e(d.key)}" data-order="{order}" data-status="{d.status}" data-trusted="{int(d.trusted)}" '
    f'data-ports="{len(d.open_ports)}" data-q="{_e(search)}"' + (f' class="{classes}"' if classes else "") + f">{tds}</tr>"
  )


_COLUMNS = (
  ("state", "num"), ("address", "num"), ("hostname", "text"), ("device", "text"), ("os (ttl)", "text"),
  ("latency", "num"), ("open ports", "num"), ("risk", "num"), ("last seen", "num"),
)


def _devices_section(devices: list[Device], risks: dict[str, RiskAssessment], counts: dict[str, int]) -> str:
  head = "".join(f'<th scope="col" data-type="{kind}"><button type="button">{label}</button></th>' for label, kind in _COLUMNS)
  filters = "".join(
    f'<button type="button" data-filter="{key}" aria-pressed="{str(key == "all").lower()}">{label}<span class="n">{counts[key]}</span></button>'
    for key, label in (("all", "all"), ("online", "online"), ("untrusted", "untrusted"), ("ports", "open ports"), ("offline", "offline"))
  )
  if devices:
    rows = "".join(_device_row(d, risks[d.key], i) for i, d in enumerate(devices))
    body = (
      f'<div class="table-wrap"><table id="devices"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>'
      '<p class="empty" id="devices-empty" hidden><strong id="devices-empty-text">no device matches this filter</strong>'
      '<button type="button" class="link" id="clear-filters">show every device</button></p></div>'
    )
  else:
    body = (
      '<div class="table-wrap"><p class="empty"><strong>no devices yet</strong>'
      "the table fills in after the first scan; check the interface with <code>beacon interfaces</code> "
      "if it stays empty.</p></div>"
    )
  return (
    '<section aria-labelledby="devices-title">'
    f'<div class="toolbar"><h2 id="devices-title">devices <span class="count">{len(devices)}</span></h2>'
    f'<div class="seg needs-js" role="group" aria-label="filter devices">{filters}</div><span class="spacer"></span>'
    '<input class="search needs-js" id="q" type="search" placeholder="search ip, mac, hostname, vendor, port" '
    'aria-label="search devices" autocomplete="off" spellcheck="false"></div>'
    '<p class="news" id="news" hidden><span id="news-text"></span>'
    '<button type="button" class="link" id="mark-seen">mark as seen</button></p>'
    f"{body}</section>"
  )


 # attention and events ->
def _attention_item(d: Device, risk: RiskAssessment) -> str:
  name = d.alias or d.hostname
  label = f"<strong>{_e(name)}</strong>" if name else f'<span class="muted">{_e(d.display_vendor)}</span>'
  why = " · ".join(r.text for r in risk.reasons if r.text != "not trusted") or "not reviewed yet"
  return f'<li>{_risk_badge(risk)}<span class="mono">{_e(d.ip)}</span>{label}<span class="why">{_e(why)}</span></li>'


def _attention_section(devices: list[Device], risks: dict[str, RiskAssessment]) -> str:
  pending = sorted(
    (d for d in devices if not d.trusted and d.status == DeviceStatus.ONLINE),
    key=lambda d: (-risks[d.key].score, _ip_order(d.ip)),
  )
  if not pending:
    return ""
  shown = 6
  items = "".join(_attention_item(d, risks[d.key]) for d in pending[:shown])
  more = f" and {len(pending) - shown} more" if len(pending) > shown else ""
  return (
    '<section class="attention" aria-labelledby="attention-title">'
    f'<h2 id="attention-title">{_plural(len(pending), "online device")} not trusted yet{more}</h2>'
    f"<ul>{items}</ul>"
    "<p>decide on them one by one with <code>beacon review</code>, or trust one with "
    "<code>beacon devices trust &lt;ip&gt;</code>.</p></section>"
  )


def _event_item(e: Event) -> str:
  badge = _SEVERITY_BADGE[e.severity]
  return (
    f'<li data-sev="{e.severity}" data-ts="{_iso(e.timestamp)}">'
    f'<time class="muted" datetime="{_iso(e.timestamp)}" data-clock>{_utc(e.timestamp, "%m-%d %H:%M:%S")}</time>'
    f'<span><span class="badge {badge}">{e.severity}</span></span>'
    f'<span class="mono muted">{_e(e.type)}</span><span class="msg">{_e(e.message)}</span></li>'
  )


def _events_section(events: Sequence[Event]) -> str:
  if not events:
    body = (
      '<p class="empty events-list"><strong>no events yet</strong>'
      "new devices, disconnections, ip changes and new open ports will show up here.</p>"
    )
    filters = ""
  else:
    body = f'<ol class="events-list">{"".join(_event_item(e) for e in events)}</ol>'
    counts = Counter(str(e.severity) for e in events)
    filters = "".join(
      f'<button type="button" data-sev-filter="{key}" aria-pressed="{str(key == "all").lower()}">{key}<span class="n">{counts[key] if key != "all" else len(events)}</span></button>'
      for key in ("all", "alert", "warning", "info")
    )
    filters = f'<div class="seg needs-js" role="group" aria-label="filter events by severity">{filters}</div>'
  return (
    '<section aria-labelledby="events-title">'
    f'<div class="toolbar"><h2 id="events-title">latest events <span class="count">{len(events)}</span></h2>{filters}</div>'
    f"{body}</section>"
  )


 # page ->
def _anonymized(meta: dict[str, Any]) -> str:
  if not meta.get("anonymized"):
    return ""
  return "<span>identifiers are pseudonymized: this hides them, it does not make the report anonymous</span>"


def _headline(devices: list[Device], counts: dict[str, int], untrusted_online: int, events: Sequence[Event]) -> str:
  if not devices:
    return '<h1 class="headline">waiting for the first scan</h1><p class="sub">nothing has been discovered on this network yet.</p>'
  text = f"<strong>{counts['online']} of {_plural(len(devices), 'device')}</strong> online"
  if untrusted_online:
    text += f', <span class="bad">{untrusted_online} not trusted</span>'
  else:
    text += ', <span class="good">all of them trusted</span>' if counts["online"] else ""
  alerts = sum(e.severity == Severity.ALERT for e in events)
  details = [
    _plural(counts["ports"], "device") + " with open ports",
    f"{counts['offline']} offline",
    f"{_plural(alerts, 'alert')} in the latest events" if events else "no events yet",
  ]
  return f'<h1 class="headline">{text}</h1><p class="sub">{" · ".join(details)}</p>'


def render_html(devices: Sequence[Device], events: Sequence[Event], meta: dict[str, Any]) -> str:
  generated = utcnow()
  ordered = _sort_devices(devices)
  ports_known = meta.get("ports_known", any(d.open_ports for d in devices))
  # the caller passes the shared assessment (cli, api); a bare render falls back to the same rules
  risks = meta.get("risks") or {d.key: assess(d, events, ports_known, now=generated) for d in ordered}
  counts = {
    "all": len(ordered),
    "online": sum(d.status == DeviceStatus.ONLINE for d in ordered),
    "offline": sum(d.status != DeviceStatus.ONLINE for d in ordered),
    "untrusted": sum(not d.trusted for d in ordered),
    "ports": sum(bool(d.open_ports) for d in ordered),
  }
  untrusted_online = sum(not d.trusted and d.status == DeviceStatus.ONLINE for d in ordered)

  refresh = int(meta["refresh"]) if meta.get("refresh") else 0
  network = meta.get("network")
  scope = " · ".join(
    _e(part)
    for part in (network, meta.get("interface"), f"{meta['mode']} mode" if meta.get("mode") else None)
    if part
  )
  title = ("(" + str(untrusted_online) + ") " if untrusted_online else "") + "beacon" + (f" · {network}" if network else "")
  if refresh:
    status = (
      '<div class="live" id="live" data-live="live"><span class="signal" aria-hidden="true"></span>'
      '<span class="live-label" id="live-label">live</span>'
      f'<span class="muted" id="live-detail">generated {_utc(generated)}, refreshes every {refresh}s</span>'
      '<button type="button" class="btn needs-js" id="pause" aria-pressed="false" title="pause auto-refresh (p)">pause</button></div>'
    )
    meter = '<div class="meter needs-js" aria-hidden="true"><span id="meter"></span></div>'
    hints = "<span><kbd>/</kbd> search · <kbd>p</kbd> pause</span>"
  else:
    status = (
      '<div class="live" data-live="snapshot"><span class="signal" aria-hidden="true"></span>'
      f'<span class="live-label">snapshot</span><span class="muted">generated <time datetime="{_iso(generated)}" data-clock>{_utc(generated)}</time></span></div>'
    )
    hints = "<span><kbd>/</kbd> search</span>"
    meter = ""
  duration = f' data-duration="{float(meta["duration"]):.1f}"' if meta.get("duration") else ""

  return f"""<!doctype html>
<html lang="en" data-generated="{_iso(generated)}" data-refresh="{refresh}"{duration}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
{f'<noscript><meta http-equiv="refresh" content="{refresh}"></noscript>' if refresh else ""}
<title>{_e(title)}</title>
<link rel="icon" href="{_favicon(bool(untrusted_online))}">
<style>{_STYLE}</style>
</head>
<body>
<header class="bar"><div class="bar-inner">
<div class="brand">{_LOGO}beacon</div>
<div class="scope">{scope or "local network"}</div>
{status}
</div>{meter}</header>
<main>
{_headline(ordered, counts, untrusted_online, events)}
{_attention_section(ordered, risks)}
{_devices_section(ordered, risks, counts)}
{_events_section(events)}
</main>
<footer><span>beacon {_e(__version__)}</span><span>values come from the network and are shown as plain text</span>{_anonymized(meta)}{hints}</footer>
<script>{_SCRIPT}</script>
</body>
</html>
"""
