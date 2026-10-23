 # import libraries ->
from collections.abc import Sequence
from html import escape
from typing import Any

from beacon import __version__
from beacon.core.events import Event
from beacon.core.models import Device, DeviceStatus, utcnow


 # template ->
_STYLE = """
:root { --bg:#f7f7f5; --panel:#ffffff; --text:#1d1d1b; --muted:#6b6b66; --line:#e3e3de;
        --ok:#1f7a4d; --warn:#9a6700; --alert:#b42318; --chip:#efefea; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#141413; --panel:#1d1d1b; --text:#ecebe6; --muted:#9b9a94; --line:#2f2f2c;
          --ok:#4cc38a; --warn:#e3b341; --alert:#f47067; --chip:#2a2a27; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--text);
       font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1200px; margin:0 auto; }
h1 { font-size:20px; margin:0 0 4px; letter-spacing:.02em; }
.meta { color:var(--muted); margin-bottom:20px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:20px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.card b { display:block; font-size:22px; }
.card span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
.wrap { overflow-x:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; white-space:nowrap; }
th { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
tr:last-child td { border-bottom:none; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }
.chip { display:inline-block; background:var(--chip); border-radius:4px; padding:0 6px; margin:1px 2px 1px 0; font-size:12px; }
.online { color:var(--ok); } .offline { color:var(--muted); }
.untrusted { color:var(--alert); font-weight:600; } .muted { color:var(--muted); }
.sev-alert { color:var(--alert); } .sev-warning { color:var(--warn); } .sev-info { color:var(--muted); }
h2 { font-size:15px; margin:28px 0 10px; }
"""


 # html renderer ->
def _cell(value: object, css: str = "") -> str:
  text = "—" if value in (None, "") else escape(str(value))
  return f'<td class="{css}">{text}</td>' if css else f"<td>{text}</td>"


def _device_row(d: Device) -> str:
  latency = d.latency
  ports = "".join(f'<span class="chip">{p.port}{"/" + escape(p.service) if p.service else ""}</span>' for p in d.open_ports)
  name = d.alias or d.hostname
  tags = " (gateway)" if d.is_gateway else " (this host)" if d.is_local else ""
  return (
    "<tr>"
    + _cell(d.ip)
    + f"<td><code>{escape(d.mac or '—')}</code></td>"
    + _cell(f"{name}{tags}" if name else tags.strip(" ()") or None)
    + _cell(d.display_vendor, "muted" if not d.vendor else "")
    + _cell(d.os_guess)
    + _cell(f"{latency.avg} ms" if latency and latency.avg is not None else None)
    + _cell(f"{latency.jitter} ms" if latency and latency.jitter is not None else None)
    + f"<td>{ports or '—'}</td>"
    + _cell(str(d.status), "online" if d.status == DeviceStatus.ONLINE else "offline")
    + _cell("yes" if d.trusted else "no", "" if d.trusted else "untrusted")
    + _cell(d.last_seen.strftime("%Y-%m-%d %H:%M:%S") if d.last_seen else None)
    + "</tr>"
  )


def _event_row(e: Event) -> str:
  return (
    "<tr>"
    + _cell(e.timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    + _cell(str(e.severity), f"sev-{e.severity}")
    + _cell(str(e.type))
    + f'<td style="white-space:normal">{escape(e.message)}</td>'
    + "</tr>"
  )


def render_html(devices: Sequence[Device], events: Sequence[Event], meta: dict[str, Any]) -> str:
  online = sum(d.status == DeviceStatus.ONLINE for d in devices)
  untrusted = sum(not d.trusted for d in devices)
  with_ports = sum(bool(d.open_ports) for d in devices)
  refresh = meta.get("refresh")
  refresh_tag = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
  subtitle = " · ".join(
    escape(str(part))
    for part in (
      f"network {meta['network']}" if meta.get("network") else None,
      f"generated {utcnow().strftime('%Y-%m-%d %H:%M:%S')} utc",
      f"beacon {__version__}",
    )
    if part
  )
  cards = "".join(
    f'<div class="card"><b>{value}</b><span>{label}</span></div>'
    for value, label in ((len(devices), "devices"), (online, "online"), (untrusted, "untrusted"), (with_ports, "with open ports"))
  )
  device_rows = "".join(_device_row(d) for d in devices) or '<tr><td colspan="11" class="muted">no devices</td></tr>'
  events_section = ""
  if events:
    events_section = (
      "<h2>EVENTS</h2><div class=\"wrap\"><table><thead><tr><th>time (utc)</th><th>severity</th><th>type</th>"
      f"<th>message</th></tr></thead><tbody>{''.join(_event_row(e) for e in events)}</tbody></table></div>"
    )
  return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{refresh_tag}
<title>Beacon Network Report</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
<h1>BEACON · NETWORK REPORT</h1>
<div class="meta">{subtitle}</div>
<div class="cards">{cards}</div>
<div class="wrap"><table>
<thead><tr><th>ip</th><th>mac</th><th>name</th><th>vendor</th><th>os</th><th>latency</th><th>jitter</th>
<th>open ports</th><th>status</th><th>trusted</th><th>last seen (utc)</th></tr></thead>
<tbody>{device_rows}</tbody>
</table></div>
{events_section}
</main>
</body>
</html>
"""
