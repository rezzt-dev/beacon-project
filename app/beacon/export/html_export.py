 # import libraries ->
import base64
import hashlib
import ipaddress
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from html import escape
from typing import Any
from urllib.parse import quote

from beacon import __version__
from beacon.core.events import Event, Severity
from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.risk import ADMIN_PORTS, CLEARTEXT_PORTS, RiskAssessment, RiskLevel, assess


 # template ->
# self-contained on purpose: no fonts, scripts or images from the network, so the page works
# offline and a hostile hostname can never pull in a remote resource
_STYLE = """
:root {
  color-scheme: light dark;
  --bg: oklch(0.982 0.004 250); --surface: oklch(1 0 0); --surface-2: oklch(0.962 0.007 250);
  --hover: oklch(0.955 0.009 250); --line: oklch(0.91 0.009 250); --line-strong: oklch(0.84 0.012 250);
  --ink: oklch(0.23 0.016 250); --ink-2: oklch(0.44 0.016 250); --ink-3: oklch(0.56 0.012 250);
  --accent: oklch(0.52 0.15 248); --accent-ink: oklch(0.45 0.15 248); --accent-tint: oklch(0.95 0.025 248);
  --ok: oklch(0.56 0.13 155); --ok-ink: oklch(0.43 0.11 155); --ok-tint: oklch(0.955 0.03 155);
  --warn: oklch(0.7 0.15 70); --warn-ink: oklch(0.47 0.11 65); --warn-tint: oklch(0.96 0.04 80);
  --alert: oklch(0.56 0.2 27); --alert-ink: oklch(0.47 0.18 27); --alert-tint: oklch(0.955 0.025 27);
  --alert-line: oklch(0.87 0.06 27); --chip: oklch(0.95 0.008 250);
  --font: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  --mono: ui-monospace, "JetBrains Mono", "Cascadia Code", "SF Mono", Menlo, Consolas, monospace;
  --radius: 8px; --z-sticky: 10;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: oklch(0.17 0.01 250); --surface: oklch(0.205 0.012 250); --surface-2: oklch(0.235 0.013 250);
    --hover: oklch(0.25 0.014 250); --line: oklch(0.29 0.014 250); --line-strong: oklch(0.36 0.016 250);
    --ink: oklch(0.94 0.006 250); --ink-2: oklch(0.75 0.012 250); --ink-3: oklch(0.64 0.012 250);
    --accent: oklch(0.72 0.13 248); --accent-ink: oklch(0.8 0.1 248); --accent-tint: oklch(0.29 0.05 248);
    --ok: oklch(0.74 0.15 155); --ok-ink: oklch(0.8 0.13 155); --ok-tint: oklch(0.27 0.04 155);
    --warn: oklch(0.8 0.14 80); --warn-ink: oklch(0.85 0.12 80); --warn-tint: oklch(0.29 0.045 75);
    --alert: oklch(0.68 0.18 25); --alert-ink: oklch(0.8 0.12 25); --alert-tint: oklch(0.27 0.05 25);
    --alert-line: oklch(0.4 0.09 25); --chip: oklch(0.27 0.013 250);
  }
}
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 var(--font);
       font-variant-numeric: tabular-nums; }
button { font: inherit; color: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
html:not(.js) .needs-js { display: none !important; }
.mono { font-family: var(--mono); font-size: 13px; }
.muted { color: var(--ink-2); }
.faint { color: var(--ink-3); }

.bar { position: sticky; top: 0; z-index: var(--z-sticky); background: var(--surface-2);
       border-bottom: 1px solid var(--line); }
.bar-inner { max-width: 1320px; margin: 0 auto; padding: 10px 20px; display: flex; flex-wrap: wrap;
             align-items: center; gap: 6px 18px; }
.brand { display: flex; align-items: center; gap: 8px; font-weight: 650; font-size: 16px; letter-spacing: -0.01em; }
.brand svg { width: 18px; height: 18px; color: var(--accent); }
.scope { color: var(--ink-2); font-family: var(--mono); font-size: 13px; }
.live { margin-left: auto; display: flex; align-items: center; gap: 10px; font-size: 13px; min-width: 0; }
.live-label { font-weight: 600; }
.signal { position: relative; flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--ink-3); }
[data-live="live"] .signal { background: var(--ok); }
[data-live="live"] .signal::after { content: ""; position: absolute; inset: 0; border-radius: 50%;
  border: 1.5px solid var(--ok); animation: ping 2.4s cubic-bezier(0.16, 1, 0.3, 1) infinite; }
[data-live="stale"] .signal { background: var(--warn); }
[data-live="stale"] .live-label { color: var(--warn-ink); }
@keyframes ping { from { transform: scale(1); opacity: 0.9; } to { transform: scale(2.8); opacity: 0; } }
.meter { height: 2px; }
.meter span { display: block; height: 100%; background: var(--accent); transform-origin: left center;
              transform: scaleX(0); transition: transform 1s linear; }
.btn { border: 1px solid var(--line-strong); background: var(--surface); border-radius: 6px; padding: 2px 10px;
       font-size: 13px; cursor: pointer; transition: background-color 150ms ease-out; }
.btn:hover { background: var(--hover); }
.btn:active { background: var(--line); }
.link { border: 0; background: none; padding: 0; color: var(--accent-ink); cursor: pointer;
        text-decoration: underline; text-underline-offset: 2px; }

main { max-width: 1320px; margin: 0 auto; padding: 28px 20px 40px; }
.headline { font-size: 22px; line-height: 1.3; font-weight: 500; letter-spacing: -0.015em; margin: 0 0 4px;
            text-wrap: balance; }
.headline strong { font-weight: 680; }
.headline .bad { color: var(--alert-ink); font-weight: 680; }
.headline .good { color: var(--ok-ink); }
.sub { color: var(--ink-2); margin: 0 0 24px; }
h2 { font-size: 16px; font-weight: 650; margin: 0; letter-spacing: -0.005em; }
section { margin-bottom: 32px; }

.attention { background: var(--alert-tint); border: 1px solid var(--alert-line); border-radius: var(--radius);
             padding: 14px 16px; }
.attention h2 { color: var(--alert-ink); margin-bottom: 8px; }
.attention ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.attention li { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; }
.attention .why { color: var(--ink-2); }
.attention p { margin: 10px 0 0; color: var(--ink-2); font-size: 13px; }
.attention code { font-family: var(--mono); font-size: 13px; color: var(--ink); }

.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px; margin-bottom: 10px; }
.toolbar .count { color: var(--ink-2); font-weight: 500; }
.toolbar .spacer { flex: 1 1 0; }
.seg { display: inline-flex; flex-wrap: wrap; border: 1px solid var(--line-strong); border-radius: 7px;
       background: var(--surface); padding: 2px; gap: 2px; }
.seg button { border: 0; background: none; border-radius: 5px; padding: 2px 9px; cursor: pointer; color: var(--ink-2);
              transition: background-color 150ms ease-out, color 150ms ease-out; }
.seg button:hover { background: var(--hover); color: var(--ink); }
.seg button[aria-pressed="true"] { background: var(--accent-tint); color: var(--accent-ink); font-weight: 600; }
.seg .n { margin-left: 5px; color: var(--ink-3); font-weight: 500; }
.seg button[aria-pressed="true"] .n { color: inherit; }
.search { width: min(300px, 100%); border: 1px solid var(--line-strong); background: var(--surface);
          border-radius: 7px; padding: 5px 10px; font: inherit; color: var(--ink); }
.search::placeholder { color: var(--ink-3); }
.news { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; margin: 0 0 10px;
        padding: 6px 12px; border-radius: 6px; background: var(--accent-tint); color: var(--accent-ink); }

.table-wrap { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th { text-align: left; font-size: 12px; font-weight: 600; color: var(--ink-2); background: var(--surface-2);
     border-bottom: 1px solid var(--line); white-space: nowrap; padding: 0; }
th > span, th > button { display: flex; align-items: center; gap: 4px; width: 100%; padding: 8px 10px; }
th > button { border: 0; background: none; text-align: left; font-weight: inherit; color: inherit; cursor: pointer; }
th > button:hover { color: var(--ink); }
th[aria-sort] > button { color: var(--ink); }
th[aria-sort="ascending"] > button::after { content: "↑"; }
th[aria-sort="descending"] > button::after { content: "↓"; }
td { padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; white-space: nowrap; }
td[data-label="open ports"] { min-width: 150px; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr { transition: background-color 150ms ease-out; }
tbody tr:hover { background: var(--hover); }
tr.is-offline td { color: var(--ink-2); }
tr.is-new { background: var(--accent-tint); }
.status { display: inline-flex; align-items: center; gap: 7px; }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ink-3); flex: none; }
.dot.on { background: var(--ok); }
.dot.bad { background: var(--alert); }
.name { font-weight: 550; }
.host { font-family: var(--mono); font-size: 13px; overflow-wrap: anywhere; }
.second { color: var(--ink-2); font-size: 13px; margin-top: 1px; }
.second.mono { font-size: 12px; }
.tag { display: inline-block; font-size: 12px; font-weight: 550; line-height: 18px; padding: 0 6px; margin-left: 6px;
       border-radius: 4px; background: var(--chip); color: var(--ink-2); vertical-align: 1px; }
.tag.new { background: var(--accent); color: var(--surface); }
.badge { display: inline-flex; align-items: center; padding: 0 8px; border-radius: 999px; font-size: 12px;
         line-height: 20px; font-weight: 600; background: var(--chip); color: var(--ink-2); }
.badge.ok { background: var(--ok-tint); color: var(--ok-ink); }
.badge.warn { background: var(--warn-tint); color: var(--warn-ink); }
.badge.alert { background: var(--alert-tint); color: var(--alert-ink); }
.lat-ok { color: var(--ok-ink); } .lat-warn { color: var(--warn-ink); } .lat-bad { color: var(--alert-ink); }
.ports { display: flex; flex-wrap: wrap; gap: 4px; white-space: normal; max-width: 240px; }
.chip { font-family: var(--mono); font-size: 12px; line-height: 20px; padding: 0 6px; border-radius: 4px; background: var(--chip); }
.chip.risky { background: var(--warn-tint); color: var(--warn-ink); }
.empty { margin: 0; padding: 28px 16px; text-align: center; color: var(--ink-2); }
.empty strong { display: block; color: var(--ink); font-weight: 600; margin-bottom: 2px; }

.events-list { list-style: none; margin: 0; padding: 0; background: var(--surface); border: 1px solid var(--line);
               border-radius: var(--radius); }
.events-list li { display: grid; grid-template-columns: 8.5rem 6rem 10rem minmax(0, 1fr); gap: 12px; align-items: baseline;
                  padding: 8px 14px; border-bottom: 1px solid var(--line); }
.events-list li:last-child { border-bottom: 0; }
.events-list li.is-new { background: var(--accent-tint); }
.events-list .msg { overflow-wrap: anywhere; }

footer { max-width: 1320px; margin: 0 auto; padding: 0 20px 32px; color: var(--ink-3); font-size: 13px;
         display: flex; flex-wrap: wrap; gap: 4px 16px; }
kbd { font-family: var(--mono); font-size: 12px; padding: 0 4px; border: 1px solid var(--line-strong); border-radius: 4px; }

@media (max-width: 760px) {
  .bar-inner, main, footer { padding-left: 16px; padding-right: 16px; }
  .live { margin-left: 0; width: 100%; }
  .headline { font-size: 19px; }
  .search { width: 100%; }
  .table-wrap { overflow: visible; }
  #devices thead { display: none; }
  #devices, #devices tbody, #devices tr, #devices td { display: block; }
  #devices tr { padding: 10px 0; border-bottom: 1px solid var(--line); }
  #devices tr:last-child { border-bottom: 0; }
  #devices td { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; border: 0;
                padding: 2px 14px; white-space: normal; min-width: 0; }
  #devices td.is-empty { display: none; }
  #devices td::before { content: attr(data-label); color: var(--ink-3); flex: none; }
  #devices .cell { text-align: right; min-width: 0; overflow-wrap: anywhere; }
  .ports { justify-content: flex-end; }
  .events-list li { grid-template-columns: auto 1fr; gap: 2px 12px; }
  .events-list .msg { grid-column: 1 / -1; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
"""

_SCRIPT = """
(() => {
  "use strict";
  const doc = document.documentElement;
  const refresh = Number(doc.dataset.refresh) || 0;
  const generated = Date.parse(doc.dataset.generated);
  const duration = Number(doc.dataset.duration) || 0;
  const live = refresh > 0;
  const $ = (s) => document.querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const KEY = "beacon:" + location.pathname;
  let state = {};
  try { state = JSON.parse(sessionStorage.getItem(KEY) || "{}") || {}; } catch (_) { state = {}; }
  const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(state)); } catch (_) {} };
  doc.classList.add("js");

  // times: written in utc by the server, shown in local time and as "x min ago"
  const rel = (ms) => {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 10) return "just now";
    if (s < 60) return s + "s ago";
    const m = Math.round(s / 60);
    if (m < 60) return m + " min ago";
    const h = Math.round(m / 60);
    return h < 48 ? h + " h ago" : Math.round(h / 24) + " d ago";
  };
  const clock = (d, now) => d.toDateString() === now.toDateString()
    ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  function paintTimes() {
    const now = new Date();
    for (const el of $$("time[data-rel]")) { const d = new Date(el.dateTime); el.textContent = rel(now - d); el.title = d.toLocaleString(); }
    for (const el of $$("time[data-clock]")) { const d = new Date(el.dateTime); el.textContent = clock(d, now); el.title = d.toLocaleString() + " · " + rel(now - d); }
  }

  // devices: filter, search and sort, remembered across refreshes
  const table = $("#devices");
  const tbody = table && table.tBodies[0];
  const rows = tbody ? $$("tr[data-key]", tbody) : [];
  const search = $("#q");
  const empty = $("#devices-empty");
  const tests = {
    all: () => true,
    online: (r) => r.dataset.status === "online",
    untrusted: (r) => r.dataset.trusted === "0",
    ports: (r) => r.dataset.ports !== "0",
    offline: (r) => r.dataset.status === "offline",
  };
  if (!tests[state.filter]) state.filter = "all";
  function applyFilter() {
    const q = search ? search.value.trim().toLowerCase() : "";
    let shown = 0;
    for (const r of rows) {
      const ok = tests[state.filter](r) && (!q || r.dataset.q.includes(q));
      r.hidden = !ok;
      if (ok) shown++;
    }
    for (const b of $$("[data-filter]")) b.setAttribute("aria-pressed", String(b.dataset.filter === state.filter));
    if (empty) {
      empty.hidden = shown > 0 || rows.length === 0;
      $("#devices-empty-text").textContent = q ? "no device matches \\u201c" + q + "\\u201d with this filter" : "no device matches this filter";
    }
  }
  for (const b of $$("[data-filter]")) b.addEventListener("click", () => { state.filter = b.dataset.filter; save(); applyFilter(); });
  if (search) {
    search.value = state.query || "";
    search.addEventListener("input", () => { state.query = search.value; save(); applyFilter(); });
    search.addEventListener("keydown", (e) => { if (e.key === "Escape") { search.value = ""; state.query = ""; save(); applyFilter(); search.blur(); } });
  }
  const clear = $("#clear-filters");
  if (clear) clear.addEventListener("click", () => { state.filter = "all"; state.query = ""; if (search) search.value = ""; save(); applyFilter(); });

  function sortBy(col, dir) {
    const head = table.tHead.rows[0].cells;
    if (!head[col]) return;
    const num = head[col].dataset.type === "num";
    const value = (r) => { const c = r.cells[col]; const v = c.dataset.v !== undefined ? c.dataset.v : c.textContent.trim().toLowerCase(); return num ? Number(v) : v; };
    const order = (r) => Number(r.dataset.order);
    rows.slice().sort((a, b) => {
      const x = value(a), y = value(b);
      return (x < y ? -dir : x > y ? dir : 0) || order(a) - order(b);
    }).forEach((r) => tbody.appendChild(r));
    for (const h of head) h.removeAttribute("aria-sort");
    head[col].setAttribute("aria-sort", dir > 0 ? "ascending" : "descending");
  }
  if (table) {
    $$("th > button", table.tHead).forEach((button) => {
      const col = button.parentElement.cellIndex;
      button.addEventListener("click", () => {
        const dir = state.sort && state.sort.col === col ? -state.sort.dir : 1;
        state.sort = { col, dir };
        save();
        sortBy(col, dir);
      });
    });
    if (state.sort) sortBy(state.sort.col, state.sort.dir);
  }

  // what appeared since this tab was opened stays highlighted until marked as seen
  const news = $("#news");
  function markNew() {
    if (!live || !news) return;
    const keys = rows.map((r) => r.dataset.key);
    if (!Array.isArray(state.seenKeys)) { state.seenKeys = keys; state.seenAt = generated; save(); }
    const seen = new Set(state.seenKeys);
    const freshRows = rows.filter((r) => !seen.has(r.dataset.key));
    const freshEvents = $$("li[data-ts]").filter((li) => Date.parse(li.dataset.ts) > state.seenAt);
    for (const r of freshRows) {
      r.classList.add("is-new");
      const tag = document.createElement("span");
      tag.className = "tag new";
      tag.textContent = "new";
      r.querySelector('td[data-label="device"] .line').appendChild(tag);
    }
    for (const li of freshEvents) li.classList.add("is-new");
    const parts = [];
    if (freshRows.length) parts.push(freshRows.length + (freshRows.length === 1 ? " new device" : " new devices"));
    if (freshEvents.length) parts.push(freshEvents.length + (freshEvents.length === 1 ? " new event" : " new events"));
    news.hidden = parts.length === 0;
    $("#news-text").textContent = parts.join(" and ") + " since you opened this page";
  }
  const markSeen = $("#mark-seen");
  if (markSeen) markSeen.addEventListener("click", () => {
    state.seenKeys = rows.map((r) => r.dataset.key);
    state.seenAt = generated;
    save();
    for (const el of $$(".is-new")) el.classList.remove("is-new");
    for (const el of $$(".tag.new")) el.remove();
    news.hidden = true;
  });

  // events: severity filter
  const eventItems = $$("li[data-sev]");
  if (!["all", "alert", "warning", "info"].includes(state.sev)) state.sev = "all";
  function applySeverity() {
    for (const li of eventItems) li.hidden = state.sev !== "all" && li.dataset.sev !== state.sev;
    for (const b of $$("[data-sev-filter]")) b.setAttribute("aria-pressed", String(b.dataset.sevFilter === state.sev));
  }
  for (const b of $$("[data-sev-filter]")) b.addEventListener("click", () => { state.sev = b.dataset.sevFilter; save(); applySeverity(); });

  // live refresh: reload when the next scan should have rewritten the file, pausable
  const bar = $("#live");
  const label = $("#live-label");
  const detail = $("#live-detail");
  const meter = $("#meter");
  const pause = $("#pause");
  const loadedAt = Date.now();
  let next = 0;
  function reload() {
    state.scroll = window.scrollY;
    state.focus = document.activeElement === search;
    save();
    location.reload();
  }
  function tick() {
    const now = Date.now();
    const age = now - generated;
    const stale = age > (refresh * 3 + duration + 10) * 1000;
    const mode = state.paused ? "paused" : stale ? "stale" : "live";
    bar.dataset.live = mode;
    label.textContent = mode;
    pause.textContent = state.paused ? "resume" : "pause";
    pause.setAttribute("aria-pressed", String(!!state.paused));
    if (mode !== "live") meter.style.transform = "scaleX(0)";
    if (mode === "paused") {
      detail.textContent = "updated " + rel(age) + " · auto-refresh paused";
    } else if (mode === "stale") {
      detail.textContent = "no update for " + rel(age).replace(" ago", "") + " · is beacon watch still running?";
    } else {
      const left = Math.ceil((next - now) / 1000);
      detail.textContent = "updated " + rel(age) + (left > 0 ? " · next check in " + left + "s" : " · checking…");
      meter.style.transform = "scaleX(" + Math.min(1, Math.max(0, (now - loadedAt) / Math.max(1, next - loadedAt))) + ")";
    }
    if (!state.paused && now >= next) reload();
  }
  if (live && bar) {
    // a reload that finds the same file means the scan is still running: look again shortly
    const unchanged = state.lastGenerated === generated;
    state.lastGenerated = generated;
    save();
    const expected = generated + (refresh + duration + 2) * 1000;
    next = unchanged || expected < loadedAt ? loadedAt + 5000 : expected;
    if (Date.now() - generated > (refresh * 3 + duration + 10) * 1000) next = loadedAt + 15000;
    pause.addEventListener("click", () => { state.paused = !state.paused; save(); tick(); });
    tick();
    setInterval(tick, 1000);
  }

  // keyboard: "/" searches, "p" pauses
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || /^(input|textarea|select)$/i.test(e.target.tagName)) return;
    if (e.key === "/" && search) { e.preventDefault(); search.focus(); }
    else if (e.key === "p" && live && pause) { pause.click(); }
  });

  applyFilter();
  applySeverity();
  markNew();
  paintTimes();
  setInterval(paintTimes, 15000);
  if (state.scroll) requestAnimationFrame(() => window.scrollTo(0, state.scroll));
  if (state.focus && search) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
  state.scroll = 0;
  state.focus = false;
  save();
})();
"""


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
_FLAGGED_PORTS = set(ADMIN_PORTS) | set(CLEARTEXT_PORTS)
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
    f'<span class="chip{" risky" if p.port in _FLAGGED_PORTS else ""}" title="{_e(p.service or "unknown service")}">{p.port}</span>'
    for p in ports[:_PORTS_SHOWN]
  )
  if len(ports) > _PORTS_SHOWN:
    chips += f'<span class="chip">+{len(ports) - _PORTS_SHOWN}</span>'
  return f'<div class="ports">{chips}</div>'


def _risk_badge(risk: RiskAssessment) -> str:
  reasons = " · ".join(r.text for r in risk.reasons) or "nothing notable"
  return f'<span class="badge {_RISK_BADGE[risk.level]}" title="{_e(reasons)}">{risk.level} {risk.score}</span>'


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
  risks = {d.key: assess(d, events, ports_known, now=generated) for d in ordered}
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
<footer><span>beacon {_e(__version__)}</span><span>values come from the network and are shown as plain text</span>{hints}</footer>
<script>{_SCRIPT}</script>
</body>
</html>
"""
