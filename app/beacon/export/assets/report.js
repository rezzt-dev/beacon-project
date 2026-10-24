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
      $("#devices-empty-text").textContent = q ? "no device matches \u201c" + q + "\u201d with this filter" : "no device matches this filter";
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
