// small svg charts. one series per chart (never two y axes), no interpolation across gaps,
// a hover tooltip and a table view for every chart.

import { h, s } from "./dom.js";
import { DAY_KEYS, fmtClock, fmtNumber, fmtPercent, t } from "./i18n.js";

const W = 640;
const H = 180;
const PAD = { top: 12, right: 12, bottom: 24, left: 44 };

function niceMax(value) {
  if (value <= 0) return 1;
  const power = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) if (value <= step * power) return step * power;
  return 10 * power;
}

function withTable(title, figure, rows, headers) {
  const table = h("table", { class: "table compact", hidden: true },
    h("caption", {}, title),
    h("thead", {}, h("tr", {}, headers.map((x) => h("th", { scope: "col" }, x)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c, i) => (i === 0 ? h("th", { scope: "row" }, c) : h("td", {}, c)))))));
  const toggle = h("button", { type: "button", class: "btn small", "aria-pressed": "false", onClick: () => {
    const showing = table.hidden;
    table.hidden = !showing;
    figure.hidden = showing;
    toggle.setAttribute("aria-pressed", String(showing));
    toggle.textContent = showing ? t("chart.show_chart") : t("chart.show_table");
  } }, t("chart.show_table"));
  return h("div", { class: "chart-block" }, h("div", { class: "chart-tools" }, toggle), figure, table);
}

/**
 * line over time. `points` = [{at, value}] with value null for a bucket measured but without a reply;
 * buckets with no measurement are absent and the line breaks there (`gapMs`).
 */
export function lineChart(title, points, { unit = "", digits = 1, gapMs, valueLabel } = {}) {
  const usable = points.filter((p) => p.value !== null && p.value !== undefined);
  if (!usable.length) {
    return h("div", { class: "chart-empty" }, h("p", { class: "chart-title" }, title), h("p", { class: "empty-title" }, t("chart.no_samples")), h("p", { class: "muted" }, t("chart.no_samples_text")));
  }
  const times = points.map((p) => new Date(p.at).getTime());
  // a gap is a silence longer than the usual pace of the samples (an hourly monitor is not "missing" every hour)
  const steps = times.slice(1).map((ms, i) => ms - times[i]).filter((d) => d > 0).sort((a, b) => a - b);
  const pace = steps.length ? steps[Math.floor(steps.length / 2)] : 0;
  gapMs = Math.max(gapMs || 0, pace * 2.5);
  const t0 = Math.min(...times);
  const t1 = Math.max(...times, t0 + 1);
  const max = niceMax(Math.max(...usable.map((p) => p.value)));
  const x = (ms) => PAD.left + ((ms - t0) / (t1 - t0)) * (W - PAD.left - PAD.right);
  const y = (v) => PAD.top + (1 - v / max) * (H - PAD.top - PAD.bottom);
  const segments = [];
  let current = [];
  let previous = null;
  for (const p of points) {
    const ms = new Date(p.at).getTime();
    const broken = p.value === null || (previous !== null && gapMs && ms - previous > gapMs);
    if (broken && current.length) { segments.push(current); current = []; }
    if (p.value !== null) current.push([x(ms), y(p.value)]);
    previous = ms;
  }
  if (current.length) segments.push(current);
  const ticks = [0, max / 2, max];
  const tip = s("g", { class: "chart-tip", visibility: "hidden" },
    s("line", { class: "crosshair", y1: PAD.top, y2: H - PAD.bottom }),
    s("circle", { r: 4, class: "tip-dot" }));
  const label = h("div", { class: "chart-tooltip", hidden: true });
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": title },
    ticks.map((v) => s("g", { class: "grid" },
      s("line", { x1: PAD.left, x2: W - PAD.right, y1: y(v), y2: y(v) }),
      s("text", { x: PAD.left - 6, y: y(v) + 4, "text-anchor": "end" }, fmtNumber(v, v < 10 ? 1 : 0)))),
    s("text", { class: "axis-label", x: PAD.left, y: H - 6 }, fmtClock(new Date(t0).toISOString())),
    s("text", { class: "axis-label", x: W - PAD.right, y: H - 6, "text-anchor": "end" }, fmtClock(new Date(t1).toISOString())),
    segments.map((seg) => (seg.length === 1
      ? s("circle", { class: "series-dot", cx: seg[0][0], cy: seg[0][1], r: 3 })
      : s("path", { class: "series-line", d: "M" + seg.map(([a, b]) => `${a.toFixed(1)},${b.toFixed(1)}`).join("L") }))),
    tip,
    s("rect", { class: "hit", x: PAD.left, y: PAD.top, width: W - PAD.left - PAD.right, height: H - PAD.top - PAD.bottom }));
  const figure = h("figure", { class: "chart-figure" }, h("figcaption", { class: "chart-title" }, title), svg, label);
  svg.addEventListener("pointermove", (event) => {
    const box = svg.getBoundingClientRect();
    const px = ((event.clientX - box.left) / box.width) * W;
    let best = null;
    for (const p of usable) {
      const d = Math.abs(x(new Date(p.at).getTime()) - px);
      if (!best || d < best.d) best = { p, d };
    }
    if (!best) return;
    const cx = x(new Date(best.p.at).getTime());
    tip.setAttribute("visibility", "visible");
    tip.querySelector("line").setAttribute("x1", cx);
    tip.querySelector("line").setAttribute("x2", cx);
    tip.querySelector("circle").setAttribute("cx", cx);
    tip.querySelector("circle").setAttribute("cy", y(best.p.value));
    label.hidden = false;
    label.textContent = `${fmtClock(best.p.at)} · ${valueLabel ? valueLabel(best.p) : fmtNumber(best.p.value, digits) + unit}`;
    label.style.left = `${(cx / W) * 100}%`;
  });
  svg.addEventListener("pointerleave", () => { tip.setAttribute("visibility", "hidden"); label.hidden = true; });
  const rows = points.map((p) => [fmtClock(p.at), p.value === null ? t("chart.no_reply") : fmtNumber(p.value, digits) + unit]);
  return withTable(title, figure, rows, [t("chart.time"), title]);
}

const HEAT_STEPS = 5;

/** a 7 x 24 grid of presence frequency. an hour nobody watched is hatched, never painted as zero. */
export function presenceHeatmap(title, grid) {
  const cell = 22;
  const gap = 2;
  const left = 40;
  const top = 18;
  const width = left + 24 * (cell + gap);
  const height = top + 7 * (cell + gap);
  const label = h("div", { class: "chart-tooltip", hidden: true });
  const svg = s("svg", { viewBox: `0 0 ${width} ${height}`, class: "chart heatmap", role: "img", "aria-label": title },
    s("defs", {}, s("pattern", { id: "unwatched", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
      s("line", { x1: 0, y1: 0, x2: 0, y2: 6, class: "hatch" }))),
    [0, 6, 12, 18].map((hour) => s("text", { class: "axis-label", x: left + hour * (cell + gap), y: 12 }, String(hour).padStart(2, "0") + "h")),
    grid.map((row, day) => [
      s("text", { class: "axis-label", x: 0, y: top + day * (cell + gap) + 15 }, t(DAY_KEYS[day])),
      row.map((c, hour) => {
        const step = c.frequency === null ? null : Math.min(HEAT_STEPS - 1, Math.floor(c.frequency * HEAT_STEPS));
        const rect = s("rect", {
          x: left + hour * (cell + gap), y: top + day * (cell + gap), width: cell, height: cell, rx: 3,
          class: step === null ? "heat-unwatched" : "heat-" + step,
          fill: step === null ? "url(#unwatched)" : undefined,
          tabindex: "-1",
        });
        rect.addEventListener("pointerenter", () => {
          label.hidden = false;
          label.textContent = `${t(DAY_KEYS[day])} ${String(hour).padStart(2, "0")}:00 · ` + (c.frequency === null
            ? t("presence.unwatched")
            : t("presence.cell", { pct: fmtPercent(c.frequency), present: c.present, watched: c.watched }));
          label.style.left = `${((left + hour * (cell + gap)) / width) * 100}%`;
        });
        rect.addEventListener("pointerleave", () => { label.hidden = true; });
        return rect;
      }),
    ]));
  const legend = h("div", { class: "legend" },
    h("span", {}, t("presence.legend_low")),
    Array.from({ length: HEAT_STEPS }, (_, i) => h("span", { class: "swatch heat-" + i, "aria-hidden": "true" })),
    h("span", {}, t("presence.legend_high")),
    h("span", { class: "swatch unwatched", "aria-hidden": "true" }), h("span", {}, t("presence.unwatched")));
  const figure = h("figure", { class: "chart-figure" }, h("figcaption", { class: "chart-title" }, title), svg, label, legend);
  const rows = grid.map((row, day) => [t(DAY_KEYS[day]), ...row.map((c) => (c.frequency === null ? "·" : fmtPercent(c.frequency)))]);
  return withTable(title, figure, rows, [t("chart.day"), ...Array.from({ length: 24 }, (_, i) => String(i))]);
}

/** horizontal presence bars per device over a window, with the unwatched periods shaded behind. */
export function timeline(title, rows, windows, since, until) {
  const t0 = new Date(since).getTime();
  const t1 = new Date(until).getTime();
  const left = 160;
  const width = 760;
  const rowH = 22;
  const top = 20;
  const height = top + rows.length * rowH + 4;
  const x = (iso) => left + ((Math.min(t1, Math.max(t0, new Date(iso).getTime())) - t0) / (t1 - t0)) * (width - left - 8);
  const watched = windows.map((w) => s("rect", { class: "watched", x: x(w.start), y: top - 4, width: Math.max(2, x(w.end) - x(w.start)), height: rows.length * rowH + 4 }));
  const svg = s("svg", { viewBox: `0 0 ${width} ${height}`, class: "chart timeline", role: "img", "aria-label": title },
    s("rect", { class: "unwatched-band", x: left, y: top - 4, width: width - left - 8, height: rows.length * rowH + 4, fill: "url(#tl-unwatched)" }),
    s("defs", {}, s("pattern", { id: "tl-unwatched", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
      s("line", { x1: 0, y1: 0, x2: 0, y2: 6, class: "hatch" }))),
    watched,
    s("text", { class: "axis-label", x: left, y: 12 }, fmtClock(since)),
    s("text", { class: "axis-label", x: width - 8, y: 12, "text-anchor": "end" }, fmtClock(until)),
    rows.map((row, i) => [
      s("text", { class: "row-label", x: 0, y: top + i * rowH + 13 }, row.label.length > 22 ? row.label.slice(0, 21) + "…" : row.label),
      row.sessions.map((session) => s("rect", {
        class: "session", x: x(session.started_at), y: top + i * rowH + 3, rx: 3, height: rowH - 8,
        width: Math.max(3, x(session.ended_at || session.last_seen) - x(session.started_at)),
      }, s("title", {}, `${row.label}: ${fmtClock(session.started_at)} – ${session.open ? t("presence.still_here") : fmtClock(session.ended_at || session.last_seen)}`))),
    ]));
  const legend = h("div", { class: "legend" },
    h("span", { class: "swatch session", "aria-hidden": "true" }), h("span", {}, t("presence.connected")),
    h("span", { class: "swatch watched", "aria-hidden": "true" }), h("span", {}, t("presence.watched")),
    h("span", { class: "swatch unwatched", "aria-hidden": "true" }), h("span", {}, t("presence.unwatched")));
  const figure = h("figure", { class: "chart-figure" }, h("figcaption", { class: "chart-title" }, title), h("div", { class: "chart-scroll" }, svg), legend);
  const tableRows = rows.flatMap((row) => row.sessions.map((session) => [row.label, fmtClock(session.started_at), session.open ? t("presence.still_here") : fmtClock(session.ended_at || session.last_seen)]));
  return withTable(title, figure, tableRows, [t("col.device"), t("presence.from"), t("presence.to")]);
}
