// shared building blocks. every state carries a symbol or a word, never color alone.

import { h, icon } from "./dom.js";
import { fmtDateTime, fmtNumber, fmtRelative, t } from "./i18n.js";
import { devicePage } from "./router.js";

export function deviceName(device) {
  return device.alias || device.hostname || device.ip;
}

export function deviceLink(device, label) {
  return h("a", { href: devicePage(device.key), class: "device-link" }, label ?? deviceName(device));
}

/** a time that reads relative ("3 min ago") and shows the full local date on hover. refreshed by `tick`. */
export function timeEl(iso, { clock = false } = {}) {
  if (!iso) return h("span", { class: "muted" }, t("common.never"));
  return h("time", { datetime: iso, title: fmtDateTime(iso, true), dataset: { rel: clock ? "" : "1" } }, clock ? fmtDateTime(iso) : fmtRelative(iso));
}

export function tickTimes(root = document) {
  for (const el of root.querySelectorAll("time[data-rel='1']")) el.textContent = fmtRelative(el.dateTime);
}

export function badge(text, kind = "", symbol = null) {
  return h("span", { class: ["badge", kind] }, symbol ? h("span", { class: "badge-symbol", "aria-hidden": "true" }, symbol) : null, text);
}

export function statusBadge(device) {
  if (device.status !== "online") return badge(t("status.offline"), "", "○");
  return device.trusted ? badge(t("status.online"), "ok", "●") : badge(t("status.online_untrusted"), "alert", "●");
}

export function trustBadge(device) {
  return device.trusted ? badge(t("trust.trusted"), "ok", "✓") : badge(t("trust.untrusted"), "warn", "!");
}

const RISK_KIND = { low: "ok", medium: "warn", high: "alert" };

export function riskBadge(risk) {
  if (!risk) return h("span", { class: "muted" }, "—");
  const incomplete = !risk.complete;
  const label = t("risk." + risk.level) + " " + risk.score + (incomplete ? " ?" : "");
  const title = incomplete ? t("risk.incomplete_hint") : risk.reasons.map((r) => r.text).join(" · ") || t("risk.nothing");
  const el = badge(label, RISK_KIND[risk.level], risk.level === "high" ? "▲" : risk.level === "medium" ? "◆" : "▽");
  el.title = title;
  if (incomplete) el.classList.add("incomplete");
  return el;
}

const BASIS_KIND = { observed: "ok", inferred: "", history: "accent", context: "" };

/** the reasons behind a score: each with its basis (observed, inferred, history, context) and date. */
export function riskExplain(risk) {
  if (!risk) return h("p", { class: "muted" }, t("risk.none"));
  return h("div", { class: "risk-explain" },
    h("p", { class: "risk-head" }, riskBadge(risk), " ", h("span", { class: "muted" }, t("risk.rules", { v: risk.rules_version }))),
    risk.reasons.length
      ? h("ul", { class: "reasons" }, risk.reasons.map((r) => h("li", {},
        h("span", { class: "points" }, "+" + r.points),
        h("span", { class: "reason-text" }, r.text),
        badge(t("basis." + r.basis), BASIS_KIND[r.basis] || ""),
        r.at ? h("span", { class: "muted small" }, timeEl(r.at)) : null)))
      : h("p", { class: "muted" }, t("risk.nothing")),
    risk.notes.length ? h("ul", { class: "notes" }, risk.notes.map((n) => h("li", {}, icon("info"), n))) : null);
}

const SEVERITY = { alert: ["alert", "✗"], warning: ["warn", "!"], info: ["", "·"] };

export function severityBadge(severity) {
  const [kind, symbol] = SEVERITY[severity] || SEVERITY.info;
  return badge(t("severity." + severity), kind, symbol);
}

export function latencyText(latency) {
  if (!latency) return h("span", { class: "muted" }, t("latency.not_measured"));
  if (latency.avg === null) return h("span", { class: "muted" }, t("latency.no_reply"));
  const kind = latency.avg < 20 ? "good" : latency.avg < 100 ? "fair" : "poor";
  return h("span", { class: "latency " + kind },
    fmtNumber(latency.avg, 1) + " ms",
    latency.jitter !== null ? h("span", { class: "muted" }, " ±" + fmtNumber(latency.jitter, 1)) : null,
    latency.loss ? h("span", { class: "warn-text" }, " " + t("latency.loss", { n: fmtNumber(latency.loss) })) : null);
}

export function portChips(ports, limit = 6) {
  if (!ports.length) return h("span", { class: "muted" }, "—");
  return h("span", { class: "chips" },
    ports.slice(0, limit).map((p) => h("span", { class: ["chip", p.sensitive ? "sensitive" : ""], title: (p.service || t("ports.unknown_service")) + (p.sensitive ? " · " + t("ports.sensitive") : "") },
      p.sensitive ? h("span", { "aria-hidden": "true" }, "! ") : null, String(p.port))),
    ports.length > limit ? h("span", { class: "chip" }, "+" + (ports.length - limit)) : null);
}

export function emptyState(title, text, action) {
  return h("div", { class: "empty" },
    h("p", { class: "empty-title" }, title),
    text ? h("p", { class: "muted" }, text) : null,
    action ? h(action.href ? "a" : "button", { type: action.href ? undefined : "button", href: action.href, class: "btn", onClick: action.run }, action.label) : null);
}

export function errorState(error, retry) {
  const offline = error && error.code === "offline";
  return h("div", { class: "empty error", role: "alert" },
    h("p", { class: "empty-title" }, icon("alert"), " ", offline ? t("error.offline_title") : t("error.title")),
    h("p", { class: "muted" }, offline ? t("error.offline_text") : (error && error.message) || t("error.unknown")),
    retry ? h("button", { type: "button", class: "btn", onClick: retry }, t("common.retry")) : null);
}

export function loading(label) {
  return h("div", { class: "loading", role: "status", "aria-live": "polite" }, h("span", { class: "spinner", "aria-hidden": "true" }), label || t("common.loading"));
}

export function pager(page, pages, onPage) {
  if (pages <= 1) return null;
  return h("nav", { class: "pager", "aria-label": t("pager.label") },
    h("button", { type: "button", class: "btn small", disabled: page <= 1, onClick: () => onPage(page - 1) }, t("pager.previous")),
    h("span", { class: "muted", "aria-live": "polite" }, t("pager.position", { page, pages })),
    h("button", { type: "button", class: "btn small", disabled: page >= pages, onClick: () => onPage(page + 1) }, t("pager.next")));
}

/** a labelled form control with its hint and error, wired for screen readers. */
export function field(label, control, { hint, error, id } = {}) {
  const controlId = id || control.id || "f-" + Math.random().toString(36).slice(2);
  control.id = controlId;
  const hintId = hint ? controlId + "-hint" : null;
  const errorId = error ? controlId + "-error" : null;
  const described = [hintId, errorId].filter(Boolean).join(" ");
  if (described) control.setAttribute("aria-describedby", described);
  if (error) control.setAttribute("aria-invalid", "true");
  return h("div", { class: "field" },
    h("label", { for: controlId }, label),
    control,
    hint ? h("p", { class: "hint", id: hintId }, hint) : null,
    error ? h("p", { class: "field-error", id: errorId }, error) : null);
}

export function select(options, value, attrs = {}) {
  return h("select", attrs, options.map(([v, label]) => h("option", { value: v, selected: String(v) === String(value ?? "") }, label)));
}

/** a section with a heading and optional actions on the right. */
export function panel(title, body, actions, { id, level = "h2" } = {}) {
  const headingId = id || "p-" + Math.random().toString(36).slice(2);
  return h("section", { class: "panel", "aria-labelledby": headingId },
    h("div", { class: "panel-head" }, h(level, { id: headingId }, title), actions ? h("div", { class: "panel-actions" }, actions) : null),
    body);
}

/** a definition list for label/value facts. */
export function facts(rows) {
  return h("dl", { class: "facts" }, rows.filter(Boolean).map(([label, value]) => [h("dt", {}, label), h("dd", {}, value ?? "—")]));
}
