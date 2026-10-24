// resumen: what is on the network, what needs attention, how fresh and complete the data is.

import { api } from "../api.js";
import { app } from "../app.js";
import { deviceLink, emptyState, errorState, loading, panel, riskBadge, severityBadge, timeEl } from "../components.js";
import { h, replace, toast } from "../dom.js";
import { fmtNumber, fmtPercent, t } from "../i18n.js";
import { navigate } from "../router.js";

const RELEVANT = /^(scan\.finished|device\.|event\.|identity\.|reset)/;

function tile(label, value, href, { kind = "", hint } = {}) {
  return h("a", { href, class: ["tile", kind] },
    h("span", { class: "tile-value" }, value),
    h("span", { class: "tile-label" }, label),
    hint ? h("span", { class: "tile-hint" }, hint) : null);
}

async function startMonitor() {
  try {
    await api.post("/api/v1/monitor", { action: "start" });
    toast(t("monitor.started"), "ok");
    app.reloadStatus();
  } catch (error) {
    toast(error.message, "error");
  }
}

function nextAction(action) {
  const actions = {
    first_scan: { label: t("next.first_scan_button"), run: () => navigate("/welcome") },
    review: { label: t("next.review_button"), run: () => navigate("/review") },
    add_ports: { label: t("next.add_ports_button"), run: () => navigate("/settings#profiles") },
    start_monitor: { label: t("next.start_monitor_button"), run: startMonitor },
  };
  const button = actions[action.code];
  return h("div", { class: ["next-action", action.code === "none" ? "calm" : ""] },
    h("p", { class: "next-text" }, t("next." + action.code, { n: action.count ?? 0 })),
    button ? h("button", { type: "button", class: "btn primary", onClick: button.run }, button.label) : null);
}

function observation(summary) {
  const obs = summary.observation;
  const scan = obs.last_valid_scan;
  const total = summary.devices.total;
  const monitor = app.status?.monitor;
  return h("dl", { class: "facts" },
    h("dt", {}, t("obs.last_valid")),
    h("dd", {}, scan ? [timeEl(scan.finished_at), " · ", t("scan.status." + scan.status), scan.issues.length ? h("span", { class: "warn-text" }, " · " + t("obs.issues", { n: scan.issues.length })) : null] : t("obs.none")),
    h("dt", {}, t("obs.watched")),
    h("dd", {}, obs.watched_share_24h === null ? t("obs.no_samples") : fmtPercent(obs.watched_share_24h)),
    h("dt", {}, t("obs.ports")),
    h("dd", {}, total ? t("obs.ports_value", { n: obs.ports_examined_devices, total }) : "—"),
    h("dt", {}, t("obs.monitor")),
    h("dd", {}, monitor?.enabled ? t("monitor.every", { s: monitor.interval }) : t("monitor.stopped")));
}

function render(root, summary) {
  const d = summary.devices;
  const network = (app.status?.networks || []).find((n) => n.id === app.network());
  replace(root,
    h("header", { class: "view-head" },
      h("h1", {}, t("overview.title")),
      h("p", { class: "muted" }, network ? (network.name || network.cidr) : t("network.all"))),
    nextAction(summary.next_action),
    h("div", { class: "tiles" },
      tile(t("overview.online"), `${fmtNumber(d.online)} / ${fmtNumber(d.total)}`, "/devices?status=online"),
      tile(t("overview.pending"), fmtNumber(summary.pending_review), "/review", { kind: summary.pending_review ? "warn" : "" }),
      tile(t("overview.untrusted"), fmtNumber(d.untrusted), "/devices?trusted=false", { kind: d.untrusted ? "warn" : "" }),
      tile(t("overview.high_risk"), fmtNumber(d.risk.high), "/devices?risk=high&sort=risk&order=desc", { kind: d.risk.high ? "alert" : "" }),
      tile(t("overview.incomplete"), fmtNumber(d.risk_incomplete), "/devices?incomplete=true", { hint: t("overview.incomplete_hint") }),
      tile(t("overview.open_ports"), fmtNumber(d.with_open_ports), "/devices?has_ports=true")),
    h("div", { class: "columns" },
      panel(t("overview.attention"), summary.top_cases.length
        ? h("ul", { class: "case-list" }, summary.top_cases.map((c) => h("li", {},
          riskBadge(c.device.risk), deviceLink(c.device), h("span", { class: "muted mono" }, c.device.ip),
          h("span", { class: "muted" }, c.events[0]?.message || ""))))
        : emptyState(t("overview.nothing_pending"), t("overview.nothing_pending_text")),
        h("a", { href: "/review", class: "btn small" }, t("overview.open_review"))),
      panel(t("overview.observation"), observation(summary))),
    panel(t("overview.recent"), summary.recent_events.length
      ? h("ul", { class: "event-list" }, summary.recent_events.map((e) => h("li", {},
        severityBadge(e.severity), timeEl(e.timestamp), h("span", { class: "event-msg" }, e.message))))
      : emptyState(t("events.none"), t("events.none_text")),
      h("a", { href: "/events", class: "btn small" }, t("overview.all_events"))));
}

export async function mount(root) {
  replace(root, loading());
  const load = async () => {
    try {
      render(root, await api.get("/api/v1/summary", { network: app.network() }));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(root, errorState(error, load));
    }
  };
  await load();
  return {
    refresh(changes) {
      if (changes.some((c) => RELEVANT.test(c.kind))) load();
    },
  };
}
