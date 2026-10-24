// presencia: who was connected and when, next to when beacon was actually watching.

import { api, devicePath } from "../api.js";
import { app } from "../app.js";
import { presenceHeatmap, timeline } from "../charts.js";
import { deviceLink, emptyState, errorState, loading, panel } from "../components.js";
import { h, replace } from "../dom.js";
import { fmtPercent, t } from "../i18n.js";
import { query, setQuery } from "../router.js";

const WINDOWS = { "24h": 24, "3d": 72, "7d": 168 };

export async function mount(root) {
  let span = query().span in WINDOWS ? query().span : "24h";
  const overview = h("div");
  const detail = h("div");

  async function loadOverview() {
    replace(overview, loading());
    try {
      const data = await api.get("/api/v1/presence", { network: app.network(), hours: WINDOWS[span] });
      const rows = data.devices.map((d) => ({ label: d.device.name, sessions: d.sessions, key: d.device.key }));
      replace(overview,
        !data.enabled ? h("p", { class: "notice" }, t("presence.disabled")) : null,
        h("p", { class: "muted" }, t("presence.watched_share", { pct: data.watched_share === null ? "—" : fmtPercent(data.watched_share), tz: data.timezone })),
        rows.length
          ? timeline(t("presence.timeline"), rows, data.observation_windows, data.since, data.until)
          : emptyState(t("presence.nobody"), t("presence.nobody_text")),
        rows.length ? h("ul", { class: "inline-list" }, data.devices.map((d) => h("li", {},
          h("a", { href: "/presence?device=" + encodeURIComponent(d.device.key) + "&span=" + span }, d.device.name),
          d.profilable ? null : h("span", { class: "muted small" }, " · " + t("presence.fragmented_short"))))) : null);
    } catch (error) {
      if (error.status === 401) throw error;
      replace(overview, errorState(error, loadOverview));
    }
  }

  async function loadDetail() {
    const key = query().device;
    if (!key) { replace(detail); return; }
    replace(detail, loading());
    try {
      const data = await api.get(devicePath(key) + "/presence");
      replace(detail, panel(t("presence.device_title", { name: data.device.name }), h("div", {},
        h("p", {}, deviceLink(data.device, t("presence.open_device"))),
        h("p", {}, t("presence.status_" + data.status, { days: data.learning.days, need: data.learning.days_needed, sessions: data.learning.sessions, need_sessions: data.learning.sessions_needed })),
        data.schedule ? h("p", {}, t("presence.usual", { schedule: data.schedule })) : null,
        data.presence_while_watched !== null ? h("p", { class: "muted" }, t("presence.share_watched", { pct: fmtPercent(data.presence_while_watched) })) : null,
        data.monitored !== null ? h("p", { class: data.monitored_enough ? "muted" : "warn-text" }, t("presence.monitored", { pct: fmtPercent(data.monitored) }) + (data.monitored_enough ? "" : " " + t("presence.low_monitoring"))) : null,
        ["fragmented", "no-data"].includes(data.status) ? null : presenceHeatmap(t("presence.heatmap", { tz: data.timezone }), data.grid),
        h("p", { class: "muted small" }, t("presence.uncertainty")))));
    } catch (error) {
      replace(detail, errorState(error, loadDetail));
    }
  }

  const spans = h("div", { class: "segmented", role: "group", "aria-label": t("presence.window") }, Object.keys(WINDOWS).map((s) => h("button", {
    type: "button", class: "seg", "aria-pressed": String(s === span), onClick: (event) => {
      span = s;
      setQuery({ span: s === "24h" ? "" : s });
      for (const b of event.target.parentElement.children) b.setAttribute("aria-pressed", String(b === event.target));
      loadOverview();
    },
  }, s)));

  replace(root,
    h("header", { class: "view-head" }, h("h1", {}, t("presence.title")), h("p", { class: "muted" }, t("presence.intro"))),
    h("p", { class: "notice small" }, t("presence.privacy")),
    detail,
    panel(t("presence.timeline"), h("div", {}, spans, overview)));
  await Promise.all([loadOverview(), loadDetail()]);
  return {
    refresh(changes) {
      if (changes.some((c) => c.kind === "scan.finished" || c.kind === "reset")) { loadOverview(); loadDetail(); }
    },
  };
}
