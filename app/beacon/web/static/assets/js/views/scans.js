// escaneos: run, cancel and schedule scans, and read the honest history of each one.

import { api } from "../api.js";
import { app } from "../app.js";
import { badge, emptyState, errorState, facts, field, loading, pager, panel, select, severityBadge, timeEl } from "../components.js";
import { h, replace, toast } from "../dom.js";
import { fmtDuration, fmtNumber, t } from "../i18n.js";
import { navigate, query, setQuery } from "../router.js";

const STATUS_KIND = { complete: "ok", partial: "warn", failed: "alert", cancelled: "", aborted: "alert", running: "accent" };

function statusBadge(status) {
  return badge(t("scan.status." + status), STATUS_KIND[status] || "");
}

function duration(scan) {
  if (!scan.finished_at) return "—";
  return fmtDuration((new Date(scan.finished_at) - new Date(scan.started_at)) / 1000);
}

export async function mount(root, { params }) {
  const control = h("div");
  const history = h("div");
  const detail = h("div");
  let profiles = [];
  let page = Number(query().page || 1);
  const compareSel = [];

  // run and schedule ->
  async function startScan(profileId) {
    try {
      const job = await api.post("/api/v1/jobs", profileId ? { profile_id: profileId } : {});
      toast(t("scans.queued", { id: job.id }), "ok");
      drawControl();
    } catch (error) {
      toast(error.status === 409 ? t("scans.busy", { reason: error.message }) : error.message, "error");
    }
  }

  async function cancelJob(id) {
    try {
      await api.del(`/api/v1/jobs/${id}`);
      toast(t("scans.cancelling"), "info");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function monitor(action, profileId, interval) {
    try {
      await api.post("/api/v1/monitor", action === "start" ? { action, profile_id: profileId, interval } : { action });
      toast(action === "start" ? t("monitor.started") : t("monitor.stopped_ok"), "ok");
      await app.reloadStatus();
      drawControl();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function drawControl() {
    const status = app.status;
    let jobs = [];
    try { jobs = (await api.get("/api/v1/jobs")).items; } catch { /* the status still says what runs */ }
    const m = status.monitor;
    const profileSel = select([["", t("scans.default_profile")], ...profiles.map((p) => [p.id, p.name])], m.profile_id ?? "", { id: "scan-profile" });
    const interval = h("input", { type: "number", min: "10", max: "86400", value: String(m.interval || app.settings.monitor_interval), id: "monitor-interval" });
    const active = jobs.filter((j) => j.state === "queued" || j.state === "running");
    const recent = jobs.filter((j) => !(j.state === "queued" || j.state === "running")).slice(0, 5);
    replace(control,
      panel(t("scans.run"), h("div", {},
        h("div", { class: "form-row" },
          field(t("scans.profile"), profileSel, { hint: t("scans.profile_hint") }),
          h("button", { type: "button", class: "btn primary", onClick: () => startScan(profileSel.value ? Number(profileSel.value) : null) }, t("scans.scan_now"))),
        h("div", { class: "form-row" },
          field(t("monitor.interval"), interval, { hint: t("monitor.interval_hint") }),
          m.enabled
            ? h("button", { type: "button", class: "btn", onClick: () => monitor("stop") }, t("monitor.stop"))
            : h("button", { type: "button", class: "btn", onClick: () => monitor("start", profileSel.value ? Number(profileSel.value) : null, Number(interval.value)) }, t("monitor.start"))),
        facts([
          [t("monitor.state"), [badge(t("monitor.state_" + m.state)), m.next_at ? [" · ", t("monitor.next"), " ", timeEl(m.next_at)] : null]],
          m.last_error ? [t("monitor.last_error"), h("span", { class: "warn-text" }, m.last_error)] : null,
          [t("monitor.passive"), t("monitor.passive_" + m.passive)],
          status.external.length ? [t("monitor.external"), status.external.map((x) => `${x.kind} (pid ${x.pid}) · ${x.scope.slice(4)}`).join(", ")] : null,
        ]),
        h("p", { class: "muted small" }, t("monitor.explain")),
        active.length ? h("ul", { class: "job-list" }, active.map((j) => h("li", {},
          badge(t("job." + j.state), j.state === "running" ? "accent" : ""), " ",
          j.stage ? `${j.stage} ${j.progress.total ? `${j.progress.done}/${j.progress.total}` : ""}` : t("job.waiting"),
          h("progress", { max: j.progress.total || 1, value: j.progress.total ? j.progress.done : undefined, "aria-label": t("job.progress") }),
          h("button", { type: "button", class: "btn small", onClick: () => cancelJob(j.id) }, t("common.cancel"))))) : null,
        recent.length ? h("details", {}, h("summary", {}, t("scans.recent_jobs")), h("ul", { class: "small" }, recent.map((j) => h("li", {},
          badge(t("job." + j.state), j.state === "failed" || j.state === "blocked" ? "alert" : ""), " ", timeEl(j.finished_at || j.created_at), " · ", t("trigger." + j.trigger),
          j.error ? h("span", { class: "warn-text" }, " · " + j.error) : null,
          j.scan_id ? [" · ", h("a", { href: "/scans/" + j.scan_id }, t("scans.open"))] : null)))) : null)));
  }

  // history ->
  async function loadHistory() {
    try {
      const data = await api.get("/api/v1/scans", { network: app.network(), page, size: 20, status: query().status });
      const pages = Math.max(1, Math.ceil(data.total / data.size));
      const statusFilter = select([["", t("scans.any_status")], ...["complete", "partial", "failed", "cancelled", "aborted"].map((s) => [s, t("scan.status." + s)])], query().status, { "aria-label": t("scans.status_filter") });
      statusFilter.onchange = () => { page = 1; setQuery({ status: statusFilter.value, page: "" }); loadHistory(); };
      const compareButton = h("button", { type: "button", class: "btn small", disabled: compareSel.length !== 2, onClick: () => {
        const [a, b] = [...compareSel].sort((x, y) => x - y);
        navigate(`/scans/${b}?compare=${a}`);
      } }, t("scans.compare", { n: compareSel.length }));
      replace(history, panel(t("scans.history"), data.items.length ? h("div", {},
        h("div", { class: "toolbar" }, statusFilter, compareButton),
        h("div", { class: "table-wrap" }, h("table", { class: "table" },
          h("caption", { class: "sr-only" }, t("scans.history")),
          h("thead", {}, h("tr", {}, h("th", { scope: "col" }, h("span", { class: "sr-only" }, t("scans.select"))), [t("scans.when"), t("scans.status"), t("scans.target"), t("scans.trigger"), t("scans.devices"), t("scans.events"), t("scans.duration"), t("scans.ports")].map((x) => h("th", { scope: "col" }, x)))),
          h("tbody", {}, data.items.map((s) => h("tr", {},
            h("td", {}, h("input", { type: "checkbox", checked: compareSel.includes(s.id), "aria-label": t("scans.select_one", { id: s.id }), onChange: (e) => {
              if (e.target.checked) { compareSel.push(s.id); if (compareSel.length > 2) compareSel.shift(); }
              else compareSel.splice(compareSel.indexOf(s.id), 1);
              loadHistory();
            } })),
            h("th", { scope: "row" }, h("a", { href: "/scans/" + s.id }, timeEl(s.started_at))),
            h("td", {}, statusBadge(s.status), s.issues.length ? h("span", { class: "muted small" }, " · " + t("obs.issues", { n: s.issues.length })) : null),
            h("td", { class: "mono" }, s.target || s.network || "—"),
            h("td", {}, t("trigger." + (s.trigger || "cli"))),
            h("td", {}, fmtNumber(s.device_count)),
            h("td", {}, fmtNumber(s.event_count)),
            h("td", {}, duration(s)),
            h("td", { class: "mono small" }, s.port_spec ? (s.port_spec.length > 24 ? s.port_spec.slice(0, 24) + "…" : s.port_spec) : "—")))))),
        pager(page, pages, (n) => { page = n; setQuery({ page: n > 1 ? n : "" }); loadHistory(); }))
        : emptyState(t("scans.none"), t("scans.none_text"))));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(history, errorState(error, loadHistory));
    }
  }

  // one scan, or a comparison ->
  async function loadDetail() {
    if (!params.id) { replace(detail); return; }
    const other = query().compare;
    try {
      if (other) {
        const c = await api.get("/api/v1/scans/compare", { before: other, after: params.id });
        replace(detail, panel(t("scans.comparison", { a: c.before.id, b: c.after.id }), h("div", {},
          c.caveats.length ? h("div", { class: "notice" }, h("p", {}, h("strong", {}, t("scans.caveats"))), h("ul", {}, c.caveats.map((x) => h("li", {}, x)))) : h("p", { class: "muted" }, t("scans.comparable")),
          facts([[t("scans.between"), fmtNumber(c.scans_between)], [t("scans.devices"), `${c.device_count.before} → ${c.device_count.after}`]]),
          ["added", "returned", "absent", "address", "exposure"].map((kind) => h("section", {},
            h("h3", {}, t("compare." + kind), " ", h("span", { class: "muted" }, fmtNumber(c.changes[kind].length))),
            c.changes[kind].length ? h("ul", { class: "event-list" }, c.changes[kind].map((e) => h("li", {}, severityBadge(e.severity), timeEl(e.timestamp), h("span", { class: "event-msg" }, e.message)))) : null)),
          h("a", { href: "/scans", class: "btn small" }, t("common.close")))));
        return;
      }
      const s = await api.get(`/api/v1/scans/${params.id}`);
      replace(detail, panel(t("scans.detail", { id: s.id }), h("div", {},
        facts([
          [t("scans.status"), statusBadge(s.status)],
          [t("scans.when"), timeEl(s.started_at)],
          [t("scans.duration"), duration(s)],
          [t("scans.target"), h("span", { class: "mono" }, s.target || "—")],
          [t("scans.mode"), s.mode || "—"],
          [t("scans.trigger"), t("trigger." + (s.trigger || "cli"))],
          [t("scans.ports"), s.port_spec ? h("span", { class: "mono small" }, s.port_spec) : t("scans.no_ports")],
          [t("scans.first_result"), s.first_result_ms !== null ? fmtDuration(s.first_result_ms / 1000) : "—"],
          [t("scans.unobserved"), s.unobserved ? h("span", { class: "warn-text" }, t("scans.unobserved_value", { n: s.unobserved })) : "0"],
          [t("scans.rules"), s.rules_version || "1"],
        ]),
        Object.keys(s.stages).length ? h("section", {}, h("h3", {}, t("scans.stages")), h("ol", { class: "stages" }, Object.entries(s.stages).map(([name, secs]) => h("li", {}, name, " · ", fmtDuration(secs))))) : null,
        s.issues.length ? h("section", {}, h("h3", {}, t("scans.issues")), h("ul", {}, s.issues.map((i) => h("li", { class: "warn-text" }, `${i.stage}${i.host ? " · " + i.host : ""}: ${i.message}`)))) : null,
        h("section", {}, h("h3", {}, t("scans.events_title")), s.events.length
          ? h("ul", { class: "event-list" }, s.events.map((e) => h("li", {}, severityBadge(e.severity), h("span", { class: "event-msg" }, e.message))))
          : h("p", { class: "muted" }, t("scans.no_events"))),
        h("a", { href: "/scans", class: "btn small" }, t("common.close")))));
    } catch (error) {
      replace(detail, errorState(error, loadDetail));
    }
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("scans.title")), h("p", { class: "muted" }, t("scans.intro"))), detail, control, history);
  replace(history, loading());
  try { profiles = (await api.get("/api/v1/profiles")).items; } catch { profiles = []; }
  await Promise.all([drawControl(), loadHistory(), loadDetail()]);
  const off = app.onStatus(() => {
    // keep the job progress current without touching the inputs being edited
    if (!control.contains(document.activeElement)) drawControl();
  });
  return {
    refresh(changes) {
      if (changes.some((c) => /^(scan\.(started|finished)|profile\.|reset)/.test(c.kind))) { loadHistory(); drawControl(); }
    },
    destroy: off,
  };
}
