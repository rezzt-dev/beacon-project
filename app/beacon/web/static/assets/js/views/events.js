// eventos: a filterable timeline. repetitions are grouped, new events are announced instead of
// pushing the list around, and each event links to its device and its scan.

import { api } from "../api.js";
import { app } from "../app.js";
import { badge, emptyState, errorState, loading, select, severityBadge, timeEl } from "../components.js";
import { debounce, h, replace, toast } from "../dom.js";
import { fmtDateTime, fmtNumber, t } from "../i18n.js";
import { devicePage, query, setQuery } from "../router.js";

const TYPES = [
  "new-device", "device-online", "device-offline", "ip-changed", "port-opened", "port-closed", "ip-conflict",
  "identity-candidate", "unusual-presence", "routine-broken", "scan-failed", "scan-partial",
];
const DETAIL_KEYS = ["port", "service", "protocol_observed", "first_check", "old_ip", "new_ip", "score", "evidence", "candidate_key", "macs", "risk", "frequency", "coverage", "missing_seconds", "issues"];

function group(items) {
  const groups = [];
  for (const event of items) {
    const last = groups[groups.length - 1];
    if (last && last.type === event.type && last.device_key === event.device_key && last.severity === event.severity && event.type !== "new-device") {
      last.repeats.push(event);
    } else {
      groups.push({ ...event, repeats: [] });
    }
  }
  return groups;
}

export async function mount(root) {
  const q = query();
  let items = [];
  let nextBefore = null;
  let total = 0;
  let newCount = 0;
  const list = h("ol", { class: "timeline-list" });
  const more = h("div", { class: "more" });
  const counter = h("p", { class: "muted", "aria-live": "polite" });
  const newBanner = h("button", { type: "button", class: "btn small new-events", hidden: true, onClick: () => load() });

  const text = h("input", { type: "search", value: q.q || "", placeholder: t("events.search"), "aria-label": t("events.search") });
  const type = select([["", t("events.any_type")], ...TYPES.map((x) => [x, t("event." + x)])], q.type, { "aria-label": t("events.type") });
  const severity = select([["", t("events.any_severity")], ["alert", t("severity.alert")], ["warning", t("severity.warning")], ["info", t("severity.info")]], q.severity, { "aria-label": t("events.severity") });
  const acked = select([["", t("events.any_review")], ["false", t("events.unreviewed")], ["true", t("events.reviewed")]], q.acked, { "aria-label": t("events.review_state") });
  const since = h("input", { type: "date", value: q.since ? q.since.slice(0, 10) : "", "aria-label": t("events.since") });
  const until = h("input", { type: "date", value: q.until ? q.until.slice(0, 10) : "", "aria-label": t("events.until") });
  const grouped = h("input", { type: "checkbox", checked: q.group !== "0" });

  const toIso = (value, end = false) => {
    if (!value) return "";
    const date = new Date(value + (end ? "T23:59:59" : "T00:00:00"));
    return date.toISOString();
  };
  const apply = () => {
    setQuery({ q: text.value.trim(), type: type.value, severity: severity.value, acked: acked.value, since: toIso(since.value), until: toIso(until.value, true), group: grouped.checked ? "" : "0" });
    load();
  };
  text.addEventListener("input", debounce(apply, 300));
  for (const el of [type, severity, acked, since, until]) el.onchange = apply;
  grouped.onchange = () => { setQuery({ group: grouped.checked ? "" : "0" }); draw(); };

  function params(before) {
    const current = query();
    return {
      network: app.network(), q: current.q, type: current.type, severity: current.severity, acked: current.acked,
      since: current.since, until: current.until, device: current.device, before, size: 50,
    };
  }

  function details(event) {
    const rows = DETAIL_KEYS.filter((k) => event.details[k] !== undefined && event.details[k] !== null)
      .map((k) => [h("dt", {}, t("detail." + k)), h("dd", {}, Array.isArray(event.details[k]) ? event.details[k].join(", ") : String(event.details[k]))]);
    return h("div", { class: "event-detail" },
      h("dl", { class: "facts" }, h("dt", {}, t("events.when")), h("dd", {}, fmtDateTime(event.timestamp, true)),
        event.ip ? [h("dt", {}, "ip"), h("dd", { class: "mono" }, event.ip)] : null,
        event.mac ? [h("dt", {}, "mac"), h("dd", { class: "mono" }, event.mac)] : null, rows),
      h("div", { class: "actions" },
        event.device_key ? h("a", { class: "btn small", href: devicePage(event.device_key) }, t("events.open_device")) : null,
        event.scan_id ? h("a", { class: "btn small", href: "/scans/" + event.scan_id }, t("events.open_scan")) : null,
        !event.acked_at && event.severity !== "info" ? h("button", { type: "button", class: "btn small", onClick: async () => {
          try {
            await api.post(`/api/v1/events/${event.id}/ack`, {});
            toast(t("events.acked_ok"), "ok");
            load();
          } catch (error) { toast(error.message, "error"); }
        } }, t("events.ack")) : null));
  }

  function draw() {
    const shown = grouped.checked ? group(items) : items.map((e) => ({ ...e, repeats: [] }));
    replace(counter, t("events.count", { n: fmtNumber(total) }));
    if (!items.length) {
      replace(list, h("li", {}, emptyState(t("events.no_match"), t("events.no_match_text"))));
      replace(more);
      return;
    }
    replace(list, shown.map((event) => h("li", { class: ["timeline-item", event.severity] },
      h("details", {},
        h("summary", {},
          severityBadge(event.severity),
          h("span", { class: "event-type" }, t("event." + event.type)),
          h("span", { class: "event-msg" }, event.message),
          event.repeats.length ? badge(t("events.repeated", { n: event.repeats.length + 1 })) : null,
          event.acked_at ? badge(t("events.reviewed"), "", "✓") : null,
          timeEl(event.timestamp)),
        details(event),
        event.repeats.length ? h("ul", { class: "repeats small" }, event.repeats.map((r) => h("li", {}, timeEl(r.timestamp), " · ", r.message))) : null))));
    replace(more, nextBefore ? h("button", { type: "button", class: "btn", onClick: loadMore }, t("events.load_more")) : null);
  }

  async function load() {
    newCount = 0;
    newBanner.hidden = true;
    try {
      const data = await api.get("/api/v1/events", params());
      items = data.items;
      nextBefore = data.next_before;
      total = data.total;
      draw();
    } catch (error) {
      if (error.status === 401) throw error;
      replace(list, h("li", {}, errorState(error, load)));
    }
  }

  async function loadMore() {
    try {
      const data = await api.get("/api/v1/events", params(nextBefore));
      items = items.concat(data.items);
      nextBefore = data.next_before;
      draw();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  const deviceFilter = q.device ? h("p", { class: "notice" }, t("events.device_filter"), " ", h("a", { href: devicePage(q.device) }, q.device), " · ",
    h("a", { href: "/events" }, t("filter.clear"))) : null;
  replace(root,
    h("header", { class: "view-head" }, h("h1", {}, t("events.title")), counter),
    deviceFilter,
    h("form", { class: "filters", role: "search", onSubmit: (e) => e.preventDefault() },
      text, type, severity, acked,
      h("label", { class: "filter" }, h("span", {}, t("events.since")), since),
      h("label", { class: "filter" }, h("span", {}, t("events.until")), until),
      h("label", { class: "check" }, grouped, t("events.group"))),
    newBanner, list, more);
  replace(list, h("li", {}, loading()));
  await load();
  return {
    refresh(changes) {
      if (changes.some((c) => c.kind === "reset")) return load();
      const created = changes.filter((c) => c.kind === "scan.finished" || c.kind === "event.created");
      if (!created.length) return;
      // never move the list under the reader: offer the new events instead
      newCount += created.reduce((n, c) => n + (c.data?.events ?? c.data?.count ?? 1), 0);
      if (newCount > 0) {
        newBanner.hidden = false;
        newBanner.textContent = t("events.new", { n: newCount });
      }
    },
  };
}
