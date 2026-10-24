// dispositivos: search, combinable filters, sort, configurable columns, saved views, pages and
// bulk actions on an explicit selection (kept across pages and live updates).

import { api } from "../api.js";
import { app } from "../app.js";
import {
  deviceLink, emptyState, errorState, latencyText, loading, pager, portChips, riskBadge, select, statusBadge, timeEl, trustBadge,
} from "../components.js";
import { announce, debounce, dialog, h, icon, replace, toast } from "../dom.js";
import { fmtNumber, t } from "../i18n.js";
import { query, setQuery } from "../router.js";

const COLUMNS_KEY = "beacon.devices.columns";
const VIEWS_KEY = "beacon.devices.views";
const FILTERS = ["q", "status", "trusted", "risk", "has_ports", "incomplete", "tag", "essential", "port", "sort", "order", "page", "size"];
const ALL_COLUMNS = ["address", "hostname", "status", "trust", "risk", "ports", "latency", "labels", "last_seen"];
const DEFAULT_COLUMNS = ["address", "hostname", "status", "risk", "ports", "latency", "last_seen"];
const SORTABLE = { name: "name", address: "ip", risk: "risk", latency: "latency", last_seen: "last_seen", status: "status" };

function stored(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key));
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function store(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* private mode */ }
}

export async function mount(root) {
  let columns = stored(COLUMNS_KEY, DEFAULT_COLUMNS).filter((c) => ALL_COLUMNS.includes(c));
  const selection = new Set();
  let page = null;
  let loadSeq = 0;

  const filters = () => {
    const q = query();
    return Object.fromEntries(FILTERS.map((k) => [k, q[k] ?? ""]));
  };

  const results = h("div", { class: "results", "aria-live": "off" });
  const selectionBar = h("div", { class: "selection-bar", hidden: true, role: "region", "aria-label": t("bulk.region") });
  const summary = h("p", { class: "result-summary", "aria-live": "polite" });

  // filter form: rendered once, so typing is never interrupted by live updates
  const f = filters();
  const search = h("input", { type: "search", id: "devices-q", value: f.q, placeholder: t("devices.search_placeholder"), autocomplete: "off", spellcheck: "false" });
  const status = select([["", t("filter.any_status")], ["online", t("status.online")], ["offline", t("status.offline")]], f.status, { id: "f-status" });
  const trusted = select([["", t("filter.any_trust")], ["false", t("trust.untrusted")], ["true", t("trust.trusted")]], f.trusted, { id: "f-trusted" });
  const risk = select([["", t("filter.any_risk")], ["medium", t("filter.risk_medium_up")], ["high", t("risk.high")]], f.risk, { id: "f-risk" });
  const ports = select([["", t("filter.any_ports")], ["true", t("filter.with_ports")], ["false", t("filter.without_ports")]], f.has_ports, { id: "f-ports" });
  const incomplete = select([["", t("filter.any_coverage")], ["true", t("filter.incomplete")], ["false", t("filter.complete")]], f.incomplete, { id: "f-incomplete" });
  const sort = select([["ip", t("sort.ip")], ["name", t("sort.name")], ["risk", t("sort.risk")], ["last_seen", t("sort.last_seen")], ["latency", t("sort.latency")], ["status", t("sort.status")]], f.sort || "ip", { id: "f-sort" });
  const order = select([["", t("sort.asc")], ["desc", t("sort.desc")]], f.order, { id: "f-order" });

  const onFilter = (patch) => {
    setQuery({ ...patch, page: "" });
    load();
  };
  search.addEventListener("input", debounce(() => onFilter({ q: search.value.trim() }), 75));
  search.addEventListener("keydown", (e) => { if (e.key === "Escape" && search.value) { search.value = ""; onFilter({ q: "" }); } });
  status.onchange = () => onFilter({ status: status.value });
  trusted.onchange = () => onFilter({ trusted: trusted.value });
  risk.onchange = () => onFilter({ risk: risk.value });
  ports.onchange = () => onFilter({ has_ports: ports.value });
  incomplete.onchange = () => onFilter({ incomplete: incomplete.value });
  sort.onchange = () => onFilter({ sort: sort.value });
  order.onchange = () => onFilter({ order: order.value });

  const label = (text, control) => h("label", { class: "filter" }, h("span", {}, text), control);
  const filterBar = h("form", { class: "filters", role: "search", "aria-label": t("devices.filters"), onSubmit: (e) => e.preventDefault() },
    label(t("devices.search"), search),
    h("details", { class: "more-filters", open: matchMedia("(min-width: 760px)").matches || Object.values(f).some((v, i) => v && i > 0) },
      h("summary", {}, t("devices.filters")),
      h("div", { class: "more-filters-body" },
        label(t("filter.status"), status), label(t("filter.trust"), trusted), label(t("filter.risk"), risk),
        label(t("filter.ports"), ports), label(t("filter.coverage"), incomplete), label(t("sort.by"), sort), label(t("sort.order"), order))),
    h("div", { class: "filter-actions" },
      h("button", { type: "button", class: "btn small", onClick: clearFilters }, t("filter.clear")),
      h("button", { type: "button", class: "btn small", onClick: saveView }, t("views.save")),
      h("button", { type: "button", class: "btn small", onClick: chooseColumns }, t("columns.choose"))));

  const savedViews = h("div", { class: "saved-views" });

  function clearFilters() {
    history.replaceState(null, "", "/devices");
    for (const el of [status, trusted, risk, ports, incomplete, order]) el.value = "";
    sort.value = "ip";
    search.value = "";
    load();
  }

  function renderSavedViews() {
    const views = stored(VIEWS_KEY, []);
    replace(savedViews, views.length ? [h("span", { class: "muted" }, t("views.saved")), views.map((v, i) => h("span", { class: "saved-view" },
      h("a", { href: "/devices" + v.search }, v.name),
      h("button", { type: "button", class: "icon-btn small", "aria-label": t("views.delete", { name: v.name }), onClick: () => {
        const all = stored(VIEWS_KEY, []);
        all.splice(i, 1);
        store(VIEWS_KEY, all);
        renderSavedViews();
      } }, icon("close"))))] : null);
  }

  function saveView() {
    const input = h("input", { type: "text", maxlength: "40", required: true });
    dialog(t("views.save"), h("div", {}, h("label", {}, t("views.name"), input)), [
      { label: t("common.cancel") },
      { label: t("common.save"), primary: true, run: () => {
        const name = input.value.trim();
        if (!name) { input.focus(); return false; }
        const params = new URLSearchParams(location.search);
        params.delete("page");
        const all = stored(VIEWS_KEY, []).filter((v) => v.name !== name);
        all.push({ name, search: params.toString() ? "?" + params : "" });
        store(VIEWS_KEY, all.slice(-12));
        renderSavedViews();
        toast(t("views.saved_ok", { name }), "ok");
      } },
    ]);
  }

  function chooseColumns() {
    const boxes = ALL_COLUMNS.map((c) => h("label", { class: "check" }, h("input", { type: "checkbox", value: c, checked: columns.includes(c) }), t("col." + c)));
    dialog(t("columns.choose"), h("fieldset", { class: "checks" }, h("legend", {}, t("columns.legend")), boxes), [
      { label: t("common.cancel") },
      { label: t("columns.reset"), run: () => { columns = [...DEFAULT_COLUMNS]; store(COLUMNS_KEY, columns); draw(); } },
      { label: t("common.apply"), primary: true, run: () => {
        columns = boxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
        store(COLUMNS_KEY, columns);
        draw();
      } },
    ]);
  }

  // results ->
  function cell(device, column) {
    switch (column) {
      case "address": return [h("div", { class: "mono" }, device.ip), h("div", { class: "muted mono small" }, device.mac || t("devices.no_mac"))];
      case "hostname": return device.hostname ? [h("div", { class: "mono" }, device.hostname), h("div", { class: "muted small" }, t("devices.via", { source: device.hostname_source }))] : h("span", { class: "muted" }, "—");
      case "status": return statusBadge(device);
      case "trust": return trustBadge(device);
      case "risk": return riskBadge(device.risk);
      case "ports": return portChips(device.open_ports);
      case "latency": return latencyText(device.latency);
      case "labels": return [device.category ? h("span", { class: "chip" }, device.category) : null, ...device.tags.map((tag) => h("span", { class: "chip tag" }, "#" + tag))];
      case "last_seen": return timeEl(device.last_seen);
      default: return "—";
    }
  }

  function nameCell(device) {
    const flags = [
      device.is_gateway ? t("devices.gateway") : null,
      device.is_local ? t("devices.this_host") : null,
      device.identity_id !== null ? t("devices.linked") : null,
      device.essential ? t("devices.essential") : null,
      device.snoozed_until ? t("devices.snoozed") : null,
    ].filter(Boolean);
    return [h("div", {}, deviceLink(device), flags.map((flag) => h("span", { class: "tag-flag" }, flag))),
      h("div", { class: "muted small" }, device.vendor || (device.randomized_mac ? t("devices.randomized") : t("devices.unknown_vendor")))];
  }

  function header(column) {
    const key = SORTABLE[column];
    const current = (filters().sort || "ip") === key;
    const desc = filters().order === "desc";
    const labelText = column === "name" ? t("col.device") : t("col." + column);
    return h("th", { scope: "col", "aria-sort": current ? (desc ? "descending" : "ascending") : undefined },
      key ? h("button", { type: "button", class: "sort-btn", onClick: () => {
        const nextOrder = current && !desc ? "desc" : "";
        sort.value = key;
        order.value = nextOrder;
        onFilter({ sort: key, order: nextOrder });
      } }, labelText, h("span", { "aria-hidden": "true" }, current ? (desc ? " ↓" : " ↑") : "")) : labelText);
  }

  function draw() {
    if (!page) return;
    const pageKeys = page.items.map((d) => d.key);
    const allOnPage = pageKeys.length > 0 && pageKeys.every((k) => selection.has(k));
    const focusedKey = document.activeElement?.closest?.("tr[data-key]")?.dataset.key;
    const focusedRole = document.activeElement?.dataset?.role;
    replace(summary, t("devices.summary", { n: fmtNumber(page.total), online: fmtNumber(page.facets.online), untrusted: fmtNumber(page.facets.untrusted) }));
    if (!page.items.length) {
      const filtered = Object.entries(filters()).some(([k, v]) => v && !["sort", "order", "page", "size"].includes(k));
      replace(results, filtered
        ? emptyState(t("devices.no_match"), t("devices.no_match_text"), { label: t("filter.clear"), run: clearFilters })
        : emptyState(t("devices.empty"), t("devices.empty_text"), { label: t("devices.run_scan"), href: "/scans" }));
      renderSelection();
      return;
    }
    const selectPage = h("input", { type: "checkbox", "aria-label": t("bulk.select_page"), checked: allOnPage, dataset: { role: "select-page" }, onChange: (e) => {
      for (const key of pageKeys) e.target.checked ? selection.add(key) : selection.delete(key);
      draw();
    } });
    const table = h("table", { class: "table devices" },
      h("caption", { class: "sr-only" }, t("devices.caption")),
      h("thead", {}, h("tr", {}, h("th", { scope: "col", class: "select-col" }, selectPage), header("name"), columns.map(header))),
      h("tbody", {}, page.items.map((device) => h("tr", { dataset: { key: device.key }, class: [device.status !== "online" ? "is-offline" : "", selection.has(device.key) ? "is-selected" : ""] },
        h("td", { class: "select-col" }, h("input", { type: "checkbox", checked: selection.has(device.key), "aria-label": t("bulk.select_one", { name: device.name }), dataset: { role: "select" }, onChange: (e) => {
          e.target.checked ? selection.add(device.key) : selection.delete(device.key);
          draw();
        } })),
        h("td", { class: "name-col", "data-label": t("col.device") }, nameCell(device)),
        columns.map((c) => h("td", { "data-label": t("col." + c) }, cell(device, c)))))));
    replace(results, h("div", { class: "table-wrap" }, table), pager(page.page, page.pages, (n) => { setQuery({ page: n > 1 ? n : "" }); load(); }));
    if (focusedKey) {
      const row = results.querySelector(`tr[data-key="${CSS.escape(focusedKey)}"]`);
      const target = row?.querySelector(focusedRole ? `[data-role="${focusedRole}"]` : "a");
      if (target) target.focus({ preventScroll: true });
    }
    renderSelection();
  }

  // selection and bulk actions ->
  function renderSelection() {
    selectionBar.hidden = selection.size === 0;
    if (!selection.size) { replace(selectionBar); return; }
    const onPage = page ? page.items.filter((d) => selection.has(d.key)).length : 0;
    const action = select([
      ["", t("bulk.choose")], ["trust", t("bulk.trust")], ["untrust", t("bulk.untrust")], ["ack", t("bulk.ack")],
      ["snooze", t("bulk.snooze")], ["tag", t("bulk.tag")], ["untag", t("bulk.untag")], ["essential", t("bulk.essential")],
    ], "", { "aria-label": t("bulk.action") });
    replace(selectionBar,
      h("strong", {}, t("bulk.selected", { n: selection.size, page: onPage })),
      page && page.total > selection.size ? h("button", { type: "button", class: "btn small", onClick: selectAllMatching }, t("bulk.select_all", { n: page.total })) : null,
      h("button", { type: "button", class: "btn small", onClick: () => { selection.clear(); draw(); } }, t("bulk.clear")),
      action,
      h("button", { type: "button", class: "btn small primary", onClick: () => action.value && confirmBulk(action.value) }, t("bulk.apply")));
  }

  async function selectAllMatching() {
    const f = filters();
    try {
      const data = await api.get("/api/v1/devices", { ...f, page: "", size: "", keys_only: "true", network: app.network() });
      data.keys.forEach((k) => selection.add(k));
      if (data.truncated) toast(t("bulk.truncated", { n: data.keys.length, total: data.total }), "info");
      announce(t("bulk.selected", { n: selection.size, page: 0 }));
      draw();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function confirmBulk(action) {
    const keys = [...selection];
    const extra = {};
    let input = null;
    if (action === "tag" || action === "untag") input = h("input", { type: "text", maxlength: "32", required: true });
    if (action === "snooze") input = h("input", { type: "number", min: "1", max: "2160", value: "24", required: true });
    const body = h("div", {},
      h("p", {}, t("bulk.confirm", { action: t("bulk." + action), n: keys.length })),
      action === "trust" ? h("p", { class: "warn-text" }, t("bulk.trust_warning")) : null,
      input ? h("label", { class: "field" }, action === "snooze" ? t("bulk.hours") : t("bulk.tag_name"), input) : null,
      h("details", {}, h("summary", {}, t("bulk.show_selected")), h("ul", { class: "small mono" }, keys.slice(0, 200).map((k) => h("li", {}, k)))));
    dialog(t("bulk.title"), body, [
      { label: t("common.cancel") },
      { label: t("bulk.apply"), primary: true, run: async () => {
        if (input) {
          if (!input.value.trim()) { input.focus(); return false; }
          if (action === "snooze") extra.until = Number(input.value);
          else extra.tag = input.value.trim();
        }
        try {
          const result = await api.post("/api/v1/devices/bulk", { keys, action, ...extra });
          showResults(result);
          result.results.filter((r) => r.ok).forEach((r) => selection.delete(r.key));
          load();
        } catch (error) {
          toast(error.message, "error");
          return false;
        }
      } },
    ]);
  }

  function showResults(result) {
    const failed = result.results.filter((r) => !r.ok);
    toast(t("bulk.done", { ok: result.ok, failed: result.failed }), failed.length ? "error" : "ok");
    if (failed.length) {
      dialog(t("bulk.failures"), h("ul", {}, failed.map((r) => h("li", {}, h("span", { class: "mono" }, r.key), ": ", r.error))), [{ label: t("common.close"), primary: true }]);
    }
  }

  async function load() {
    const seq = ++loadSeq;
    try {
      const data = await api.get("/api/v1/devices", { ...filters(), network: app.network() });
      if (seq !== loadSeq) return;
      page = data;
      draw();
    } catch (error) {
      if (error.status === 401) throw error;
      if (seq === loadSeq) replace(results, errorState(error, load));
    }
  }

  replace(root,
    h("header", { class: "view-head" }, h("h1", {}, t("devices.title")), summary),
    filterBar, savedViews, selectionBar, results);
  renderSavedViews();
  replace(results, loading());
  await load();
  return {
    refresh(changes) {
      if (changes.some((c) => /^(device\.|scan\.finished|identity\.|event\.acked|reset)/.test(c.kind))) load();
    },
  };
}
