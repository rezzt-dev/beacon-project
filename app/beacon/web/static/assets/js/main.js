// boot: session, settings, the shell (header, navigation), the live connection and the router.

import { api, ApiError, setCsrf } from "./api.js";
import { app, applyPreferences } from "./app.js";
import { tickTimes } from "./components.js";
import { $, announce, debounce, dialog, h, icon, replace, toast } from "./dom.js";
import { fmtRelative, setLocale, t } from "./i18n.js";
import { Live } from "./live.js";
import { navigate, route, start } from "./router.js";

const NAV = [
  ["nav.operation", [["/", "overview", "nav.overview"], ["/devices", "devices", "nav.devices"], ["/review", "review", "nav.review"], ["/events", "events", "nav.events"]]],
  ["nav.analysis", [["/presence", "presence", "nav.presence"], ["/identities", "identities", "nav.identities"], ["/services", "services", "nav.services"], ["/networks", "networks", "nav.networks"]]],
  ["nav.administration", [["/scans", "scans", "nav.scans"], ["/alerts", "alert", "nav.alerts"], ["/reports", "reports", "nav.reports"], ["/settings", "settings", "nav.settings"]]],
];

route("/", () => import("./views/overview.js"), { nav: "/" });
route("/welcome", () => import("./views/onboarding.js"), { nav: "/" });
route("/devices", () => import("./views/devices.js"), { nav: "/devices" });
route("/devices/:key", () => import("./views/device.js"), { nav: "/devices" });
route("/review", () => import("./views/review.js"), { nav: "/review" });
route("/events", () => import("./views/events.js"), { nav: "/events" });
route("/presence", () => import("./views/presence.js"), { nav: "/presence" });
route("/identities", () => import("./views/identities.js"), { nav: "/identities" });
route("/services", () => import("./views/services.js"), { nav: "/services" });
route("/networks", () => import("./views/networks.js"), { nav: "/networks" });
route("/scans", () => import("./views/scans.js"), { nav: "/scans" });
route("/scans/:id", () => import("./views/scans.js"), { nav: "/scans" });
route("/alerts", () => import("./views/alerts.js"), { nav: "/alerts" });
route("/reports", () => import("./views/reports.js"), { nav: "/reports" });
route("/settings", () => import("./views/settings.js"), { nav: "/settings" });
route("/404", () => import("./views/notfound.js"), {});

let mounted = null;
let mountToken = 0;
// the first view keeps the natural focus order (skip link first); later navigations focus the heading
let firstMount = true;

 // shell ->
function renderNav() {
  const nav = $("#sidebar");
  nav.setAttribute("aria-label", t("nav.label"));
  replace(nav, NAV.map(([group, items]) => h("div", { class: "nav-group" },
    h("h2", { class: "nav-title", id: "nav-" + group }, t(group)),
    h("ul", { "aria-labelledby": "nav-" + group }, items.map(([href, iconName, label]) => h("li", {},
      h("a", { href, class: "nav-link", dataset: { nav: href } }, icon(iconName), h("span", {}, t(label)),
        href === "/review" ? h("span", { class: "nav-count", id: "nav-review-count", hidden: true }) : null)))))));
  const menu = $("#menu-btn");
  replace(menu, icon("menu"));
  menu.setAttribute("aria-label", t("nav.menu"));
  menu.hidden = false;
  menu.onclick = () => toggleMenu();
  $(".skip-link").textContent = t("nav.skip");
}

function toggleMenu(force) {
  const open = force ?? !document.body.classList.contains("menu-open");
  document.body.classList.toggle("menu-open", open);
  $("#menu-btn").setAttribute("aria-expanded", String(open));
  if (open) $("#sidebar a")?.focus();
}

function markNav(navPath) {
  for (const link of document.querySelectorAll(".nav-link")) {
    if (link.dataset.nav === navPath) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

function renderSearch() {
  const form = $("#global-search");
  const input = h("input", { type: "search", id: "global-q", name: "q", placeholder: t("search.placeholder"), "aria-label": t("search.label"), autocomplete: "off", spellcheck: "false" });
  replace(form, icon("search"), input, h("kbd", { class: "kbd-hint", "aria-hidden": "true" }, "/"));
  form.onsubmit = (event) => {
    event.preventDefault();
    const q = input.value.trim();
    navigate("/devices" + (q ? "?q=" + encodeURIComponent(q) : ""));
  };
}

function renderNetworkSelect() {
  const slot = $("#network-slot");
  const networks = app.status?.networks || [];
  if (networks.length < 2) {
    const only = networks[0];
    replace(slot, only ? h("span", { class: "network-name", title: only.cidr }, only.name || only.cidr) : null);
    return;
  }
  const select = h("select", { id: "network-select", "aria-label": t("network.select") },
    h("option", { value: "" }, t("network.all")),
    networks.map((n) => h("option", { value: n.id, selected: n.id === app.network() }, n.name || n.cidr)));
  select.onchange = () => {
    app.setNetwork(select.value ? Number(select.value) : null);
    remount();
  };
  replace(slot, select);
}

const HEALTH = {
  ok: ["ok", "●"], scanning: ["accent", "◌"], idle: ["", "○"], empty: ["", "○"],
  stale: ["warn", "!"], failing: ["alert", "✗"], blocked: ["warn", "!"],
};

function renderHealth() {
  const status = app.status;
  if (!status) return;
  const health = status.health;
  const [kind, symbol] = HEALTH[health.state] || HEALTH.idle;
  const running = status.running;
  const detail = running
    ? t("health.stage", { stage: running.stage || "…", done: running.progress.done, total: running.progress.total ?? "?" })
    : health.last_valid_at ? t("health.last_valid", { when: fmtRelative(health.last_valid_at) }) : t("health.no_valid");
  replace($("#health"),
    h("a", { href: "/scans", class: ["health-pill", kind], title: health.message },
      h("span", { class: "health-symbol", "aria-hidden": "true" }, symbol),
      h("span", { class: "health-label" }, t("health." + health.state)),
      h("span", { class: "health-detail" }, detail)));
  const count = $("#nav-review-count");
  if (count) {
    count.hidden = !status.pending_review;
    count.textContent = status.pending_review ? String(status.pending_review) : "";
    count.setAttribute("aria-label", t("review.pending_count", { n: status.pending_review || 0 }));
  }
  document.title = (status.pending_review ? `(${status.pending_review}) ` : "") + "beacon live";
}

function renderLiveState(state, info) {
  const host = $("#live-state");
  const paused = info.paused;
  const label = paused ? t("live.paused", { n: info.pending }) : t("live." + state, { s: info.retryIn ?? "" });
  replace(host,
    h("span", { class: ["live-dot", state, paused ? "paused" : ""], "aria-hidden": "true" }),
    h("span", { class: "live-label" }, label),
    h("button", {
      type: "button",
      class: "icon-btn",
      "aria-pressed": String(paused),
      title: paused ? t("live.resume_hint") : t("live.pause_hint"),
      "aria-label": paused ? t("live.resume") : t("live.pause"),
      onClick: () => (paused ? app.live.resume() : app.live.pause()),
    }, icon(paused ? "play" : "pause")));
}

 // views ->
async function mountView(match) {
  const token = ++mountToken;
  toggleMenu(false);
  if (mounted?.destroy) mounted.destroy();
  mounted = null;
  markNav(match.meta.nav);
  const main = $("#main");
  replace(main, h("div", { class: "loading" }, h("span", { class: "spinner", "aria-hidden": "true" }), t("common.loading")));
  let module;
  try {
    module = await match.loader();
  } catch (error) {
    replace(main, h("p", { class: "empty" }, t("error.load_view")));
    return;
  }
  if (token !== mountToken) return;
  const root = h("div", { class: "view" });
  replace(main, root);
  try {
    mounted = (await module.mount(root, { params: match.params })) || {};
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return signedOut();
    console.error(error);
    replace(root, h("div", { class: "empty error", role: "alert" }, h("p", { class: "empty-title" }, t("error.title")), h("p", {}, error.message)));
    return;
  }
  if (token !== mountToken) return;
  const heading = root.querySelector("h1");
  const initial = firstMount;
  firstMount = false;
  if (heading && !initial && document.activeElement !== $("#global-q")) {
    heading.tabIndex = -1;
    heading.focus({ preventScroll: true });
  }
  window.scrollTo(0, 0);
}

function remount() {
  renderNetworkSelect();
  const current = location.pathname + location.search;
  history.replaceState(null, "", current);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

const pendingChanges = [];
const flushChanges = debounce(() => {
  const batch = pendingChanges.splice(0);
  if (mounted?.refresh) mounted.refresh(batch);
}, 300);

 // signed out ->
function signedOut() {
  app.live?.close();
  replace($("#main"), h("div", { class: "empty" },
    h("h1", {}, t("session.signed_out")),
    h("p", {}, t("session.signed_out_text")),
    h("pre", { class: "code" }, "beacon live --url")));
}

 // keyboard ->
function shortcuts() {
  let prefix = null;
  document.addEventListener("keydown", (event) => {
    const target = event.target;
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (target.closest("input, textarea, select, [contenteditable]") || document.querySelector(".backdrop")) return;
    if (prefix === "g") {
      prefix = null;
      const go = { o: "/", d: "/devices", r: "/review", e: "/events", p: "/presence", i: "/identities", s: "/services", n: "/networks", c: "/scans", a: "/alerts", h: "/reports", t: "/settings" }[event.key];
      if (go) { event.preventDefault(); navigate(go); }
      return;
    }
    if (event.key === "/") { event.preventDefault(); $("#global-q")?.focus(); }
    else if (event.key === "g") { prefix = "g"; setTimeout(() => { prefix = null; }, 1500); }
    else if (event.key === "p") { event.preventDefault(); app.live.paused ? app.live.resume() : app.live.pause(); }
    else if (event.key === "?") { event.preventDefault(); showShortcuts(); }
  });
}

function showShortcuts() {
  const rows = [
    ["/", t("keys.search")], ["g o", t("nav.overview")], ["g d", t("nav.devices")], ["g r", t("nav.review")],
    ["g e", t("nav.events")], ["g p", t("nav.presence")], ["g i", t("nav.identities")], ["g s", t("nav.services")],
    ["g n", t("nav.networks")], ["g c", t("nav.scans")], ["g a", t("nav.alerts")], ["g h", t("nav.reports")], ["g t", t("nav.settings")],
    ["p", t("keys.pause")], ["?", t("keys.help")], ["Esc", t("keys.close")],
  ];
  dialog(t("keys.title"), h("table", { class: "table compact" },
    h("caption", { class: "sr-only" }, t("keys.title")),
    h("tbody", {}, rows.map(([key, label]) => h("tr", {}, h("th", { scope: "row" }, h("kbd", {}, key)), h("td", {}, label))))));
}

 // boot ->
async function boot() {
  let session;
  try {
    session = await api.get("/api/v1/session");
  } catch (error) {
    setLocale("auto");
    renderNav();
    if (error.status === 401) return signedOut();
    replace($("#main"), h("p", { class: "empty" }, t("error.offline_text")));
    return;
  }
  setCsrf(session.csrf);
  app.settings = await api.get("/api/v1/settings");
  applyPreferences(app.settings);
  renderNav();
  renderSearch();
  app.onStatus(() => { renderHealth(); });
  await app.reloadStatus();
  renderNetworkSelect();
  let knownNetworks = (app.status.networks || []).length;
  app.live = new Live({
    onChange: (changes) => {
      if (pendingChanges.length + changes.length > 1000 || changes.some((c) => c.kind === "retention.applied")) {
        pendingChanges.splice(0, pendingChanges.length, { kind: "reset" });
      } else if (!pendingChanges.some((c) => c.kind === "reset")) {
        pendingChanges.push(...changes);
      }
      if (changes.some((c) => c.kind.startsWith("network."))) app.reloadStatus().then(renderNetworkSelect);
      if (changes.some((c) => c.kind === "settings.updated")) {
        api.get("/api/v1/settings").then((s) => { app.settings = s; applyPreferences(s); });
      }
      flushChanges();
    },
    onStatus: (status) => {
      app.setStatus(status);
      if ((status.networks || []).length !== knownNetworks) {
        knownNetworks = (status.networks || []).length;
        renderNetworkSelect();
      }
    },
    onReset: () => {
      announce(t("live.reloaded"));
      app.reloadStatus();
      if (mounted?.refresh) mounted.refresh([{ kind: "reset" }]);
    },
    onState: (state, info) => {
      renderLiveState(state, info);
      if (state === "reconnecting" && info.attempt === 1) announce(t("live.lost"), false);
    },
  });
  app.live.connect();
  shortcuts();
  setInterval(() => tickTimes(), 15000);
  window.addEventListener("beacon:unauthorized", signedOut);
  start(mountView);
  if (!app.status.onboarded && app.status.health.state === "empty" && location.pathname === "/") navigate("/welcome", { replace: true });
}

boot().catch((error) => {
  console.error(error);
  toast(error.message || "beacon live failed to start", "error");
});
