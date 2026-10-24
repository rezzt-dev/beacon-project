// revisión: devices waiting for a decision, riskiest first, with the evidence and the context.

import { api, devicePath } from "../api.js";
import { app } from "../app.js";
import { badge, deviceLink, emptyState, errorState, facts, field, loading, pager, riskExplain, severityBadge, timeEl } from "../components.js";
import { announce, dialog, h, replace, toast } from "../dom.js";
import { fmtDateTime, t } from "../i18n.js";
import { query, setQuery } from "../router.js";

function suggestAlias(device) {
  if (device.hostname) return device.hostname.split(".")[0];
  const vendor = (device.vendor || "").toLowerCase().split(" ")[0].replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return `${vendor || "device"}-${device.ip.split(".").pop()}`;
}

export async function mount(root) {
  const list = h("div", { class: "cases" });
  const counter = h("p", { class: "muted", "aria-live": "polite" });
  const showSnoozed = h("input", { type: "checkbox", checked: query().snoozed === "true" });
  showSnoozed.onchange = () => { setQuery({ snoozed: showSnoozed.checked ? "true" : "", page: "" }); load(); };
  let cases = [];
  let total = 0;
  let currentPage = 1;
  let loadSeq = 0;
  const pagination = h("div");
  // our own decisions come back as live changes: the list is already up to date, keep the focus
  let quietUntil = 0;

  async function decide(device, run, message, card) {
    const next = card.nextElementSibling || card.previousElementSibling;
    try {
      quietUntil = Date.now() + 3000;
      await run();
      toast(message, "ok");
      announce(message);
      card.remove();
      total = Math.max(0, total - 1);
      cases = cases.filter((c) => c.device.key !== device.key);
      replace(counter, t("review.count", { n: total }));
      const target = next?.querySelector("h2");
      if (target) { target.tabIndex = -1; target.focus(); }
      else if (!cases.length) {
        await load();
        const heading = list.querySelector("h2");
        if (heading) { heading.tabIndex = -1; heading.focus(); }
      }
      drawPager();
      app.reloadStatus();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function trustWithAlias(device, card) {
    const input = h("input", { type: "text", maxlength: "64", value: device.alias || suggestAlias(device) });
    dialog(t("review.trust_alias"), field(t("device.alias"), input, { hint: t("review.alias_hint") }), [
      { label: t("common.cancel") },
      { label: t("review.trust"), primary: true, run: () => decide(device, async () => {
        if (input.value.trim()) await api.patch(devicePath(device.key), { alias: input.value.trim() });
        await api.post(devicePath(device.key) + "/trust", { trusted: true });
      }, t("review.trusted", { name: input.value.trim() || device.name }), card) },
    ]);
  }

  function snooze(device, card) {
    const hours = h("select", {}, [[4, "4 h"], [24, "24 h"], [72, "3 d"], [168, "7 d"]].map(([v, l]) => h("option", { value: v }, l)));
    dialog(t("device.snooze"), h("div", {}, h("p", {}, t("device.snooze_text")), field(t("device.snooze_for"), hours)), [
      { label: t("common.cancel") },
      { label: t("device.snooze"), primary: true, run: () => decide(device, () => api.post(devicePath(device.key) + "/review", { action: "snooze", until: Number(hours.value) }), t("device.snoozed_ok"), card) },
    ]);
  }

  function forget(device, card) {
    dialog(t("device.forget"), h("p", {}, t("device.forget_text", { name: device.name })), [
      { label: t("common.cancel") },
      { label: t("device.forget"), danger: true, run: () => decide(device, () => api.del(devicePath(device.key)), t("device.forgotten_ok"), card) },
    ]);
  }

  function identityActions(device, events, card) {
    const proposal = events.find((e) => e.type === "identity-candidate" && e.details.candidate_key);
    if (!proposal) return null;
    const candidate = proposal.details.candidate_key;
    return h("div", { class: "proposal" },
      h("p", {}, t("review.identity_proposal", { score: proposal.details.score })),
      h("ul", { class: "small" }, (proposal.details.evidence || []).map((e) => h("li", {}, e))),
      h("p", { class: "muted small" }, t("review.identity_no_trust")),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn", onClick: () => decide(device, () => api.post("/api/v1/identities/link", { new: device.key, old: candidate, trust: false }), t("identity.linked_ok"), card) }, t("identity.accept")),
        h("button", { type: "button", class: "btn", onClick: () => decide(device, () => api.post("/api/v1/identities/reject", { new: device.key, candidate }), t("identity.rejected_ok"), card) }, t("identity.reject"))));
  }

  function caseCard(item, index) {
    const d = item.device;
    const card = h("article", { class: "case", "aria-labelledby": "case-" + index },
      h("header", { class: "case-head" },
        h("h2", { id: "case-" + index }, deviceLink(d)),
        h("span", { class: "mono muted" }, d.ip), d.mac ? h("span", { class: "mono muted small" }, d.mac) : null,
        d.snoozed_until ? badge(t("device.snoozed_until", { when: fmtDateTime(d.snoozed_until) }), "", "⏸") : null),
      h("div", { class: "case-body" },
        h("div", {}, h("h3", {}, t("review.evidence")), riskExplain(d.risk)),
        h("div", {}, h("h3", {}, t("review.context")),
          facts([
            [t("device.vendor"), d.vendor || (d.randomized_mac ? t("devices.randomized") : t("devices.unknown_vendor"))],
            [t("device.hostname"), d.hostname || "—"],
            [t("device.first_seen"), timeEl(d.first_seen)],
            [t("device.last_seen"), timeEl(d.last_seen)],
          ]),
          h("ul", { class: "event-list" }, item.events.slice(0, 5).map((e) => h("li", {}, severityBadge(e.severity), timeEl(e.timestamp), h("span", { class: "event-msg" }, e.message)))))));
    const actions = h("div", { class: "actions" },
      h("button", { type: "button", class: "btn primary", onClick: () => decide(d, () => api.post(devicePath(d.key) + "/trust", { trusted: true }), t("review.trusted", { name: d.name }), card) }, t("review.trust")),
      h("button", { type: "button", class: "btn", onClick: () => trustWithAlias(d, card) }, t("review.trust_alias")),
      h("button", { type: "button", class: "btn", onClick: () => decide(d, () => api.post(devicePath(d.key) + "/review", { action: "ack" }), t("review.acked", { name: d.name }), card), title: t("review.ack_hint") }, t("review.ack")),
      h("button", { type: "button", class: "btn", onClick: () => snooze(d, card) }, t("device.snooze")),
      h("button", { type: "button", class: "btn danger", onClick: () => forget(d, card) }, t("device.forget")));
    const proposal = identityActions(d, item.events, card);
    if (proposal) card.append(proposal);
    card.append(actions);
    return card;
  }

  function drawPager() {
    replace(pagination, pager(currentPage, Math.max(1, Math.ceil(total / 20)), (n) => {
      setQuery({ page: n > 1 ? n : "" });
      load();
    }));
  }

  function draw() {
    drawPager();
    replace(counter, t("review.count", { n: total }));
    replace(list, cases.length
      ? cases.map(caseCard)
      : emptyState(t("review.empty"), t("review.empty_text"), { label: t("nav.devices"), href: "/devices" }));
  }

  async function load() {
    const seq = ++loadSeq;
    try {
      const data = await api.get("/api/v1/review", { network: app.network(), snoozed: showSnoozed.checked ? "true" : "", page: query().page || 1, size: 20 });
      if (seq !== loadSeq) return;
      total = data.total;
      currentPage = data.page;
      const lastPage = Math.max(1, Math.ceil(total / data.size));
      if (currentPage > lastPage) {
        setQuery({ page: lastPage > 1 ? lastPage : "" });
        return load();
      }
      cases = data.items;
      draw();
    } catch (error) {
      if (error.status === 401) throw error;
      replace(list, errorState(error, load));
    }
  }

  replace(root,
    h("header", { class: "view-head" }, h("h1", {}, t("review.title")), counter,
      h("p", { class: "muted" }, t("review.intro"))),
    h("label", { class: "check" }, showSnoozed, t("review.show_snoozed")),
    list, pagination);
  replace(list, loading());
  await load();
  return {
    refresh(changes) {
      // a decision taken elsewhere removes the card; never redraw while a dialog is open
      if (document.querySelector(".backdrop") || Date.now() < quietUntil) return;
      if (changes.some((c) => /^(event\.|device\.|identity\.|scan\.finished|reset)/.test(c.kind))) load();
    },
  };
}
