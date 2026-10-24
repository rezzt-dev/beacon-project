// identidades: proposed links between private macs, with evidence, certainty and full history.
// confirming never grants trust; ambiguous candidates are shown side by side, never merged.

import { api } from "../api.js";
import { app } from "../app.js";
import { badge, deviceLink, emptyState, errorState, loading, panel, timeEl, trustBadge } from "../components.js";
import { dialog, h, replace, toast } from "../dom.js";
import { fmtNumber, t } from "../i18n.js";

function compare(a, b) {
  const rows = [
    ["device.ip", (d) => d.ip], ["device.mac", (d) => d.mac], ["device.hostname", (d) => d.hostname || "—"],
    ["device.vendor", (d) => d.vendor || "—"], ["identity.ports", (d) => d.open_ports.map((p) => p.port).join(", ") || "—"],
    ["device.first_seen", (d) => d.first_seen], ["device.last_seen", (d) => d.last_seen],
  ];
  return h("table", { class: "table compact compare" },
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, ""), h("th", { scope: "col" }, t("identity.newer")), h("th", { scope: "col" }, t("identity.older")))),
    h("tbody", {}, rows.map(([label, get]) => {
      const left = get(a);
      const right = get(b);
      const isTime = label.endsWith("_seen");
      return h("tr", { class: left === right && !isTime ? "same" : "" },
        h("th", { scope: "row" }, t(label)),
        h("td", { class: "mono" }, isTime ? timeEl(left) : left),
        h("td", { class: "mono" }, isTime ? timeEl(right) : right));
    })));
}

export async function mount(root) {
  const body = h("div");

  async function act(run, message) {
    try {
      await run();
      toast(message, "ok");
      load();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function confirmLink(candidate) {
    const trust = h("input", { type: "checkbox" });
    dialog(t("identity.confirm_title"), h("div", {},
      h("p", {}, t("identity.confirm_text")),
      compare(candidate.new, candidate.candidate),
      h("label", { class: "check" }, trust, t("identity.also_trust", { name: candidate.new.name }))), [
      { label: t("common.cancel") },
      { label: t("identity.accept"), primary: true, run: () => act(() => api.post("/api/v1/identities/link", { new: candidate.new.key, old: candidate.candidate.key, trust: trust.checked }), t("identity.linked_ok")) },
    ]);
  }

  function render(data) {
    const candidates = data.candidates;
    replace(body,
      panel(t("identity.candidates"), candidates.length
        ? h("ul", { class: "candidate-list" }, candidates.map((c) => h("li", { class: "candidate" },
          h("div", { class: "candidate-head" },
            deviceLink(c.new), h("span", { "aria-hidden": "true" }, " → "), h("span", { class: "sr-only" }, t("identity.probably")), deviceLink(c.candidate),
            badge(t("identity.level_" + c.level) + " · " + fmtNumber(c.score, 2), c.level === "probable" ? "ok" : "warn"),
            c.ambiguous ? badge(t("identity.ambiguous"), "alert", "!") : null),
          h("ul", { class: "evidence small" }, c.evidence.map((e) => h("li", {}, e))),
          c.ambiguous ? h("p", { class: "warn-text small" }, t("identity.ambiguous_text")) : null,
          h("details", {}, h("summary", {}, t("identity.compare")), compare(c.new, c.candidate)),
          h("div", { class: "actions" },
            h("button", { type: "button", class: "btn", onClick: () => confirmLink(c) }, t("identity.accept")),
            h("button", { type: "button", class: "btn", onClick: () => act(() => api.post("/api/v1/identities/reject", { new: c.new.key, candidate: c.candidate.key }), t("identity.rejected_ok")) }, t("identity.reject"))))))
        : emptyState(t("identity.no_candidates"), t("identity.no_candidates_text")),
        h("p", { class: "muted small" }, t("identity.thresholds", { probable: data.thresholds.probable, possible: data.thresholds.possible }))),
      panel(t("identity.confirmed"), data.identities.length
        ? h("ul", { class: "identity-list" }, data.identities.map((i) => h("li", {},
          h("strong", {}, i.label || "#" + i.id), " ", h("span", { class: "muted" }, t("identity.since", { when: "" })), timeEl(i.created_at),
          h("ul", {}, i.members.map((m) => h("li", {}, deviceLink(m), " ", h("span", { class: "mono muted" }, m.mac || m.ip), " ", trustBadge(m), " ",
            h("button", { type: "button", class: "btn small", onClick: () => act(() => api.post("/api/v1/identities/unlink", { key: m.key }), t("identity.unlinked_ok")) }, t("identity.unlink"))))))))
        : emptyState(t("identity.none"), t("identity.none_text"))),
      panel(t("identity.history"), data.history.length
        ? h("ul", { class: "audit" }, data.history.map((a) => h("li", {}, timeEl(a.at), " · ", h("strong", {}, t("audit." + a.action)), " · ",
          h("span", { class: "mono small" }, [a.details.new, a.details.old, a.details.device, a.entity_id, a.details.candidate].filter(Boolean).join(" ↔ ")),
          a.details.evidence?.length ? h("span", { class: "muted small" }, " · " + a.details.evidence.join(", ")) : null,
          " · ", h("span", { class: "muted" }, a.actor))))
        : h("p", { class: "muted" }, t("identity.no_history"))),
      data.rejections.length ? panel(t("identity.rejections"), h("ul", { class: "small mono" }, data.rejections.map((r) => h("li", {}, `${r.new} ≠ ${r.candidate}`)))) : null);
  }

  async function load() {
    try {
      render(await api.get("/api/v1/identities", { network: app.network() }));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(body, errorState(error, load));
    }
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("identity.title")), h("p", { class: "muted" }, t("identity.intro"))), body);
  replace(body, loading());
  await load();
  return {
    refresh(changes) {
      if (document.querySelector(".backdrop")) return;
      if (changes.some((c) => /^(identity\.|scan\.finished|reset)/.test(c.kind))) load();
    },
  };
}
