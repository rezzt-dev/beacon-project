// servicios: every port seen on the network, how sure beacon is about it and how well it was checked.

import { api } from "../api.js";
import { app } from "../app.js";
import { badge, emptyState, errorState, loading, timeEl } from "../components.js";
import { debounce, h, replace } from "../dom.js";
import { fmtDateTime, fmtNumber, t } from "../i18n.js";
import { devicePage, query, setQuery } from "../router.js";

export async function mount(root) {
  const body = h("div");
  const summary = h("p", { class: "muted", "aria-live": "polite" });
  const search = h("input", { type: "search", value: query().q || "", placeholder: t("services.search"), "aria-label": t("services.search") });
  search.addEventListener("input", debounce(() => { setQuery({ q: search.value.trim() }); load(); }, 250));

  function render(data) {
    replace(summary, t("services.summary", { examined: data.devices_examined, total: data.devices_in_scope, ports: data.examined_ports ? data.examined_ports.length > 40 ? data.examined_ports.slice(0, 40) + "…" : data.examined_ports : "—" }));
    if (!data.items.length) {
      replace(body, emptyState(t("services.empty"), data.devices_examined ? t("services.empty_text") : t("services.never_text")));
      return;
    }
    replace(body, h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("caption", { class: "sr-only" }, t("services.caption")),
      h("thead", {}, h("tr", {}, [t("ports.port"), t("ports.service"), t("ports.exposure"), t("services.open_on"), t("services.coverage"), t("services.changes"), t("ports.checked")].map((x) => h("th", { scope: "col" }, x)))),
      h("tbody", {}, data.items.map((s) => h("tr", {},
        h("th", { scope: "row", class: "mono" }, `${s.port}/${s.protocol}`),
        h("td", {}, s.service || "—", s.observed_protocols.length ? [" ", badge(t("services.observed", { list: s.observed_protocols.join(", ") }), "ok")] : [" ", badge(t("basis.inferred"))]),
        h("td", {}, s.exposure ? t("exposure." + s.exposure) : "—", s.encrypted === false ? h("div", { class: "warn-text small" }, t("ports.plaintext")) : null),
        h("td", {}, h("details", {}, h("summary", {}, t("services.devices", { n: s.open })),
          h("ul", { class: "small" }, s.devices.map((d) => h("li", {}, h("a", { href: devicePage(d.key) }, d.name), " ", h("span", { class: "mono muted" }, d.ip),
            d.last_probe && d.last_probe !== "open" ? h("span", { class: "warn-text" }, " · " + t("ports.last_probe", { result: t("ports.state_" + d.last_probe) })) : null,
            d.banner ? h("code", { class: "banner" }, d.banner) : null))),
          s.devices_truncated ? h("p", { class: "muted small" },
            t("services.listed", { n: s.devices.length, total: s.open }), " ",
            h("a", { href: `/devices?port=${s.port}${app.network() ? `&network=${app.network()}` : ""}` }, t("services.all"))) : null,
          s.certificates.length ? h("ul", { class: "small" }, s.certificates.map((c) => h("li", {}, t("tls.summary", { subject: c.subject || "?", issuer: c.issuer || "?", until: c.not_after ? fmtDateTime(c.not_after) : "?" }),
            c.expired ? badge(t("tls.expired"), "alert") : null, c.self_signed ? badge(t("tls.self_signed"), "warn") : null))) : null)),
        h("td", {}, t("services.examined_on", { n: fmtNumber(s.examined_devices), total: fmtNumber(s.devices_in_scope) }), s.legacy_unknown ? h("div", { class: "muted small" }, t("services.legacy", { n: s.legacy_unknown })) : null),
        h("td", {}, s.opened_7d || s.closed_7d ? t("services.changes_value", { opened: s.opened_7d, closed: s.closed_7d }) : "—"),
        h("td", {}, timeEl(s.last_checked))))))));
  }

  async function load() {
    try {
      render(await api.get("/api/v1/services", { network: app.network(), q: query().q }));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(body, errorState(error, load));
    }
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("services.title")), summary, h("p", { class: "muted" }, t("services.intro"))),
    h("form", { class: "filters", role: "search", onSubmit: (e) => e.preventDefault() }, search), body);
  replace(body, loading());
  await load();
  return {
    refresh(changes) {
      if (changes.some((c) => c.kind === "scan.finished" || c.kind === "reset")) load();
    },
  };
}
