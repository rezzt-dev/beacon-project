// redes: the networks beacon tells apart and their devices grouped by what is known.
// a sweep only proves membership in a range, so this shows groups, never invented cables or links.

import { api } from "../api.js";
import { app } from "../app.js";
import { deviceLink, emptyState, errorState, facts, field, loading, panel, statusBadge, timeEl } from "../components.js";
import { dialog, h, replace, toast } from "../dom.js";
import { fmtNumber, t } from "../i18n.js";

function role(device) {
  if (device.is_gateway) return "gateway";
  if (device.is_local) return "local";
  return "other";
}

export async function mount(root) {
  const body = h("div");

  function rename(network) {
    const input = h("input", { type: "text", maxlength: "64", value: network.name || "" });
    dialog(t("networks.rename"), field(t("networks.name"), input, { hint: t("networks.name_hint") }), [
      { label: t("common.cancel") },
      { label: t("common.save"), primary: true, run: async () => {
        try {
          await api.patch(`/api/v1/networks/${network.id}`, { name: input.value.trim() || null });
          toast(t("common.saved"), "ok");
          await app.reloadStatus();
          load();
        } catch (error) {
          toast(error.message, "error");
          return false;
        }
      } },
    ]);
  }

  async function load() {
    try {
      const [networks, interfaces] = await Promise.all([api.get("/api/v1/networks"), api.get("/api/v1/interfaces")]);
      const selected = app.network();
      const shown = networks.items.filter((n) => selected === null || n.id === selected);
      if (!shown.length) {
        replace(body, emptyState(t("networks.empty"), t("networks.empty_text"), { label: t("nav.scans"), href: "/scans" }));
        return;
      }
      const sections = await Promise.all(shown.map(async (network) => {
        const devices = await api.get("/api/v1/devices", { network: network.id, size: 500, sort: "ip" });
        const groups = { gateway: [], local: [], other: [] };
        devices.items.forEach((d) => groups[role(d)].push(d));
        const local = interfaces.items.find((i) => i.network === network.cidr);
        return panel(network.name || network.cidr, h("div", {},
          facts([
            [t("networks.range"), h("span", { class: "mono" }, network.cidr)],
            [t("networks.gateway"), network.gateway_ip ? [h("span", { class: "mono" }, network.gateway_ip), " ", h("span", { class: "mono muted" }, network.gateway_mac || t("networks.gateway_mac_unknown"))] : t("networks.unknown")],
            [t("networks.interface"), local ? `${local.name} · ${local.ip}` : network.interface || t("networks.not_attached")],
            [t("networks.devices"), t("networks.devices_value", { online: fmtNumber(network.online), total: fmtNumber(network.devices) })],
            [t("networks.last_scan"), timeEl(network.last_scan_at)],
          ]),
          h("p", { class: "muted small" }, t("networks.topology_note")),
          h("div", { class: "groups" }, ["gateway", "local", "other"].filter((g) => groups[g].length).map((g) => h("section", { class: "group" },
            h("h3", {}, t("networks.group_" + g), " ", h("span", { class: "muted" }, fmtNumber(groups[g].length))),
            h("ul", { class: "member-list" }, groups[g].map((d) => h("li", {}, statusBadge(d), " ", deviceLink(d), " ", h("span", { class: "mono muted small" }, d.ip))))))),
          devices.total > devices.items.length ? h("p", { class: "muted" }, t("networks.more", { n: devices.total - devices.items.length })) : null),
        h("button", { type: "button", class: "btn small", onClick: () => rename(network) }, t("networks.rename")));
      }));
      replace(body, sections);
    } catch (error) {
      if (error.status === 401) throw error;
      replace(body, errorState(error, load));
    }
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("networks.title")), h("p", { class: "muted" }, t("networks.intro"))), body);
  replace(body, loading());
  await load();
  return {
    refresh(changes) {
      if (document.querySelector(".backdrop")) return;
      if (changes.some((c) => /^(network\.|scan\.finished|device\.deleted|reset)/.test(c.kind))) load();
    },
  };
}
