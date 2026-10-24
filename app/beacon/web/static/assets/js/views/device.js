// detalle de dispositivo: everything known, why it scores what it scores, how fresh the data is,
// and the actions that change it (edit, trust, review, snooze, recheck, forget).

import { api, devicePath } from "../api.js";
import { lineChart, presenceHeatmap } from "../charts.js";
import {
  badge, deviceLink, emptyState, errorState, facts, field, latencyText, loading, panel, riskBadge, riskExplain, severityBadge, statusBadge, timeEl, trustBadge,
} from "../components.js";
import { announce, dialog, h, replace, toast } from "../dom.js";
import { fmtDateTime, fmtNumber, t } from "../i18n.js";
import { navigate } from "../router.js";

const RANGES = { "24h": [1, 15], "7d": [7, 120], "30d": [30, 360] };

export async function mount(root, { params }) {
  const key = params.key;
  let device = null;
  let dirty = false;
  let range = "24h";
  const formSlot = h("div");
  const body = h("div", { class: "detail" });
  const banner = h("div", { class: "notice", hidden: true, role: "status" });

  async function load() {
    try {
      device = await api.get(devicePath(key));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(root, error.status === 404
        ? emptyState(t("device.not_found"), t("device.not_found_text"), { label: t("nav.devices"), href: "/devices" })
        : errorState(error, load));
      return false;
    }
    render();
    return true;
  }

  // actions ->
  async function act(run, done) {
    try {
      await run();
      if (done) toast(done, "ok");
      announce(done || t("common.saved"));
      await load();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  const trust = (value) => act(() => api.post(devicePath(key) + "/trust", { trusted: value, version: device.version }), value ? t("device.trusted_ok") : t("device.untrusted_ok"));
  const ack = () => act(() => api.post(devicePath(key) + "/review", { action: "ack" }), t("device.acked_ok"));
  const recheck = () => act(async () => {
    const job = await api.post(devicePath(key) + "/recheck", {});
    toast(t("device.recheck_queued", { id: job.id }), "info");
  });

  function snooze() {
    const hours = h("select", {}, [[4, "4 h"], [24, "24 h"], [72, "3 d"], [168, "7 d"]].map(([v, l]) => h("option", { value: v }, l)));
    dialog(t("device.snooze"), h("div", {}, h("p", {}, t("device.snooze_text")), field(t("device.snooze_for"), hours)), [
      { label: t("common.cancel") },
      { label: t("device.snooze"), primary: true, run: () => act(() => api.post(devicePath(key) + "/review", { action: "snooze", until: Number(hours.value) }), t("device.snoozed_ok")) },
    ]);
  }

  function forget() {
    dialog(t("device.forget"), h("p", {}, t("device.forget_text", { name: device.name })), [
      { label: t("common.cancel") },
      { label: t("device.forget"), danger: true, run: async () => {
        try {
          await api.del(devicePath(key));
          toast(t("device.forgotten_ok"), "ok");
          navigate("/devices");
        } catch (error) {
          toast(error.message, "error");
          return false;
        }
      } },
    ]);
  }

  // edit form: kept as typed while live updates arrive ->
  function editForm() {
    const alias = h("input", { type: "text", maxlength: "64", value: device.alias || "" });
    const category = h("input", { type: "text", maxlength: "32", value: device.category || "", list: "categories" });
    const tags = h("input", { type: "text", value: device.tags.join(", ") });
    const owner = h("input", { type: "text", maxlength: "64", value: device.owner || "" });
    const notes = h("textarea", { rows: "3", maxlength: "2000" }, device.notes || "");
    const essential = h("input", { type: "checkbox", checked: device.essential });
    const errorBox = h("p", { class: "field-error", role: "alert", hidden: true });
    const values = () => ({ alias: alias.value, category: category.value, tags: tags.value, owner: owner.value, notes: notes.value, essential: essential.checked });
    const initial = values();
    const form = h("form", { class: "edit-form", "aria-labelledby": "edit-title", novalidate: true },
      field(t("device.alias"), alias, { hint: t("device.alias_hint") }),
      field(t("device.category"), category),
      h("datalist", { id: "categories" }, ["router", "phone", "laptop", "tv", "camera", "printer", "iot", "server", "nas"].map((c) => h("option", { value: c }))),
      field(t("device.tags"), tags, { hint: t("device.tags_hint") }),
      field(t("device.owner"), owner, { hint: t("device.owner_hint") }),
      field(t("device.notes"), notes, { hint: t("device.notes_hint") }),
      h("label", { class: "check" }, essential, t("device.essential")),
      errorBox,
      h("div", { class: "form-actions" },
        h("button", { type: "submit", class: "btn primary" }, t("common.save")),
        h("button", { type: "button", class: "btn", onClick: () => { dirty = false; banner.hidden = true; replace(formSlot, editForm()); } }, t("common.discard"))));
    form.addEventListener("input", () => { dirty = true; });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorBox.hidden = true;
      const changes = {
        alias: alias.value, category: category.value, owner: owner.value, notes: notes.value, essential: essential.checked,
        tags: tags.value.split(",").map((x) => x.trim()).filter(Boolean),
        version: device.version,
      };
      try {
        await api.patch(devicePath(key), changes);
        dirty = false;
        banner.hidden = true;
        toast(t("common.saved"), "ok");
        await load();
        replace(formSlot, editForm());
      } catch (error) {
        errorBox.hidden = false;
        errorBox.textContent = error.status === 409 ? t("device.conflict") : error.message;
        if (error.status === 409) {
          errorBox.append(" ", h("button", { type: "button", class: "btn small", onClick: async () => {
            // only the fields this person changed are kept; everything else takes the newer value
            const typed = values();
            await load();
            const fresh = editForm();
            replace(formSlot, fresh);
            fresh.applyChanges(Object.fromEntries(Object.entries(typed).filter(([k, v]) => v !== initial[k])));
            dirty = true;
          } }, t("device.conflict_merge")));
        }
      }
    });
    const wrapper = h("div", {}, h("h2", { id: "edit-title" }, t("device.edit")), form);
    wrapper.applyChanges = (changes) => {
      const controls = { alias, category, tags, owner, notes };
      for (const [key, value] of Object.entries(changes)) {
        if (key === "essential") essential.checked = value;
        else controls[key].value = value;
      }
    };
    return wrapper;
  }

  // sections ->
  function portsTable() {
    if (!device.ports.length) {
      return emptyState(device.coverage.checked_at ? t("ports.none_open") : t("ports.never_examined"), device.coverage.checked_at ? null : t("ports.never_examined_text"));
    }
    return h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("caption", { class: "sr-only" }, t("ports.caption")),
      h("thead", {}, h("tr", {}, [t("ports.port"), t("ports.state"), t("ports.service"), t("ports.exposure"), t("ports.checked"), t("ports.details")].map((x) => h("th", { scope: "col" }, x)))),
      h("tbody", {}, device.ports.map((p) => h("tr", { class: p.state === "open" ? "" : "is-offline" },
        h("th", { scope: "row", class: "mono" }, `${p.port}/${p.protocol}`),
        h("td", {}, badge(t("ports.state_" + p.state), p.state === "open" ? (p.sensitive ? "warn" : "ok") : ""),
          p.last_probe && p.last_probe !== p.state ? h("div", { class: "muted small" }, t("ports.last_probe", { result: t("ports.state_" + p.last_probe) })) : null),
        h("td", {}, p.protocol_observed ? [p.protocol_observed, " ", badge(t("basis.observed"), "ok")] : p.service ? [p.service, " ", badge(t("basis.inferred"))] : "—"),
        h("td", {}, p.exposure ? t("exposure." + p.exposure) : "—", p.encrypted === false ? h("div", { class: "warn-text small" }, t("ports.plaintext")) : p.encrypted ? h("div", { class: "muted small" }, t("ports.encrypted")) : null),
        h("td", {}, timeEl(p.checked_at)),
        h("td", { class: "small" },
          p.banner ? h("code", { class: "banner" }, p.banner) : null,
          p.tls && p.tls.subject !== undefined ? h("div", {}, t("tls.summary", { subject: p.tls.subject || "?", issuer: p.tls.issuer || "?", until: p.tls.not_after ? fmtDateTime(p.tls.not_after) : "?" }),
            p.tls.self_signed ? badge(t("tls.self_signed"), "warn") : null, " ", h("span", { class: "muted" }, t("tls.not_validated"))) : null))))));
  }

  function coverageBlock() {
    const c = device.coverage;
    return h("div", {},
      facts([
        [t("coverage.examined"), c.legacy ? t("coverage.legacy") : c.examined ? t("coverage.ports", { n: fmtNumber(c.examined_count), spec: c.examined.length > 60 ? c.examined.slice(0, 60) + "…" : c.examined }) : t("coverage.never")],
        [t("coverage.checked"), c.checked_at ? timeEl(c.checked_at) : t("coverage.never")],
      ]),
      c.history.length ? h("details", {}, h("summary", {}, t("coverage.history")), h("table", { class: "table compact" },
        h("thead", {}, h("tr", {}, [t("coverage.when"), t("coverage.ports_label"), t("ports.state_open"), t("ports.state_closed"), t("ports.state_filtered"), t("ports.state_error")].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", {}, c.history.map((r) => h("tr", {}, h("th", { scope: "row" }, timeEl(r.checked_at)), h("td", {}, r.legacy ? t("coverage.legacy_short") : String(r.ports)),
          h("td", {}, r.open ?? "—"), h("td", {}, r.closed ?? "—"), h("td", {}, r.filtered ?? "—"), h("td", {}, r.errors ?? "—"))))))
        : null);
  }

  const latencySlot = h("div");
  async function loadLatency() {
    const [days, bucket] = RANGES[range];
    replace(latencySlot, loading());
    try {
      const since = new Date(Date.now() - days * 86400000).toISOString();
      const data = await api.get(devicePath(key) + "/measurements", { since, bucket });
      const gap = bucket * 60000 * 2.5;
      replace(latencySlot,
        lineChart(t("latency.chart"), data.points.map((p) => ({ at: p.at, value: p.received ? p.rtt_avg : null })), { unit: " ms", gapMs: gap }),
        lineChart(t("latency.loss_chart"), data.points.map((p) => ({ at: p.at, value: p.loss })), { unit: " %", digits: 0, gapMs: gap }));
    } catch (error) {
      replace(latencySlot, errorState(error, loadLatency));
    }
  }

  const presenceSlot = h("div");
  async function loadPresence() {
    try {
      const data = await api.get(devicePath(key) + "/presence");
      replace(presenceSlot,
        h("p", {}, t("presence.status_" + data.status, { days: data.learning.days, need: data.learning.days_needed, sessions: data.learning.sessions, need_sessions: data.learning.sessions_needed })),
        data.schedule ? h("p", {}, t("presence.usual", { schedule: data.schedule })) : null,
        data.monitored !== null && !data.monitored_enough ? h("p", { class: "warn-text" }, t("presence.low_monitoring")) : null,
        data.status === "fragmented" || data.status === "no-data" ? null : presenceHeatmap(t("presence.heatmap", { tz: data.timezone }), data.grid),
        h("a", { href: "/presence?device=" + encodeURIComponent(key) }, t("presence.open")));
    } catch (error) {
      replace(presenceSlot, errorState(error, loadPresence));
    }
  }

  function render() {
    const d = device;
    const actions = h("div", { class: "actions" },
      d.trusted
        ? h("button", { type: "button", class: "btn", onClick: () => trust(false) }, t("device.untrust"))
        : h("button", { type: "button", class: "btn primary", onClick: () => trust(true) }, t("device.trust")),
      d.pending_events ? h("button", { type: "button", class: "btn", onClick: ack }, t("device.ack", { n: d.pending_events })) : null,
      d.snoozed_until
        ? h("button", { type: "button", class: "btn", onClick: () => act(() => api.post(devicePath(key) + "/review", { action: "unsnooze" }), t("device.unsnoozed_ok")) }, t("device.unsnooze"))
        : h("button", { type: "button", class: "btn", onClick: snooze }, t("device.snooze")),
      h("button", { type: "button", class: "btn", onClick: recheck }, t("device.recheck")),
      h("button", { type: "button", class: "btn danger", onClick: forget }, t("device.forget")));
    replace(body,
      h("div", { class: "columns" },
        panel(t("device.facts"), facts([
          [t("device.ip"), h("span", { class: "mono" }, d.ips.join(", "))],
          d.ips6.length ? [t("device.ipv6"), h("span", { class: "mono small" }, d.ips6.join(", "))] : null,
          [t("device.mac"), d.mac ? [h("span", { class: "mono" }, d.mac), d.randomized_mac ? h("span", { class: "muted" }, " · " + t("devices.randomized")) : null] : t("devices.no_mac")],
          [t("device.hostname"), d.hostname ? [h("span", { class: "mono" }, d.hostname), h("span", { class: "muted" }, " · " + t("devices.via", { source: d.hostname_source }))] : "—"],
          [t("device.vendor"), d.vendor || (d.randomized_mac ? t("devices.randomized") : t("devices.unknown_vendor"))],
          [t("device.os"), d.os_guess ? [d.os_guess, h("span", { class: "muted" }, " · " + t("device.os_estimate", { ttl: d.ttl }))] : "—"],
          [t("device.network"), d.network ? (d.network.name || d.network.cidr) : "—"],
          [t("device.first_seen"), timeEl(d.first_seen)],
          [t("device.last_seen"), timeEl(d.last_seen)],
          [t("device.latency"), latencyText(d.latency)],
          d.services.length ? [t("device.mdns"), d.services.join(", ")] : null,
          d.sources.length ? [t("device.sources"), d.sources.join(", ")] : null,
        ])),
        panel(t("device.risk"), h("div", {}, riskExplain(d.risk), h("h3", {}, t("coverage.title")), coverageBlock()))),
      panel(t("ports.title"), portsTable()),
      panel(t("latency.title"), h("div", {},
        h("div", { class: "segmented", role: "group", "aria-label": t("latency.range") }, Object.keys(RANGES).map((r) => h("button", {
          type: "button", class: "seg", "aria-pressed": String(r === range), onClick: (event) => {
            range = r;
            for (const b of event.target.parentElement.children) b.setAttribute("aria-pressed", String(b === event.target));
            loadLatency();
          },
        }, r))),
        latencySlot)),
      panel(t("presence.title"), presenceSlot),
      d.identity.id !== null ? panel(t("identity.title"), h("div", {},
        h("p", {}, t("identity.members_text")),
        h("ul", {}, d.identity.members.map((m) => h("li", {}, deviceLink(m), " ", h("span", { class: "mono muted" }, m.mac || m.ip), " · ", timeEl(m.last_seen)))),
        h("a", { href: "/identities" }, t("identity.open")))) : null,
      panel(t("device.events"), d.events.length
        ? h("ul", { class: "event-list" }, d.events.map((e) => h("li", {}, severityBadge(e.severity), timeEl(e.timestamp), h("span", { class: "event-msg" }, e.message), e.acked_at ? badge(t("events.reviewed")) : null)))
        : emptyState(t("events.none"), null),
        h("a", { class: "btn small", href: "/events?device=" + encodeURIComponent(key) }, t("device.all_events"))),
      panel(t("device.audit"), d.audit.length
        ? h("ul", { class: "audit" }, d.audit.map((a) => h("li", {}, timeEl(a.at), " · ", h("strong", {}, t("audit." + a.action)), " · ", h("span", { class: "muted" }, a.actor))))
        : h("p", { class: "muted" }, t("device.no_audit"))));
    replace(header,
      h("p", { class: "breadcrumb" }, h("a", { href: "/devices" }, t("nav.devices")), " / "),
      h("h1", {}, d.name),
      h("div", { class: "badges" }, statusBadge(d), trustBadge(d), riskBadge(d.risk), d.snoozed_until ? badge(t("device.snoozed_until", { when: fmtDateTime(d.snoozed_until) }), "", "⏸") : null),
      actions);
    if (!dirty && !formSlot.contains(document.activeElement)) replace(formSlot, editForm());
    loadLatency();
    loadPresence();
  }

  const header = h("header", { class: "view-head device-head" });
  replace(root, header, banner, h("div", { class: "detail-layout" }, body, h("aside", { class: "side" }, formSlot)));
  replace(body, loading());
  if (!(await load())) return {};
  return {
    async refresh(changes) {
      const mine = changes.some((c) => c.kind === "reset" || (c.entity === "device" && c.entity_id === key) || c.kind === "scan.finished" || c.kind.startsWith("identity."));
      if (!mine) return;
      if (dirty) {
        banner.hidden = false;
        replace(banner, t("device.changed_elsewhere"), " ", h("button", { type: "button", class: "btn small", onClick: () => { dirty = false; load(); banner.hidden = true; } }, t("device.reload")));
        return;
      }
      await load();
    },
  };
}

