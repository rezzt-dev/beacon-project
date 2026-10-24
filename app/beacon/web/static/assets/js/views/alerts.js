// alertas: when to notify, where, and when to stay quiet. nothing is sent anywhere until a
// channel is configured here.

import { api } from "../api.js";
import { app } from "../app.js";
import { badge, emptyState, errorState, field, loading, panel, select, timeEl } from "../components.js";
import { dialog, h, replace, toast } from "../dom.js";
import { fmtDateTime, t } from "../i18n.js";

export async function mount(root) {
  const policiesBox = h("div");
  const silencesBox = h("div");
  const channelsBox = h("div");
  const deliveriesBox = h("div");
  let channels = [];
  let eventTypes = [];

  async function run(action, message, reload) {
    try {
      await action();
      if (message) toast(message, "ok");
      await reload();
      return true;
    } catch (error) {
      toast((error.field ? error.field + ": " : "") + error.message, "error");
      return false;
    }
  }

  // policies ->
  function policyDialog(policy) {
    const name = h("input", { type: "text", maxlength: "64", value: policy?.name || "" });
    const types = h("fieldset", { class: "checks columns-3" }, h("legend", {}, t("alerts.types")),
      eventTypes.map((type) => h("label", { class: "check" }, h("input", { type: "checkbox", value: type, checked: policy?.event_types.includes(type) }), t("event." + type))));
    const severity = select([["info", t("severity.info")], ["warning", t("severity.warning")], ["alert", t("severity.alert")]], policy?.min_severity || "warning");
    const trusted = select([["", t("alerts.any_device")], ["false", t("trust.untrusted")], ["true", t("trust.trusted")]], policy?.device_filter?.trusted === undefined ? "" : String(policy.device_filter.trusted));
    const essential = h("input", { type: "checkbox", checked: Boolean(policy?.device_filter?.essential) });
    const minRisk = h("input", { type: "number", min: "0", max: "100", value: policy?.min_risk ?? "" });
    const threshold = h("input", { type: "number", min: "1", max: "10000", value: policy?.threshold ?? 1 });
    const windowMin = h("input", { type: "number", min: "0", max: "10080", value: policy ? Math.round(policy.window_seconds / 60) : 0 });
    const cooldown = h("input", { type: "number", min: "0", max: "10080", value: policy ? Math.round(policy.cooldown_seconds / 60) : 15 });
    const channelBoxes = channels.map((c) => h("label", { class: "check" }, h("input", { type: "checkbox", value: c.id, checked: policy?.channels.includes(c.id) }), `${c.name} (${c.kind})`));
    dialog(policy ? t("alerts.edit_policy", { name: policy.name }) : t("alerts.new_policy"), h("div", { class: "settings-form" },
      field(t("alerts.name"), name), types,
      field(t("alerts.min_severity"), severity), field(t("alerts.device_trust"), trusted),
      h("label", { class: "check" }, essential, t("alerts.only_essential")),
      field(t("alerts.min_risk"), minRisk, { hint: t("alerts.min_risk_hint") }),
      field(t("alerts.threshold"), threshold, { hint: t("alerts.threshold_hint") }),
      field(t("alerts.window"), windowMin), field(t("alerts.cooldown"), cooldown, { hint: t("alerts.cooldown_hint") }),
      h("fieldset", { class: "checks" }, h("legend", {}, t("alerts.channels")), channelBoxes.length ? channelBoxes : h("p", { class: "hint" }, t("alerts.no_channels_yet")))), [
      { label: t("common.cancel") },
      { label: t("common.save"), primary: true, run: () => {
        const filter = {};
        if (trusted.value) filter.trusted = trusted.value === "true";
        if (essential.checked) filter.essential = true;
        const body = {
          name: name.value.trim(),
          event_types: [...types.querySelectorAll("input:checked")].map((i) => i.value),
          min_severity: severity.value, device_filter: filter, min_risk: minRisk.value === "" ? null : Number(minRisk.value),
          threshold: Number(threshold.value), window_seconds: Number(windowMin.value) * 60, cooldown_seconds: Number(cooldown.value) * 60,
          channels: channelBoxes.map((l) => l.querySelector("input")).filter((i) => i.checked).map((i) => Number(i.value)),
          network_id: app.network(),
        };
        return run(() => (policy ? api.patch(`/api/v1/alerts/policies/${policy.id}`, { ...body, version: policy.version }) : api.post("/api/v1/alerts/policies", body)), t("common.saved"), loadPolicies);
      } },
    ]);
  }

  async function loadPolicies() {
    try {
      const data = await api.get("/api/v1/alerts/policies");
      eventTypes = data.event_types;
      replace(policiesBox, panel(t("alerts.policies"), data.items.length
        ? h("ul", { class: "profile-list" }, data.items.map((p) => h("li", {},
          h("strong", {}, p.name), " ", p.enabled ? badge(t("alerts.enabled"), "ok") : badge(t("alerts.disabled")), " ",
          h("span", { class: "muted" }, [
            p.event_types.length ? p.event_types.map((x) => t("event." + x)).join(", ") : t("alerts.any_type"),
            t("alerts.from_severity", { s: t("severity." + p.min_severity) }),
            p.threshold > 1 ? t("alerts.threshold_short", { n: p.threshold, m: Math.round(p.window_seconds / 60) }) : null,
            p.channels.length ? t("alerts.to_channels", { n: p.channels.length }) : t("alerts.record_only"),
          ].filter(Boolean).join(" · ")),
          p.last_fired_at ? h("span", { class: "muted small" }, " · ", t("alerts.last_fired"), " ", timeEl(p.last_fired_at)) : null,
          h("span", { class: "actions inline" },
            h("button", { type: "button", class: "btn small", onClick: () => run(() => api.patch(`/api/v1/alerts/policies/${p.id}`, { enabled: !p.enabled, version: p.version }), null, loadPolicies) }, p.enabled ? t("alerts.disable") : t("alerts.enable")),
            h("button", { type: "button", class: "btn small", onClick: () => policyDialog(p) }, t("common.edit")),
            h("button", { type: "button", class: "btn small danger", onClick: () => run(() => api.del(`/api/v1/alerts/policies/${p.id}`), t("alerts.deleted"), loadPolicies) }, t("common.delete"))))))
        : emptyState(t("alerts.no_policies"), t("alerts.no_policies_text")),
        h("button", { type: "button", class: "btn small primary", onClick: () => policyDialog(null) }, t("alerts.new_policy"))));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(policiesBox, errorState(error, loadPolicies));
    }
  }

  // silences ->
  function silenceDialog() {
    const reason = h("input", { type: "text", maxlength: "200" });
    const start = h("input", { type: "datetime-local" });
    const hours = h("input", { type: "number", min: "1", max: "2160", value: "2" });
    const device = h("input", { type: "text", spellcheck: "false", placeholder: "aa:bb:cc:dd:ee:ff" });
    dialog(t("alerts.new_silence"), h("div", { class: "settings-form" },
      h("p", { class: "hint" }, t("alerts.silence_hint")),
      field(t("alerts.reason"), reason), field(t("alerts.starts"), start, { hint: t("alerts.starts_hint") }),
      field(t("alerts.hours"), hours), field(t("alerts.device_key"), device, { hint: t("alerts.device_key_hint") })), [
      { label: t("common.cancel") },
      { label: t("common.save"), primary: true, run: () => run(() => api.post("/api/v1/alerts/silences", {
        reason: reason.value.trim() || null, hours: Number(hours.value), device_key: device.value.trim() || null,
        starts_at: start.value ? new Date(start.value).toISOString() : null, network_id: app.network(),
      }), t("common.saved"), loadSilences) },
    ]);
  }

  async function loadSilences() {
    try {
      const { items } = await api.get("/api/v1/alerts/silences");
      replace(silencesBox, panel(t("alerts.silences"), items.length
        ? h("ul", { class: "profile-list" }, items.map((s) => h("li", {},
          new Date(s.starts_at) > new Date() ? badge(t("alerts.scheduled")) : badge(t("alerts.active"), "warn"), " ",
          `${fmtDateTime(s.starts_at)} → ${fmtDateTime(s.ends_at)}`, " · ", s.reason || t("alerts.no_reason"),
          s.device_key ? h("span", { class: "mono muted" }, " · " + s.device_key) : null,
          h("span", { class: "actions inline" }, h("button", { type: "button", class: "btn small", onClick: () => run(() => api.del(`/api/v1/alerts/silences/${s.id}`), t("alerts.ended"), loadSilences) }, t("alerts.end_now"))))))
        : emptyState(t("alerts.no_silences"), null),
        h("button", { type: "button", class: "btn small", onClick: silenceDialog }, t("alerts.new_silence"))));
    } catch (error) {
      replace(silencesBox, errorState(error, loadSilences));
    }
  }

  // channels ->
  function channelDialog() {
    const kind = select([["desktop", t("alerts.kind_desktop")], ["webhook", t("alerts.kind_webhook")]], "desktop");
    const name = h("input", { type: "text", maxlength: "64" });
    const url = h("input", { type: "text", spellcheck: "false", placeholder: "https://example.com/hook" });
    const secret = h("input", { type: "password", autocomplete: "new-password" });
    const webhookFields = h("div", { hidden: true }, field(t("alerts.url"), url, { hint: t("alerts.url_hint") }), field(t("alerts.secret"), secret, { hint: t("alerts.secret_hint") }));
    kind.onchange = () => { webhookFields.hidden = kind.value !== "webhook"; };
    dialog(t("alerts.new_channel"), h("div", { class: "settings-form" }, h("p", { class: "notice small" }, t("alerts.privacy")), field(t("alerts.kind"), kind), field(t("alerts.name"), name), webhookFields), [
      { label: t("common.cancel") },
      { label: t("common.save"), primary: true, run: () => run(() => api.post("/api/v1/alerts/channels", {
        kind: kind.value, name: name.value.trim(), config: kind.value === "webhook" ? { url: url.value.trim() } : {}, secret: secret.value || null,
      }), t("common.saved"), loadChannels) },
    ]);
  }

  async function loadChannels() {
    try {
      channels = (await api.get("/api/v1/alerts/channels")).items;
      replace(channelsBox, panel(t("alerts.channels"), channels.length
        ? h("ul", { class: "profile-list" }, channels.map((c) => h("li", {},
          h("strong", {}, c.name), " ", badge(t("alerts.kind_" + c.kind)), " ",
          c.config.url ? h("span", { class: "mono muted small" }, c.config.url) : null,
          c.has_secret ? h("span", { class: "muted small" }, " · " + t("alerts.signed")) : null,
          h("span", { class: "actions inline" },
            h("button", { type: "button", class: "btn small", onClick: async () => {
              try {
                const result = await api.post(`/api/v1/alerts/channels/${c.id}/test`, {});
                toast(result.status === "sent" ? t("alerts.test_ok") : t("alerts.test_failed", { error: result.error || result.status }), result.status === "sent" ? "ok" : "error");
                loadDeliveries();
              } catch (error) { toast(error.message, "error"); }
            } }, t("alerts.test")),
            h("button", { type: "button", class: "btn small danger", onClick: () => run(() => api.del(`/api/v1/alerts/channels/${c.id}`), t("alerts.deleted"), loadChannels) }, t("common.delete"))))))
        : emptyState(t("alerts.no_channels"), t("alerts.no_channels_text")),
        h("button", { type: "button", class: "btn small", onClick: channelDialog }, t("alerts.new_channel"))));
    } catch (error) {
      replace(channelsBox, errorState(error, loadChannels));
    }
  }

  async function loadDeliveries() {
    try {
      const { items } = await api.get("/api/v1/alerts/deliveries", { size: 30 });
      replace(deliveriesBox, panel(t("alerts.deliveries"), items.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "table compact" },
          h("thead", {}, h("tr", {}, [t("alerts.when"), t("alerts.policy"), t("alerts.channel"), t("alerts.status"), t("alerts.attempts"), t("alerts.error")].map((x) => h("th", { scope: "col" }, x)))),
          h("tbody", {}, items.map((d) => h("tr", {},
            h("th", { scope: "row" }, timeEl(d.created_at)), h("td", {}, d.policy || t("alerts.test")), h("td", {}, d.channel || "—"),
            h("td", {}, badge(t("alerts.status_" + d.status), d.status === "sent" ? "ok" : d.status === "failed" ? "alert" : "")),
            h("td", {}, String(d.attempts)), h("td", { class: "small" }, d.last_error || "—"))))))
        : h("p", { class: "muted" }, t("alerts.no_deliveries"))));
    } catch (error) {
      replace(deliveriesBox, errorState(error, loadDeliveries));
    }
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("alerts.title")), h("p", { class: "muted" }, t("alerts.intro"))),
    h("div", { class: "columns" }, policiesBox, channelsBox), silencesBox, deliveriesBox);
  replace(policiesBox, loading());
  await loadChannels();
  await Promise.all([loadPolicies(), loadSilences(), loadDeliveries()]);
  return {
    refresh(changes) {
      if (document.querySelector(".backdrop")) return;
      if (changes.some((c) => c.kind.startsWith("delivery."))) loadDeliveries();
      if (changes.some((c) => c.kind.startsWith("policy."))) loadPolicies();
    },
  };
}
