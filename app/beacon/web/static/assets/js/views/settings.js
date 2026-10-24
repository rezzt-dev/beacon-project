// configuración y diagnóstico: preferences, scan profiles, retention, backups and what this
// machine can do, with the fix for the usual problems.

import { api } from "../api.js";
import { app, applyPreferences } from "../app.js";
import { badge, emptyState, errorState, facts, field, loading, panel, select } from "../components.js";
import { dialog, h, replace, toast } from "../dom.js";
import { fmtNumber, t } from "../i18n.js";

export async function mount(root) {
  const prefs = h("div");
  const profilesBox = h("div", { id: "profiles" });
  const retentionBox = h("div");
  const diagBox = h("div");

  // preferences ->
  function drawPrefs() {
    const s = app.settings;
    const language = select([["auto", t("settings.lang_auto")], ["es", "Español"], ["en", "English"]], s.language);
    const theme = select([["system", t("settings.theme_system")], ["light", t("settings.theme_light")], ["dark", t("settings.theme_dark")]], s.theme);
    const density = select([["comfortable", t("settings.density_comfortable")], ["compact", t("settings.density_compact")]], s.density);
    const zone = h("input", { type: "text", value: s.timezone, list: "zones", spellcheck: "false" });
    const zones = h("datalist", { id: "zones" }, ["local", ...(Intl.supportedValuesOf ? Intl.supportedValuesOf("timeZone") : [])].map((z) => h("option", { value: z })));
    const interval = h("input", { type: "number", min: "10", max: "86400", value: String(s.monitor_interval) });
    const presence = h("input", { type: "checkbox", checked: s.presence.enabled });
    const presenceReports = h("input", { type: "checkbox", checked: s.presence.in_reports });
    const passive = h("input", { type: "checkbox", checked: s.passive.enabled });
    const errorBox = h("p", { class: "field-error", role: "alert", hidden: true });
    const form = h("form", { class: "settings-form" },
      field(t("settings.language"), language),
      field(t("settings.theme"), theme),
      field(t("settings.density"), density),
      field(t("settings.timezone"), zone, { hint: t("settings.timezone_hint") }), zones,
      field(t("settings.interval"), interval, { hint: t("settings.interval_hint") }),
      h("fieldset", { class: "checks" }, h("legend", {}, t("settings.privacy")),
        h("label", { class: "check" }, presence, t("settings.presence_enabled")),
        h("label", { class: "check" }, presenceReports, t("settings.presence_reports")),
        h("label", { class: "check" }, passive, t("settings.passive")),
        h("p", { class: "hint" }, t("settings.privacy_hint"))),
      errorBox,
      h("button", { type: "submit", class: "btn primary" }, t("common.save")));
    form.onsubmit = async (event) => {
      event.preventDefault();
      errorBox.hidden = true;
      try {
        app.settings = await api.patch("/api/v1/settings", {
          language: language.value, theme: theme.value, density: density.value, timezone: zone.value.trim() || "local",
          monitor_interval: Number(interval.value), presence: { enabled: presence.checked, in_reports: presenceReports.checked },
          passive: { enabled: passive.checked },
        });
        applyPreferences(app.settings);
        toast(t("common.saved"), "ok");
        location.reload();
      } catch (error) {
        errorBox.hidden = false;
        errorBox.textContent = error.message;
      }
    };
    replace(prefs, panel(t("settings.preferences"), form));
  }

  // profiles ->
  function profileDialog(profile) {
    const name = h("input", { type: "text", maxlength: "64", value: profile?.name || "", required: true });
    const target = h("input", { type: "text", value: profile?.target || "", placeholder: "192.168.1.0/24", spellcheck: "false" });
    const iface = h("input", { type: "text", value: profile?.interface || "", spellcheck: "false" });
    const ports = h("input", { type: "text", value: profile?.ports || "", placeholder: "top, web, admin, 22,80, 1-1024", spellcheck: "false" });
    const exclude = h("textarea", { rows: "2", spellcheck: "false" }, (profile?.exclude || []).join("\n"));
    const interval = h("input", { type: "number", min: "10", max: "86400", value: profile?.interval_seconds ?? "" });
    const samples = h("input", { type: "number", min: "0", max: "50", value: profile?.options?.latency_samples ?? 3 });
    const tls = h("input", { type: "checkbox", checked: profile?.options?.tls ?? true });
    const ipv6 = h("input", { type: "checkbox", checked: profile?.options?.ipv6 ?? true });
    const errorBox = h("p", { class: "field-error", role: "alert", hidden: true });
    dialog(profile ? t("profiles.edit", { name: profile.name }) : t("profiles.new"), h("div", { class: "settings-form" },
      field(t("profiles.name"), name),
      field(t("profiles.target"), target, { hint: t("profiles.target_hint") }),
      field(t("profiles.interface"), iface, { hint: t("profiles.interface_hint") }),
      field(t("profiles.ports"), ports, { hint: t("profiles.ports_hint") }),
      field(t("profiles.exclude"), exclude, { hint: t("profiles.exclude_hint") }),
      field(t("profiles.interval"), interval, { hint: t("profiles.interval_hint") }),
      field(t("profiles.samples"), samples),
      h("label", { class: "check" }, tls, t("profiles.tls")),
      h("label", { class: "check" }, ipv6, t("profiles.ipv6")),
      errorBox), [
      { label: t("common.cancel") },
      { label: t("common.save"), primary: true, run: async () => {
        const body = {
          name: name.value.trim(), target: target.value.trim() || null, interface: iface.value.trim() || null,
          ports: ports.value.trim() || null, exclude: exclude.value.split(/\s|,/).map((x) => x.trim()).filter(Boolean),
          interval_seconds: interval.value ? Number(interval.value) : null,
          options: { ...(profile?.options || {}), latency_samples: Number(samples.value), tls: tls.checked, ipv6: ipv6.checked },
        };
        try {
          if (profile) await api.patch(`/api/v1/profiles/${profile.id}`, { ...body, version: profile.version });
          else await api.post("/api/v1/profiles", body);
          toast(t("common.saved"), "ok");
          loadProfiles();
        } catch (error) {
          errorBox.hidden = false;
          errorBox.textContent = (error.field ? error.field + ": " : "") + error.message;
          return false;
        }
      } },
    ]);
  }

  async function loadProfiles() {
    try {
      const { items } = await api.get("/api/v1/profiles");
      replace(profilesBox, panel(t("profiles.title"), items.length
        ? h("ul", { class: "profile-list" }, items.map((p) => h("li", {},
          h("strong", {}, p.name), " ",
          h("span", { class: "mono muted" }, p.target || t("profiles.interface_network")), " · ",
          p.ports ? t("profiles.with_ports", { ports: p.ports }) : t("profiles.no_ports"), " · ",
          p.interval_seconds ? t("monitor.every", { s: p.interval_seconds }) : t("profiles.manual"),
          p.exclude.length ? " · " + t("profiles.excluded", { n: p.exclude.length }) : "",
          h("span", { class: "actions inline" },
            h("button", { type: "button", class: "btn small", onClick: () => profileDialog(p) }, t("common.edit")),
            h("button", { type: "button", class: "btn small danger", onClick: async () => {
              try { await api.del(`/api/v1/profiles/${p.id}`); toast(t("profiles.deleted"), "ok"); loadProfiles(); } catch (error) { toast(error.message, "error"); }
            } }, t("common.delete"))))))
        : emptyState(t("profiles.none"), t("profiles.none_text")),
        h("button", { type: "button", class: "btn small primary", onClick: () => profileDialog(null) }, t("profiles.new"))));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(profilesBox, errorState(error, loadProfiles));
    }
  }

  // retention and backup ->
  async function loadRetention() {
    try {
      const preview = await api.post("/api/v1/maintenance/retention", { preview: true });
      const policy = preview.policy;
      const inputs = Object.fromEntries(Object.entries(policy).map(([k, v]) => [k, h("input", { type: "number", min: "1", max: "36500", value: v ?? "", "aria-label": t("retention." + k.replace("_days", "")) + " · " + t("retention.days") })]));
      replace(retentionBox, panel(t("retention.title"), h("div", {},
        h("p", { class: "muted" }, t("retention.intro")),
        h("div", { class: "table-wrap" }, h("table", { class: "table compact" },
          h("thead", {}, h("tr", {}, [t("retention.kind"), t("retention.days"), t("retention.would_delete")].map((x) => h("th", { scope: "col" }, x)))),
          h("tbody", {}, Object.keys(policy).map((k) => {
            const kind = k.replace("_days", "");
            const count = kind === "scans" ? (preview.would_delete.scans ?? 0) + (preview.would_delete.port_coverage ?? 0) : preview.would_delete[kind] ?? 0;
            return h("tr", {}, h("th", { scope: "row" }, t("retention." + kind)), h("td", {}, inputs[k]), h("td", {}, fmtNumber(count)));
          })))),
        h("p", { class: "hint" }, t("retention.kept")),
        h("div", { class: "actions" },
          h("button", { type: "button", class: "btn", onClick: async () => {
            const retention = Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value ? Number(el.value) : null]));
            try { app.settings = await api.patch("/api/v1/settings", { retention }); toast(t("common.saved"), "ok"); loadRetention(); } catch (error) { toast(error.message, "error"); }
          } }, t("retention.save")),
          h("button", { type: "button", class: "btn danger", onClick: () => dialog(t("retention.apply"), h("p", {}, t("retention.confirm")), [
            { label: t("common.cancel") },
            { label: t("retention.apply"), danger: true, run: async () => {
              try {
                const result = await api.post("/api/v1/maintenance/retention", { preview: false });
                toast(t("retention.done", { n: Object.values(result.deleted).reduce((a, b) => a + b, 0) }), "ok");
                loadRetention();
              } catch (error) { toast(error.message, "error"); return false; }
            } },
          ]) }, t("retention.apply")),
          h("button", { type: "button", class: "btn", onClick: async () => {
            try { const b = await api.post("/api/v1/maintenance/backup", {}); toast(t("backup.done", { path: b.path }), "ok"); } catch (error) { toast(error.message, "error"); }
          } }, t("backup.now"))),
        h("p", { class: "hint" }, t("backup.hint")))));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(retentionBox, errorState(error, loadRetention));
    }
  }

  // diagnostics ->
  async function loadDiagnostics() {
    try {
      const d = await api.get("/api/v1/diagnostics");
      const c = d.capabilities;
      const yes = (value, fix) => (value ? badge(t("common.available"), "ok", "✓") : [badge(t("common.unavailable"), "warn", "!"), fix ? h("div", { class: "hint" }, fix) : null]);
      replace(diagBox, panel(t("diag.title"), h("div", {},
        facts([
          [t("diag.version"), d.version],
          [t("diag.platform"), `${c.platform} · python ${c.python}`],
          [t("diag.privileged"), yes(c.privileged_mode, t("diag.privileged_fix"))],
          [t("diag.icmp"), yes(c.unprivileged_icmp, t("diag.icmp_fix"))],
          [t("diag.scapy"), yes(c.scapy)],
          [t("diag.ipv6"), yes(c.ipv6_neighbours)],
          [t("diag.notifications"), yes(c.desktop_notifications, t("diag.notifications_fix"))],
          [t("diag.vendors"), c.vendors ? fmtNumber(c.vendors) : [badge(t("common.unavailable"), "warn", "!"), h("div", { class: "hint" }, t("diag.vendors_fix"))]],
          [t("diag.data"), h("code", {}, d.paths.data)],
          [t("diag.database"), [h("code", {}, d.paths.database), " · ", fmtNumber(d.database.bytes / 1048576, 1), " MB · ", t("diag.schema", { v: d.database.schema })]],
          [t("diag.timezone"), d.timezone],
        ]),
        h("details", {}, h("summary", {}, t("diag.tables")), facts(Object.entries(d.database.tables).map(([k, v]) => [k, fmtNumber(v)]))),
        d.leases.length ? h("details", {}, h("summary", {}, t("diag.leases")), h("ul", { class: "small" }, d.leases.map((l) => h("li", {}, `${l.scope} · ${l.kind} · pid ${l.pid} · ${l.active ? t("diag.active") : t("diag.expired")}`)))) : null,
        d.recent_failures.length ? h("details", {}, h("summary", {}, t("diag.failures", { n: d.recent_failures.length })), h("ul", { class: "small" }, d.recent_failures.map((s) => h("li", {}, `#${s.id} · ${s.started_at} · ${s.issues.map((i) => i.message).join("; ")}`)))) : null,
        h("details", {}, h("summary", {}, t("diag.troubleshooting")), h("ul", {}, ["empty", "slow", "offline", "signin", "lan"].map((k) => h("li", {}, h("strong", {}, t("trouble." + k + "_q")), " ", t("trouble." + k + "_a"))))))));
    } catch (error) {
      if (error.status === 401) throw error;
      replace(diagBox, errorState(error, loadDiagnostics));
    }
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("settings.title"))), h("div", { class: "columns" }, prefs, profilesBox), retentionBox, diagBox);
  drawPrefs();
  replace(diagBox, loading());
  await Promise.all([loadProfiles(), loadRetention(), loadDiagnostics()]);
  if (location.hash === "#profiles") profilesBox.scrollIntoView();
  return {
    refresh(changes) {
      if (document.querySelector(".backdrop") || root.contains(document.activeElement)) return;
      if (changes.some((c) => c.kind.startsWith("profile."))) loadProfiles();
    },
  };
}
