// informes: standalone exports. sensitive parts (presence, fingerprints) only on explicit choice,
// with a preview of exactly what will be included before downloading.

import { api } from "../api.js";
import { app } from "../app.js";
import { errorState, facts, field, panel, select } from "../components.js";
import { h, replace } from "../dom.js";
import { fmtNumber, t } from "../i18n.js";

const FIELDS = [
  "ip", "mac", "hostname", "alias", "vendor", "randomized_mac", "os_guess", "ttl", "status", "trusted", "gateway",
  "latency_avg_ms", "latency_jitter_ms", "packet_loss_pct", "open_ports", "first_seen", "last_seen",
  "network_id", "ips6", "category", "tags", "owner", "essential", "risk", "risk_level", "risk_complete",
];

export async function mount(root) {
  const format = select([["html", t("reports.html")], ["json", "JSON"], ["csv", "CSV"]], "html", { id: "r-format" });
  const online = h("input", { type: "checkbox" });
  const events = h("input", { type: "number", min: "0", max: "1000", value: "50", id: "r-events" });
  const since = h("input", { type: "date", id: "r-since" });
  const presence = h("input", { type: "checkbox" });
  const fingerprint = h("input", { type: "checkbox" });
  const anonymize = h("input", { type: "checkbox" });
  const fieldBoxes = FIELDS.map((f) => h("label", { class: "check" }, h("input", { type: "checkbox", value: f }), f));
  const preview = h("div", { "aria-live": "polite" });
  const download = h("a", { class: "btn primary", download: "" }, t("reports.download"));

  function options() {
    const fields = fieldBoxes.map((l) => l.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
    return {
      format: format.value,
      network: app.network() ?? "",
      online: online.checked ? "true" : "",
      events: events.value,
      since: since.value ? new Date(since.value + "T00:00:00").toISOString() : "",
      fields: fields.join(","),
      include_presence: presence.checked ? "true" : "",
      include_fingerprint: fingerprint.checked ? "true" : "",
      anonymize: anonymize.checked ? "true" : "",
    };
  }

  async function refreshPreview() {
    const opts = options();
    const params = new URLSearchParams(Object.entries(opts).filter(([, v]) => v !== "" && v !== null));
    download.href = "/api/v1/reports/export?" + params;
    try {
      const data = await api.get("/api/v1/reports/preview", opts);
      replace(preview,
        facts([
          [t("reports.devices"), fmtNumber(data.devices)],
          [t("reports.events"), fmtNumber(data.events)],
          [t("reports.fields"), data.fields ? data.fields.join(", ") : t("reports.default_fields")],
          [t("reports.presence"), data.includes_presence ? t("common.yes") : t("common.no")],
          [t("reports.fingerprint"), data.includes_fingerprint ? t("common.yes") : t("common.no")],
          [t("reports.anonymized"), data.anonymized ? t("common.yes") : t("common.no")],
        ]),
        data.warnings.length ? h("ul", { class: "notice" }, data.warnings.map((w) => h("li", {}, w))) : null,
        data.sample ? h("details", {}, h("summary", {}, t("reports.sample")), h("pre", { class: "code small" }, JSON.stringify(data.sample, null, 2))) : null);
    } catch (error) {
      replace(preview, errorState(error, refreshPreview));
    }
  }

  const form = h("form", { class: "report-form", onSubmit: (e) => e.preventDefault(), onChange: refreshPreview },
    field(t("reports.format"), format, { hint: t("reports.format_hint") }),
    h("label", { class: "check" }, online, t("reports.online_only")),
    field(t("reports.events_count"), events),
    field(t("reports.since"), since, { hint: t("reports.since_hint") }),
    h("fieldset", { class: "checks" }, h("legend", {}, t("reports.sensitive")),
      h("label", { class: "check" }, presence, t("reports.include_presence")),
      h("label", { class: "check" }, fingerprint, t("reports.include_fingerprint")),
      h("label", { class: "check" }, anonymize, t("reports.anonymize")),
      h("p", { class: "hint" }, t("reports.anonymize_hint"))),
    h("details", {}, h("summary", {}, t("reports.choose_fields")), h("fieldset", { class: "checks columns-3" }, h("legend", { class: "sr-only" }, t("reports.choose_fields")), fieldBoxes)));

  replace(root,
    h("header", { class: "view-head" }, h("h1", {}, t("reports.title")), h("p", { class: "muted" }, t("reports.intro"))),
    h("div", { class: "columns" }, panel(t("reports.options"), form), panel(t("reports.preview"), h("div", {}, preview, download))),
    panel(t("reports.print_title"), h("p", { class: "muted" }, t("reports.print_text"))));
  await refreshPreview();
  return {};
}
