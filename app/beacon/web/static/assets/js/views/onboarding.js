// primer uso: pick the network, see what this machine can do, run a first discovery and decide
// on the baseline device by device. nothing is trusted unless the person selects it.

import { api } from "../api.js";
import { app } from "../app.js";
import { badge, deviceLink, errorState, field, loading, riskBadge } from "../components.js";
import { dialog, h, replace, toast } from "../dom.js";
import { fmtNumber, t } from "../i18n.js";
import { navigate } from "../router.js";

const PORTS = [["", "onboard.ports_none"], ["top", "onboard.ports_top"], ["web", "onboard.ports_web"], ["admin", "onboard.ports_admin"]];

export async function mount(root) {
  const step = h("div", { class: "onboarding" });
  const steps = h("ol", { class: "steps", "aria-label": t("onboard.progress") });
  let current = 1;
  let jobId = null;
  let poll = null;

  function drawSteps() {
    replace(steps, [1, 2, 3].map((n) => h("li", { class: n === current ? "current" : n < current ? "done" : "", "aria-current": n === current ? "step" : undefined },
      h("span", { class: "step-n", "aria-hidden": "true" }, n < current ? "✓" : String(n)), t("onboard.step" + n))));
  }

  async function finish(startMonitor) {
    try {
      app.settings = await api.patch("/api/v1/settings", { onboarded: true });
      if (startMonitor) await api.post("/api/v1/monitor", { action: "start" });
      await app.reloadStatus();
      navigate("/");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  // step 1 ->
  async function chooseNetwork() {
    current = 1;
    drawSteps();
    replace(step, loading());
    let interfaces;
    try {
      interfaces = (await api.get("/api/v1/interfaces")).items;
    } catch (error) {
      replace(step, errorState(error, chooseNetwork));
      return;
    }
    const caps = (await api.get("/api/v1/status")).capabilities;
    const radios = interfaces.map((iface, i) => h("label", { class: "choice" },
      h("input", { type: "radio", name: "iface", value: iface.name, checked: i === 0 }),
      h("span", {}, h("strong", {}, iface.name), " ", h("span", { class: "mono" }, iface.network), " ", h("span", { class: "muted" }, iface.gateway ? t("onboard.gateway", { ip: iface.gateway }) : ""))));
    const ports = h("select", { id: "onboard-ports" }, PORTS.map(([v, k]) => h("option", { value: v, selected: v === "top" }, t(k))));
    replace(step,
      h("h2", {}, t("onboard.step1_title")),
      interfaces.length
        ? h("fieldset", { class: "choices" }, h("legend", {}, t("onboard.interface")), radios)
        : h("p", { class: "warn-text" }, t("onboard.no_interfaces")),
      field(t("onboard.ports"), ports, { hint: t("onboard.ports_hint") }),
      h("h3", {}, t("onboard.capabilities")),
      h("ul", { class: "capabilities" },
        h("li", {}, caps.privileged_mode ? badge(t("onboard.cap_privileged"), "ok", "✓") : badge(t("onboard.cap_unprivileged"), "", "·"), " ", h("span", { class: "muted" }, caps.privileged_mode ? t("onboard.cap_privileged_text") : t("onboard.cap_unprivileged_text"))),
        h("li", {}, caps.unprivileged_icmp ? badge(t("onboard.cap_icmp"), "ok", "✓") : badge(t("onboard.cap_no_icmp"), "warn", "!")),
        h("li", {}, caps.vendors ? badge(t("onboard.cap_vendors", { n: fmtNumber(caps.vendors) }), "ok", "✓") : [badge(t("onboard.cap_no_vendors"), "warn", "!"), " ", h("code", {}, "beacon vendors update")])),
      h("p", { class: "muted small" }, t("onboard.scope_note")),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn primary", disabled: !interfaces.length, onClick: () => {
          const chosen = step.querySelector("input[name=iface]:checked")?.value;
          runDiscovery(chosen, ports.value);
        } }, t("onboard.start")),
        h("button", { type: "button", class: "btn", onClick: () => finish(false) }, t("onboard.skip"))));
  }

  // step 2 ->
  async function runDiscovery(iface, ports) {
    current = 2;
    drawSteps();
    replace(step, h("h2", {}, t("onboard.step2_title")), loading(t("onboard.creating_profile")));
    try {
      const existing = (await api.get("/api/v1/profiles")).items.find((p) => p.name === "default");
      const body = { name: "default", interface: iface || null, ports: ports || null, target: null };
      const profile = existing
        ? await api.patch(`/api/v1/profiles/${existing.id}`, { interface: body.interface, ports: body.ports, version: existing.version })
        : await api.post("/api/v1/profiles", body);
      const job = await api.post("/api/v1/jobs", { profile_id: profile.id });
      jobId = job.id;
    } catch (error) {
      replace(step, h("h2", {}, t("onboard.step2_title")), errorState(error, () => runDiscovery(iface, ports)));
      return;
    }
    const progress = h("progress", { "aria-label": t("job.progress") });
    const stage = h("p", { "aria-live": "polite" }, t("job.waiting"));
    replace(step, h("h2", {}, t("onboard.step2_title")), h("p", { class: "muted" }, t("onboard.discovery_text")), stage, progress,
      h("button", { type: "button", class: "btn", onClick: async () => { await api.del(`/api/v1/jobs/${jobId}`).catch(() => {}); chooseNetwork(); } }, t("common.cancel")));
    clearInterval(poll);
    poll = setInterval(async () => {
      let job;
      try { job = await api.get(`/api/v1/jobs/${jobId}`); } catch { return; }
      if (job.state === "running" || job.state === "queued") {
        stage.textContent = job.stage ? t("onboard.stage", { stage: job.stage }) : t("job.waiting");
        if (job.progress.total) { progress.max = job.progress.total; progress.value = job.progress.done; }
        return;
      }
      clearInterval(poll);
      if (job.state === "completed") reviewBaseline(job);
      else replace(step, h("h2", {}, t("onboard.step2_title")),
        h("p", { class: "warn-text", role: "alert" }, t("onboard.failed", { reason: job.error || t("job." + job.state) })),
        h("button", { type: "button", class: "btn", onClick: chooseNetwork }, t("common.retry")));
    }, 700);
  }

  // step 3 ->
  async function reviewBaseline(job) {
    current = 3;
    drawSteps();
    replace(step, loading());
    await app.reloadStatus();
    const data = await api.get("/api/v1/devices", { size: 500, sort: "risk", order: "desc" });
    const boxes = new Map();
    const rows = data.items.map((d) => {
      const box = h("input", { type: "checkbox", "aria-label": t("bulk.select_one", { name: d.name }), checked: d.trusted, disabled: d.trusted });
      boxes.set(d.key, box);
      return h("li", { class: "baseline-item" }, box, deviceLink(d), h("span", { class: "mono muted" }, d.ip), h("span", { class: "muted" }, d.vendor || (d.randomized_mac ? t("devices.randomized") : t("devices.unknown_vendor"))), riskBadge(d.risk));
    });
    const monitor = h("input", { type: "checkbox", checked: true });
    const selected = () => [...boxes.entries()].filter(([, b]) => b.checked && !b.disabled).map(([k]) => k);
    replace(step,
      h("h2", {}, t("onboard.step3_title")),
      h("p", {}, t("onboard.found", { n: data.total, status: t("scan.status." + (job.scan_status || "complete")) })),
      h("p", { class: "notice" }, t("onboard.baseline_note")),
      data.items.length ? h("ul", { class: "baseline" }, rows) : h("p", { class: "muted" }, t("onboard.nothing_found")),
      h("label", { class: "check" }, monitor, t("onboard.start_monitor")),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn primary", onClick: () => {
          const keys = selected();
          if (!keys.length) { finish(monitor.checked).then(() => navigate("/review")); return; }
          dialog(t("onboard.trust_title"), h("div", {}, h("p", {}, t("onboard.trust_confirm", { n: keys.length })),
            h("ul", { class: "small" }, keys.map((k) => h("li", { class: "mono" }, k)))), [
            { label: t("common.cancel") },
            { label: t("review.trust"), primary: true, run: async () => {
              const result = await api.post("/api/v1/devices/bulk", { keys, action: "trust" });
              toast(t("bulk.done", { ok: result.ok, failed: result.failed }), result.failed ? "error" : "ok");
              await finish(monitor.checked);
            } },
          ]);
        } }, t("onboard.trust_selected")),
        h("button", { type: "button", class: "btn", onClick: async () => { await finish(monitor.checked); navigate("/review"); } }, t("onboard.review_one_by_one"))));
  }

  replace(root, h("header", { class: "view-head" }, h("h1", {}, t("onboard.title")), h("p", { class: "muted" }, t("onboard.intro"))), steps, step);
  await chooseNetwork();
  return { destroy: () => clearInterval(poll) };
}
