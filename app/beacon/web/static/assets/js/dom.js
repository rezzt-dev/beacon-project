// dom helpers: every value from the network is set as text, never parsed as html.

const SVG_NS = "http://www.w3.org/2000/svg";

/** h("button", {class: "btn", onClick: fn}, "label", child) -> element. */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  applyAttrs(el, attrs);
  append(el, children);
  return el;
}

/** svg element with the same api as `h`. */
export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyAttrs(el, attrs, true);
  append(el, children);
  return el;
}

function applyAttrs(el, attrs, svg = false) {
  if (!attrs) return;
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === "class") {
      el.setAttribute("class", Array.isArray(value) ? value.filter(Boolean).join(" ") : value);
    } else if (key === "dataset") {
      for (const [k, v] of Object.entries(value)) if (v !== undefined && v !== null) el.dataset[k] = String(v);
    } else if (key === "text") {
      el.textContent = String(value);
    } else if (key === "value" && !svg) {
      el.value = value;
    } else if (key === "checked" && !svg) {
      el.checked = Boolean(value);
    } else if (value === true) {
      el.setAttribute(key, "");
    } else {
      el.setAttribute(key, String(value));
    }
  }
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function clear(el) {
  while (el.firstChild) el.firstChild.remove();
  return el;
}

export function replace(el, ...children) {
  clear(el);
  append(el, children);
  return el;
}

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

/** a small set of line icons, drawn here so nothing is fetched from elsewhere. */
const ICONS = {
  overview: "M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z",
  devices: "M4 5h16v10H4zM8 19h8M12 15v4",
  review: "M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11",
  events: "M12 8v4l3 3M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",
  presence: "M3 4h18v16H3zM3 9h18M8 4v16M13 4v16",
  identities: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8",
  services: "M4 6h16M4 12h16M4 18h16M8 6v0M8 12v0M8 18v0",
  networks: "M12 2v6M12 16v6M4.9 4.9l4.2 4.2M14.9 14.9l4.2 4.2M2 12h6M16 12h6M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  scans: "M21 12a9 9 0 1 1-3-6.7M21 4v5h-5",
  reports: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
  menu: "M3 6h18M3 12h18M3 18h18",
  close: "M18 6L6 18M6 6l12 12",
  check: "M20 6L9 17l-5-5",
  alert: "M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  info: "M12 16v-4M12 8h.01M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z",
  pause: "M6 4h4v16H6zM14 4h4v16h-4z",
  play: "M5 3l14 9-14 9z",
  external: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3",
};

export function icon(name, label) {
  const svg = s("svg", { viewBox: "0 0 24 24", class: "icon", "aria-hidden": label ? undefined : "true", role: label ? "img" : undefined, "aria-label": label },
    s("path", { d: ICONS[name] || ICONS.info }));
  return svg;
}

/** polite announcements for screen readers, rate limited so live updates never flood them. */
let lastAnnounce = 0;
export function announce(message, assertive = false) {
  const region = document.getElementById(assertive ? "sr-alert" : "sr-status");
  if (!region) return;
  const now = Date.now();
  if (!assertive && now - lastAnnounce < 4000) return;
  lastAnnounce = now;
  region.textContent = "";
  setTimeout(() => { region.textContent = message; }, 50);
}

/** a transient message with an optional action; never steals focus. */
export function toast(message, kind = "info", action = null) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const item = h("div", { class: ["toast", kind], role: kind === "error" ? "alert" : "status" },
    icon(kind === "error" ? "alert" : kind === "ok" ? "check" : "info"),
    h("span", { class: "toast-text" }, message),
    action ? h("button", { type: "button", class: "btn small", onClick: () => { action.run(); item.remove(); } }, action.label) : null,
    h("button", { type: "button", class: "icon-btn", "aria-label": "×", onClick: () => item.remove() }, icon("close")));
  host.append(item);
  setTimeout(() => item.remove(), kind === "error" ? 10000 : 5000);
}

/**
 * modal dialog with focus trap: focus moves in, tab stays in, escape closes, focus returns.
 * returns {close, element}.
 */
export function dialog(title, body, actions = [], { onClose } = {}) {
  const opener = document.activeElement;
  const titleId = `dlg-${Math.random().toString(36).slice(2)}`;
  const close = () => {
    backdrop.remove();
    document.removeEventListener("keydown", onKey, true);
    if (onClose) onClose();
    if (opener && opener.isConnected) opener.focus();
  };
  const panel = h("div", { class: "dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, tabindex: "-1" },
    h("div", { class: "dialog-head" },
      h("h2", { id: titleId }, title),
      h("button", { type: "button", class: "icon-btn", "aria-label": "close", onClick: close }, icon("close"))),
    h("div", { class: "dialog-body" }, body),
    actions.length ? h("div", { class: "dialog-actions" }, actions.map((a) => h("button", {
      type: "button",
      class: ["btn", a.primary ? "primary" : "", a.danger ? "danger" : ""],
      onClick: async () => { if ((await a.run?.()) !== false) close(); },
    }, a.label))) : null);
  const backdrop = h("div", { class: "backdrop", onMousedown: (e) => { if (e.target === backdrop) close(); } }, panel);
  function onKey(event) {
    if (event.key === "Escape") { event.preventDefault(); close(); return; }
    if (event.key !== "Tab") return;
    const focusable = $$('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])', panel).filter((el) => !el.disabled && el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (!focusable.includes(document.activeElement)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
    else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
  document.addEventListener("keydown", onKey, true);
  document.body.append(backdrop);
  const target = $("input, select, textarea", panel) || $(".dialog-actions .primary", panel) || panel;
  target.focus();
  return { close, element: panel };
}

export function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}
