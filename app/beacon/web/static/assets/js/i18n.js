// strings and locale formatting. every visible text goes through `t`; dates, numbers and
// durations through `Intl`, in the language and time zone the user chose.

import { STRINGS } from "./strings.js";

let lang = "en";
let timeZone;

export function setLocale(language, zone) {
  const wanted = language === "auto" ? (navigator.language || "en").slice(0, 2) : language;
  lang = STRINGS[wanted] ? wanted : "en";
  timeZone = zone && zone !== "local" ? zone : undefined;
  document.documentElement.lang = lang;
}

export const currentLang = () => lang;

/** t("devices.count", {n: 3}) - plural entries are `{one, other}` objects. */
export function t(key, params = {}) {
  let entry = STRINGS[lang][key] ?? STRINGS.en[key];
  if (entry === undefined) {
    console.warn("missing string", key);
    return key;
  }
  if (typeof entry === "object") {
    const rule = new Intl.PluralRules(lang).select(Number(params.n ?? 0));
    entry = entry[rule] ?? entry.other;
  }
  return entry.replace(/\{(\w+)\}/g, (_, name) => (params[name] === undefined ? "" : String(params[name])));
}

const dateCache = new Map();
function formatter(options) {
  const key = lang + (timeZone || "") + JSON.stringify(options);
  if (!dateCache.has(key)) dateCache.set(key, new Intl.DateTimeFormat(lang, { timeZone, ...options }));
  return dateCache.get(key);
}

export function fmtDateTime(value, withSeconds = false) {
  if (!value) return t("common.never");
  const date = new Date(value);
  return formatter({ dateStyle: "medium", timeStyle: withSeconds ? "medium" : "short" }).format(date);
}

export function fmtDate(value) {
  if (!value) return t("common.never");
  return formatter({ dateStyle: "medium" }).format(new Date(value));
}

export function fmtClock(value) {
  if (!value) return "—";
  const date = new Date(value);
  const today = new Date();
  return date.toDateString() === today.toDateString()
    ? formatter({ hour: "2-digit", minute: "2-digit" }).format(date)
    : formatter({ month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(date);
}

export function fmtNumber(value, digits = 0) {
  if (value === null || value === undefined) return "—";
  return new Intl.NumberFormat(lang, { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(value);
}

export function fmtPercent(value, digits = 0) {
  if (value === null || value === undefined) return "—";
  return new Intl.NumberFormat(lang, { style: "percent", maximumFractionDigits: digits }).format(value);
}

/** "3 min ago" / "in 20 s", in the user's language. */
export function fmtRelative(value, now = Date.now()) {
  if (!value) return t("common.never");
  const seconds = Math.round((new Date(value).getTime() - now) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  const abs = Math.abs(seconds);
  if (abs < 45) return rtf.format(Math.round(seconds), "second");
  if (abs < 2700) return rtf.format(Math.round(seconds / 60), "minute");
  if (abs < 64800) return rtf.format(Math.round(seconds / 3600), "hour");
  return rtf.format(Math.round(seconds / 86400), "day");
}

export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return t("duration.seconds", { n: s });
  if (s < 3600) return t("duration.minutes", { n: Math.round(s / 60) });
  if (s < 172800) return t("duration.hours", { n: Math.floor(s / 3600), m: Math.round((s % 3600) / 60) });
  return t("duration.days", { n: Math.round(s / 86400) });
}

export const DAY_KEYS = ["day.mon", "day.tue", "day.wed", "day.thu", "day.fri", "day.sat", "day.sun"];
