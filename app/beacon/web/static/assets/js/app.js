// shared state of the page: server status, settings and the chosen network.

import { api } from "./api.js";
import { setLocale } from "./i18n.js";

const NETWORK_KEY = "beacon.network";
const statusListeners = new Set();

function readNetwork() {
  try {
    const raw = localStorage.getItem(NETWORK_KEY);
    return raw ? Number(raw) : null;
  } catch {
    return null;
  }
}

export const app = {
  status: null,
  settings: null,
  live: null,
  networkId: readNetwork(),

  /** the network filter every view applies, or null for all of them. */
  network() {
    const known = this.status?.networks || [];
    return known.some((n) => n.id === this.networkId) ? this.networkId : null;
  },

  setNetwork(id) {
    this.networkId = id;
    try {
      if (id === null) localStorage.removeItem(NETWORK_KEY);
      else localStorage.setItem(NETWORK_KEY, String(id));
    } catch {
      // private mode: the choice lasts until reload
    }
  },

  setStatus(status) {
    this.status = { ...(this.status || {}), ...status };
    for (const fn of statusListeners) fn(this.status);
  },

  onStatus(fn) {
    statusListeners.add(fn);
    return () => statusListeners.delete(fn);
  },

  async reloadStatus() {
    this.setStatus(await api.get("/api/v1/status"));
    return this.status;
  },
};

/** theme, density and language from the saved settings. */
export function applyPreferences(settings) {
  const root = document.documentElement;
  root.dataset.theme = settings.theme || "system";
  root.dataset.density = settings.density || "comfortable";
  setLocale(settings.language || "auto", settings.timezone);
}
