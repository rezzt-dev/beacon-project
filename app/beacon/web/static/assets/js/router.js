// history-api router: every view has a stable url that survives a reload; filters live in the query.

const routes = [];
let current = null;
let onNavigate = () => {};

/** route("/devices/:key", loader, {nav, group}) - `loader` resolves to the view module. */
export function route(pattern, loader, meta = {}) {
  const names = [];
  const regex = new RegExp(
    "^" + pattern.replace(/\/:(\w+)/g, (_, name) => { names.push(name); return "/([^/]+)"; }) + "/?$",
  );
  routes.push({ pattern, regex, names, loader, meta });
}

export function match(pathname) {
  for (const entry of routes) {
    const found = entry.regex.exec(pathname);
    if (found) {
      const params = {};
      entry.names.forEach((name, i) => { params[name] = decodeURIComponent(found[i + 1]); });
      return { ...entry, params };
    }
  }
  return null;
}

export function start(handler) {
  onNavigate = handler;
  window.addEventListener("popstate", () => resolve());
  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[href]");
    if (!link || link.target || link.hasAttribute("download") || event.defaultPrevented) return;
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const url = new URL(link.href, location.href);
    if (url.origin !== location.origin || url.pathname.startsWith("/api/") || url.pathname === "/login") return;
    event.preventDefault();
    navigate(url.pathname + url.search);
  });
  resolve();
}

export function navigate(path, { replace = false } = {}) {
  if (path === location.pathname + location.search) return;
  history[replace ? "replaceState" : "pushState"](null, "", path);
  resolve();
}

function resolve() {
  current = match(location.pathname) || match("/404");
  onNavigate(current);
}

export const currentRoute = () => current;

/** the query string as a plain object. */
export function query() {
  return Object.fromEntries(new URLSearchParams(location.search));
}

/** change some query values without a new history entry (filters, sort, page). */
export function setQuery(patch, { push = false } = {}) {
  const params = new URLSearchParams(location.search);
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined || value === null || value === "" || value === false) params.delete(key);
    else params.set(key, String(value));
  }
  const search = params.toString();
  const url = location.pathname + (search ? "?" + search : "");
  history[push ? "pushState" : "replaceState"](null, "", url);
}

export const devicePage = (key) => "/devices/" + encodeURIComponent(key);
