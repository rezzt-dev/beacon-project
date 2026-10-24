// thin fetch wrapper: json in and out, the csrf header on writes, one error shape.

let csrf = null;

export class ApiError extends Error {
  constructor(status, code, message, field, extra) {
    super(message);
    this.status = status;
    this.code = code;
    this.field = field;
    this.extra = extra || {};
  }
}

export function setCsrf(token) {
  csrf = token;
}

async function request(method, path, { body, query, headers } = {}) {
  const url = new URL(path, location.origin);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) value.forEach((v) => url.searchParams.append(key, v));
      else url.searchParams.set(key, String(value));
    }
  }
  const init = { method, credentials: "same-origin", headers: { accept: "application/json", ...(headers || {}) } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (method !== "GET" && csrf) init.headers["x-beacon-csrf"] = csrf;
  let response;
  try {
    response = await fetch(url, init);
  } catch (error) {
    throw new ApiError(0, "offline", "beacon live is not reachable");
  }
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json().catch(() => null) : await response.text();
  if (!response.ok) {
    const err = (data && data.error) || {};
    const { code, message, field, ...extra } = err;
    throw new ApiError(response.status, code || "http_" + response.status, message || response.statusText, field, extra);
  }
  return data;
}

export const api = {
  get: (path, query) => request("GET", path, { query }),
  post: (path, body, headers) => request("POST", path, { body: body ?? {}, headers }),
  patch: (path, body, headers) => request("PATCH", path, { body, headers }),
  del: (path) => request("DELETE", path),
};

export const devicePath = (key) => "/api/v1/devices/" + encodeURIComponent(key);
