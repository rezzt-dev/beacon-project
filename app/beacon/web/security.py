 # import libraries ->
import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


 # constants ->
SESSION_COOKIE = "beacon_session"
CSRF_HEADER = "x-beacon-csrf"
SESSION_TTL = 12 * 3600
MAX_BODY = 64 * 1024
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# everything the page may load comes from this server; nothing inline, nothing remote
CSP = (
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
  "font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
  "content-security-policy": CSP,
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), usb=(), serial=()",
}


 # secrets ->
def _write_secret(path: Path, value: str) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, "w") as handle:
    handle.write(value)


def load_secret(path: Path, rotate: bool = False) -> str:
  """a random secret kept in the data directory with owner-only permissions."""
  if not rotate and path.is_file():
    value = path.read_text().strip()
    if len(value) >= 32:
      return value
  value = secrets.token_urlsafe(32)
  _write_secret(path, value)
  return value


 # sessions ->
@dataclass(slots=True)
class Auth:
  """login token and signed session cookies. stateless: sessions survive a server restart.

  `token` is what the login link carries; `key` signs cookies. both live in files only the owner
  can read. the csrf token is derived from the session, so it never needs storing either.
  """

  token: str
  key: bytes
  secure_cookie: bool = False

  @classmethod
  def from_dir(cls, directory: Path, rotate: bool = False, secure_cookie: bool = False) -> "Auth":
    token = load_secret(directory / "live-token", rotate)
    key = load_secret(directory / "live-session-key", rotate).encode()
    return cls(token, key, secure_cookie)

  def check_token(self, candidate: str) -> bool:
    return hmac.compare_digest(candidate.encode(), self.token.encode())

  def _sign(self, payload: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(self.key, payload.encode(), hashlib.sha256).digest()).decode().rstrip("=")

  def new_session(self, now: float | None = None) -> str:
    session_id = secrets.token_urlsafe(18)
    expires = int((now or time.time()) + SESSION_TTL)
    payload = f"{session_id}.{expires}"
    return f"{payload}.{self._sign(payload)}"

  def session_id(self, cookie: str | None, now: float | None = None) -> str | None:
    if not cookie or cookie.count(".") != 2:
      return None
    session_id, expires, signature = cookie.split(".")
    if not hmac.compare_digest(signature, self._sign(f"{session_id}.{expires}")):
      return None
    if not expires.isdigit() or int(expires) < (now or time.time()):
      return None
    return session_id

  def csrf_for(self, session_id: str) -> str:
    return self._sign(f"csrf:{session_id}")

  def cookie_header(self, value: str, max_age: int = SESSION_TTL) -> str:
    flags = f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    return flags + ("; Secure" if self.secure_cookie else "")


 # rate limiting ->
@dataclass(slots=True)
class RateLimiter:
  """token buckets per (client, bucket name): cheap protection against floods and runaway scripts."""

  rates: dict[str, tuple[int, float]] = field(
    default_factory=lambda: {"login": (10, 60.0), "write": (60, 10.0), "jobs": (6, 60.0), "read": (600, 10.0)}
  )
  _buckets: dict[tuple[str, str], tuple[float, float]] = field(default_factory=dict)
  _lock: threading.Lock = field(default_factory=threading.Lock)

  def allow(self, client: str, bucket: str, now: float | None = None) -> bool:
    capacity, period = self.rates[bucket]
    now = now or time.monotonic()
    with self._lock:
      tokens, updated = self._buckets.get((client, bucket), (float(capacity), now))
      tokens = min(capacity, tokens + (now - updated) * capacity / period)
      if tokens < 1:
        self._buckets[(client, bucket)] = (tokens, now)
        return False
      self._buckets[(client, bucket)] = (tokens - 1, now)
      if len(self._buckets) > 10_000:
        self._buckets.clear()
      return True


 # middleware ->
def _error(status: int, code: str, message: str) -> JSONResponse:
  return JSONResponse({"error": {"code": code, "message": message}}, status_code=status, headers={"cache-control": "no-store"})


class GuardMiddleware:
  """the checks every request passes before reaching a route.

  - host: only the names this server was started for (dns rebinding cannot reach the api).
  - origin: a browser write must come from this same origin.
  - auth: everything under `/api/` except the session endpoints needs a valid session cookie,
    and every write also needs the csrf header that only our own page can read.
  - limits: request body size and per-client rates.
  """

  def __init__(self, app: ASGIApp, auth: Auth, allowed_hosts: set[str], limiter: RateLimiter | None = None) -> None:
    self.app = app
    self.auth = auth
    self.allowed_hosts = {h.lower() for h in allowed_hosts}
    self.limiter = limiter or RateLimiter()

  async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] != "http":
      await self.app(scope, receive, send)
      return
    headers = Headers(scope=scope)
    method = scope["method"]
    path = scope["path"]
    client = (scope.get("client") or ("?", 0))[0]

    host = headers.get("host", "").lower()
    if host not in self.allowed_hosts:
      await _error(421, "bad_host", "this server only answers to the address it was started on")(scope, receive, send)
      return
    origin = headers.get("origin")
    if method not in SAFE_METHODS and origin is not None and origin.lower() not in {f"http://{host}", f"https://{host}"}:
      await _error(403, "bad_origin", "cross-origin requests are not allowed")(scope, receive, send)
      return
    if headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
      await _error(403, "bad_origin", "cross-site requests are not allowed")(scope, receive, send)
      return

    if path.startswith("/api/"):
      public = path in ("/api/v1/session", "/api/v1/health")
      bucket = "login" if public and method == "POST" else "read" if method in SAFE_METHODS else "write"
      if path.startswith("/api/v1/jobs") and method == "POST":
        bucket = "jobs"
      if not self.limiter.allow(client, bucket):
        await _error(429, "rate_limited", "too many requests; slow down")(scope, receive, send)
        return
      session = self.auth.session_id(_cookie(headers.get("cookie", ""), SESSION_COOKIE))
      scope.setdefault("state", {})["session"] = session
      if not public and session is None:
        await _error(401, "unauthenticated", "open the link printed by `beacon live` to sign in")(scope, receive, send)
        return
      if method not in SAFE_METHODS and not public:
        sent = headers.get(CSRF_HEADER, "")
        if session is None or not hmac.compare_digest(sent, self.auth.csrf_for(session)):
          await _error(403, "csrf", "missing or wrong csrf token; reload the page")(scope, receive, send)
          return
      length = headers.get("content-length")
      if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
        await _error(413, "too_large", f"request bodies are limited to {MAX_BODY // 1024} kb")(scope, receive, send)
        return
      receive = _limited(receive, MAX_BODY)

    async def send_with_headers(message: Message) -> None:
      if message["type"] == "http.response.start":
        raw = list(message.get("headers", []))
        present = {k.decode().lower() for k, _ in raw}
        for name, value in SECURITY_HEADERS.items():
          if name not in present:
            raw.append((name.encode(), value.encode()))
        if path.startswith("/api/") and "cache-control" not in present:
          raw.append((b"cache-control", b"no-store"))
        message["headers"] = raw
      await send(message)

    await self.app(scope, receive, send_with_headers)


def _cookie(header: str, name: str) -> str | None:
  for part in header.split(";"):
    key, _, value = part.strip().partition("=")
    if key == name:
      return value
  return None


def _limited(receive: Receive, limit: int) -> Receive:
  """a body without content-length (chunked) is cut off at `limit` bytes as well."""
  seen = 0

  async def wrapped() -> Message:
    nonlocal seen
    message = await receive()
    if message["type"] == "http.request":
      seen += len(message.get("body", b""))
      if seen > limit:
        raise ValueError("request body too large")
    return message

  return wrapped
