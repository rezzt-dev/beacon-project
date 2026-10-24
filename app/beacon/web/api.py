 # import libraries ->
import json
import os
import platform
import shutil
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, TypeVar

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from beacon import __version__
from beacon.core.events import EventType, Severity
from beacon.core.models import DeviceStatus, utcnow
from beacon.core.risk import RULES_VERSION, RiskLevel
from beacon.scanners.network import list_interfaces
from beacon.scanners.privileges import (
  can_open_raw_socket,
  privileged_mode_available,
  scapy_available,
)
from beacon.services import alerts as alert_service
from beacon.services import catalog, identity, inventory, presence, profiles, review
from beacon.services import scans as scan_service
from beacon.services import settings as app_settings
from beacon.services.inventory import DeviceQuery
from beacon.services.serialize import event_dict
from beacon.storage import ConflictError, EventFilter, NotFoundError, Repository
from beacon.storage.database import backup_to
from beacon.web.jobs import JobRejected, ScanWorker
from beacon.web.security import Auth
from beacon.web.workspace import Workspace


T = TypeVar("T")


 # errors ->
class ApiError(Exception):
  def __init__(self, status: int, code: str, message: str, field: str | None = None, extra: dict[str, Any] | None = None) -> None:
    super().__init__(message)
    self.status, self.code, self.message, self.field, self.extra = status, code, message, field, extra or {}

  def response(self) -> JSONResponse:
    body: dict[str, Any] = {"code": self.code, "message": self.message}
    if self.field:
      body["field"] = self.field
    return JSONResponse({"error": {**body, **self.extra}}, status_code=self.status)


def error_response(exc: Exception) -> JSONResponse:
  """one error shape for the whole api: `{"error": {"code", "message", "field"?}}`."""
  if isinstance(exc, ApiError):
    return exc.response()
  if isinstance(exc, NotFoundError):
    return ApiError(404, "not_found", str(exc)).response()
  if isinstance(exc, ConflictError):
    return ApiError(409, "conflict", str(exc), extra={"current_version": exc.current}).response()
  if isinstance(exc, JobRejected):
    status = 429 if exc.code == "queue_full" else 409
    return ApiError(status, exc.code, str(exc), extra={"holder": exc.holder} if exc.holder else None).response()
  if isinstance(exc, ValueError):
    return ApiError(422, "invalid", str(exc), getattr(exc, "field", None)).response()
  raise exc


 # request helpers ->
def _bool(value: str | None, name: str) -> bool | None:
  if value is None or value == "":
    return None
  if value.lower() in ("1", "true", "yes"):
    return True
  if value.lower() in ("0", "false", "no"):
    return False
  raise ApiError(422, "invalid", f"{name} must be true or false", name)


def _int(value: str | None, name: str, default: int | None = None, low: int | None = None, high: int | None = None) -> int | None:
  if value is None or value == "":
    return default
  try:
    number = int(value)
  except ValueError as exc:
    raise ApiError(422, "invalid", f"{name} must be a whole number", name) from exc
  if (low is not None and number < low) or (high is not None and number > high):
    raise ApiError(422, "invalid", f"{name} must be between {low} and {high}", name)
  return number


def _time(value: str | None, name: str) -> datetime | None:
  if not value:
    return None
  try:
    moment = datetime.fromisoformat(value)
  except ValueError as exc:
    raise ApiError(422, "invalid", f"{name} must be an iso date", name) from exc
  if moment.tzinfo is None:
    raise ApiError(422, "invalid", f"{name} needs a timezone", name)
  return moment


def _enum(value: str | None, kind: type, name: str) -> Any:
  if value is None or value == "":
    return None
  try:
    return kind(value)
  except ValueError as exc:
    raise ApiError(422, "invalid", f"{name} must be one of: {', '.join(v.value for v in kind)}", name) from exc


async def _body(request: Request) -> dict[str, Any]:
  if not request.headers.get("content-type", "").startswith("application/json"):
    raise ApiError(415, "unsupported_media_type", "send a json body with content-type application/json")
  try:
    raw = await request.body()
  except ValueError as exc:
    raise ApiError(413, "too_large", "request body too large") from exc
  try:
    data = json.loads(raw or b"{}")
  except json.JSONDecodeError as exc:
    raise ApiError(400, "bad_json", f"invalid json: {exc.msg}") from exc
  if not isinstance(data, dict):
    raise ApiError(400, "bad_json", "the body must be a json object")
  return data


def _version(request: Request, body: dict[str, Any]) -> int | None:
  """optimistic concurrency: `If-Match: "<version>"` or a `version` field."""
  header = request.headers.get("if-match", "").strip().strip('"').removeprefix("W/").strip('"')
  if header:
    if not header.isdigit():
      raise ApiError(422, "invalid", "If-Match must carry the version number", "version")
    return int(header)
  version = body.get("version")
  if version is not None and (not isinstance(version, int) or isinstance(version, bool)):
    raise ApiError(422, "invalid", "version must be a number", "version")
  return version


 # api ->
class Api:
  def __init__(self, workspace: Workspace, worker: ScanWorker, auth: Auth, started_at: datetime, lan: bool = False) -> None:
    self.workspace = workspace
    self.worker = worker
    self.auth = auth
    self.started_at = started_at
    self.lan = lan
    self._capabilities: dict[str, Any] | None = None

  @property
  def repo(self) -> Repository:
    return self.workspace.repository

  async def db(self, func: Callable[..., T], *args: Any) -> T:
    return await run_in_threadpool(func, *args)

  @staticmethod
  def actor(request: Request) -> str:
    session = request.scope.get("state", {}).get("session") or "anonymous"
    return f"web:{session[:8]}"

  def routes(self) -> list[Route]:
    def route(path: str, endpoint: Callable, methods: list[str]) -> Route:
      async def guarded(request: Request) -> Response:
        try:
          return await endpoint(request)
        except Exception as exc:  # mapped to the api error shape; unknown errors propagate as 500
          return error_response(exc)

      return Route(path, guarded, methods=methods)

    return [
      route("/api/v1/health", self.health, ["GET"]),
      route("/api/v1/session", self.session, ["GET", "POST", "DELETE"]),
      route("/api/v1/status", self.status, ["GET"]),
      route("/api/v1/summary", self.summary, ["GET"]),
      route("/api/v1/devices", self.devices, ["GET"]),
      route("/api/v1/devices/bulk", self.devices_bulk, ["POST"]),
      route("/api/v1/devices/{key}", self.device, ["GET", "PATCH", "DELETE"]),
      route("/api/v1/devices/{key}/trust", self.device_trust, ["POST"]),
      route("/api/v1/devices/{key}/review", self.device_review, ["POST"]),
      route("/api/v1/devices/{key}/recheck", self.device_recheck, ["POST"]),
      route("/api/v1/devices/{key}/measurements", self.device_measurements, ["GET"]),
      route("/api/v1/devices/{key}/presence", self.device_presence, ["GET"]),
      route("/api/v1/review", self.review_queue, ["GET"]),
      route("/api/v1/events", self.events, ["GET"]),
      route("/api/v1/events/{event_id:int}/ack", self.event_ack, ["POST"]),
      route("/api/v1/identities", self.identities, ["GET"]),
      route("/api/v1/identities/link", self.identity_link, ["POST"]),
      route("/api/v1/identities/unlink", self.identity_unlink, ["POST"]),
      route("/api/v1/identities/reject", self.identity_reject, ["POST"]),
      route("/api/v1/presence", self.network_presence, ["GET"]),
      route("/api/v1/services", self.services, ["GET"]),
      route("/api/v1/networks", self.networks, ["GET"]),
      route("/api/v1/networks/{network_id:int}", self.network, ["PATCH"]),
      route("/api/v1/interfaces", self.interfaces, ["GET"]),
      route("/api/v1/scans", self.scans, ["GET"]),
      route("/api/v1/scans/compare", self.scans_compare, ["GET"]),
      route("/api/v1/scans/{scan_id:int}", self.scan, ["GET"]),
      route("/api/v1/jobs", self.jobs, ["GET", "POST"]),
      route("/api/v1/jobs/{job_id:int}", self.job, ["GET", "DELETE"]),
      route("/api/v1/monitor", self.monitor, ["GET", "POST"]),
      route("/api/v1/profiles", self.profiles, ["GET", "POST"]),
      route("/api/v1/profiles/{profile_id:int}", self.profile, ["GET", "PATCH", "DELETE"]),
      route("/api/v1/settings", self.settings, ["GET", "PATCH"]),
      route("/api/v1/diagnostics", self.diagnostics, ["GET"]),
      route("/api/v1/audit", self.audit, ["GET"]),
      route("/api/v1/maintenance/retention", self.retention, ["POST"]),
      route("/api/v1/maintenance/backup", self.backup, ["POST"]),
      route("/api/v1/alerts/policies", self.policies, ["GET", "POST"]),
      route("/api/v1/alerts/policies/{policy_id:int}", self.policy, ["PATCH", "DELETE"]),
      route("/api/v1/alerts/silences", self.silences, ["GET", "POST"]),
      route("/api/v1/alerts/silences/{silence_id:int}", self.silence, ["DELETE"]),
      route("/api/v1/alerts/channels", self.channels, ["GET", "POST"]),
      route("/api/v1/alerts/channels/{channel_id:int}", self.channel, ["PATCH", "DELETE"]),
      route("/api/v1/alerts/channels/{channel_id:int}/test", self.channel_test, ["POST"]),
      route("/api/v1/alerts/deliveries", self.deliveries, ["GET"]),
      route("/api/v1/reports/preview", self.report_preview, ["GET"]),
      route("/api/v1/reports/export", self.report_export, ["GET"]),
    ]

  # session ->
  async def health(self, _request: Request) -> Response:
    return JSONResponse({"ok": True, "version": __version__})

  async def session(self, request: Request) -> Response:
    session = request.scope.get("state", {}).get("session")
    if request.method == "GET":
      if session is None:
        raise ApiError(401, "unauthenticated", "open the link printed by `beacon live` to sign in")
      return JSONResponse({"authenticated": True, "csrf": self.auth.csrf_for(session), "version": __version__})
    if request.method == "DELETE":
      response = JSONResponse({"authenticated": False})
      response.headers["set-cookie"] = self.auth.cookie_header("", max_age=0)
      return response
    body = await _body(request)
    token = body.get("token")
    if not isinstance(token, str) or not self.auth.check_token(token):
      raise ApiError(401, "bad_token", "this sign-in link is not valid; run `beacon live --url` for a fresh one")
    cookie = self.auth.new_session()
    session_id = self.auth.session_id(cookie)
    assert session_id is not None
    response = JSONResponse({"authenticated": True, "csrf": self.auth.csrf_for(session_id), "version": __version__})
    response.headers["set-cookie"] = self.auth.cookie_header(cookie)
    return response

  # status ->
  def capabilities(self) -> dict[str, Any]:
    if self._capabilities is None:
      from beacon.scanners.icmp import IcmpPinger

      pinger = IcmpPinger.open(1)
      icmp = pinger is not None
      if pinger is not None:
        pinger.close()
      self._capabilities = {
        "platform": f"{platform.system()} {platform.release()}".strip().lower(),
        "python": sys.version.split()[0],
        "raw_sockets": can_open_raw_socket(),
        "scapy": scapy_available(),
        "privileged_mode": privileged_mode_available(),
        "unprivileged_icmp": icmp,
        "ipv6_neighbours": bool(shutil.which("ip") or shutil.which("ndp")),
        "desktop_notifications": bool(shutil.which("notify-send") or shutil.which("osascript")),
        "vendors": len(self.workspace.vendors),
      }
    return self._capabilities

  def status_snapshot(self) -> dict[str, Any]:
    repo = self.repo
    worker = self.worker.status()
    monitor = worker["monitor"]
    networks = repo.list_networks()
    last_valid = repo.last_valid_scan()
    last_any = (repo.list_scans(limit=1) or [None])[0]
    leases = [lease for lease in repo.list_leases() if lease["active"]]
    external = [lease for lease in leases if not lease["kind"].startswith("live-") or lease["pid"] != os.getpid()]
    now = utcnow()
    interval = monitor["interval"] if monitor["enabled"] else (app_settings.load(repo)["monitor_interval"])
    valid_at = datetime.fromisoformat(last_valid["finished_at"]) if last_valid and last_valid["finished_at"] else None
    if worker["running"]:
      state, message = "scanning", f"scanning · {worker['running']['stage'] or 'starting'}"
    elif monitor["state"] == "blocked":
      state, message = "blocked", monitor["last_error"] or "the monitor cannot scan"
    elif last_any and last_any["status"] == "failed" and (monitor["enabled"] or external):
      state, message = "failing", (last_any["issues"][-1]["message"] if last_any["issues"] else "the last scan failed")
    elif valid_at is None:
      state, message = "empty", "no scan yet"
    elif (monitor["enabled"] or external) and now - valid_at > timedelta(seconds=3 * interval + 120):
      state, message = "stale", "no valid result for a while"
    elif monitor["enabled"] or external:
      state, message = "ok", "monitoring"
    else:
      state, message = "idle", "monitor stopped"
    _oldest, cursor = repo.change_bounds()
    return {
      "version": __version__,
      "rules_version": RULES_VERSION,
      "server": {"started_at": self.started_at.isoformat(), "pid": os.getpid(), "lan": self.lan},
      "health": {
        "state": state,
        "message": message,
        "last_valid_at": valid_at.isoformat() if valid_at else None,
        "last_scan": last_any,
      },
      "monitor": monitor,
      "running": worker["running"],
      "queued": worker["queued"],
      "external": external,
      "networks": networks,
      "cursor": cursor,
      "pending_review": repo.count_pending_devices(),
      "onboarded": app_settings.load(repo)["onboarded"],
    }

  async def status(self, _request: Request) -> Response:
    data = await self.db(self.status_snapshot)
    data["capabilities"] = await self.db(self.capabilities)
    return JSONResponse(data)

  def _summary(self, network_id: int | None) -> dict[str, Any]:
    repo = self.repo
    page = inventory.query_devices(repo, DeviceQuery(network_id=network_id, size=1))
    top_cases, pending = review.review_page(repo, network_id, page=1, size=5, per_case=1)
    recent = repo.query_events(EventFilter(network_id=network_id, min_severity=Severity.WARNING), limit=8)
    last = repo.last_valid_scan(network_id)
    watched = presence.watched_share(repo, network_id, hours=24)
    facets = page.facets
    total = page.total
    next_action: dict[str, Any]
    if last is None:
      next_action = {"code": "first_scan", "text": "run a first discovery of your network"}
    elif pending:
      next_action = {"code": "review", "text": f"review {pending} devices waiting for a decision", "count": pending}
    elif total and facets["incomplete"] == total:
      next_action = {"code": "add_ports", "text": "no device has port data yet: scan with a port profile to judge exposure"}
    elif not self.worker.monitor.enabled:
      next_action = {"code": "start_monitor", "text": "start the monitor to keep the inventory current"}
    else:
      next_action = {"code": "none", "text": "nothing needs your attention"}
    return {
      "devices": {
        "total": total,
        "online": facets["online"],
        "offline": facets["offline"],
        "untrusted": facets["untrusted"],
        "with_open_ports": facets["open_ports"],
        "risk": facets["risk"],
        "risk_incomplete": facets["incomplete"],
      },
      "pending_review": pending,
      "top_cases": [c.to_dict() for c in top_cases],
      "recent_events": [event_dict(e) for e in recent],
      "observation": {
        "last_valid_scan": last,
        "watched_share_24h": watched,
        "ports_examined_devices": total - facets["incomplete"],
      },
      "next_action": next_action,
    }

  async def summary(self, request: Request) -> Response:
    network_id = _int(request.query_params.get("network"), "network")
    return JSONResponse(await self.db(self._summary, network_id))

  # devices ->
  def _query(self, request: Request) -> DeviceQuery:
    params = request.query_params
    return DeviceQuery(
      network_id=_int(params.get("network"), "network"),
      q=params.get("q") or None,
      status=_enum(params.get("status"), DeviceStatus, "status"),
      trusted=_bool(params.get("trusted"), "trusted"),
      tag=params.get("tag") or None,
      category=params.get("category") or None,
      essential=_bool(params.get("essential"), "essential"),
      has_open_ports=_bool(params.get("has_ports"), "has_ports"),
      port=_int(params.get("port"), "port", low=1, high=65535),
      min_risk=_enum(params.get("risk"), RiskLevel, "risk"),
      incomplete=_bool(params.get("incomplete"), "incomplete"),
      sort=params.get("sort") or "ip",
      descending=params.get("order") == "desc",
      page=_int(params.get("page"), "page", 1, 1) or 1,
      size=_int(params.get("size"), "size", 50, 1, inventory.MAX_PAGE_SIZE) or 50,
    )

  async def devices(self, request: Request) -> Response:
    query = self._query(request)
    if _bool(request.query_params.get("keys_only"), "keys_only"):
      return JSONResponse(await self.db(lambda: inventory.matching_keys(self.repo, query)))
    page = await self.db(lambda: inventory.query_devices(self.repo, query))
    return JSONResponse(page.to_dict())

  async def device(self, request: Request) -> Response:
    key = request.path_params["key"]
    if request.method == "GET":
      detail = await self.db(lambda: inventory.get_detail(self.repo, key))
      return JSONResponse(detail, headers={"etag": f'"{detail["version"]}"'})
    if request.method == "DELETE":
      if not await self.db(lambda: self.repo.delete_device(key, self.actor(request))):
        raise NotFoundError(f"device {key} not found")
      return JSONResponse({"deleted": key})
    body = await _body(request)
    version = _version(request, body)
    changes = {k: v for k, v in body.items() if k != "version"}
    updated = await self.db(lambda: inventory.edit_device(self.repo, key, changes, version, self.actor(request)))
    return JSONResponse(updated, headers={"etag": f'"{updated["version"]}"'})

  async def device_trust(self, request: Request) -> Response:
    body = await _body(request)
    trusted = body.get("trusted")
    if not isinstance(trusted, bool):
      raise ApiError(422, "invalid", "trusted must be true or false", "trusted")
    key = request.path_params["key"]
    result = await self.db(lambda: inventory.set_trust(self.repo, key, trusted, self.actor(request), _version(request, body)))
    return JSONResponse(result)

  async def device_review(self, request: Request) -> Response:
    """review decisions that are not trust: acknowledge the events, snooze, wake up."""
    body = await _body(request)
    action = body.get("action")
    key = request.path_params["key"]
    actor = self.actor(request)

    def apply() -> dict[str, Any]:
      repo = self.repo
      if repo.get_device(key) is None:
        raise NotFoundError(f"device {key} not found")
      if action == "ack":
        return {"acknowledged": repo.ack_events(key, actor)}
      if action == "snooze":
        inventory.snooze(repo, key, body.get("until"), actor)
        return {"snoozed": True}
      if action == "unsnooze":
        inventory.snooze(repo, key, None, actor)
        return {"snoozed": False}
      raise ApiError(422, "invalid", "action must be ack, snooze or unsnooze", "action")

    return JSONResponse(await self.db(apply))

  async def device_recheck(self, request: Request) -> Response:
    key = request.path_params["key"]
    device = await self.db(lambda: self.repo.get_device(key))
    if device is None:
      raise NotFoundError(f"device {key} not found")
    body = await _body(request) if request.headers.get("content-type", "").startswith("application/json") else {}
    profile_id = body.get("profile_id")
    if profile_id is not None and not isinstance(profile_id, int):
      raise ApiError(422, "invalid", "profile_id must be a number", "profile_id")
    profiles.check_scope(f"{device.ip}/32")
    job = await self.db(lambda: self.worker.submit("recheck", "web", profile_id, f"{device.ip}/32", device.network_id))
    return JSONResponse(job.to_dict(), status_code=202)

  async def device_measurements(self, request: Request) -> Response:
    key = request.path_params["key"]
    params = request.query_params
    since = _time(params.get("since"), "since") or utcnow() - timedelta(days=7)
    bucket_minutes = _int(params.get("bucket"), "bucket", None, 1, 1440)
    bucket = timedelta(minutes=bucket_minutes) if bucket_minutes else None

    def load() -> dict[str, Any]:
      if self.repo.get_device(key) is None:
        raise NotFoundError(f"device {key} not found")
      series = self.repo.measurement_series(key, since, bucket=bucket)
      return {"since": since.isoformat(), "bucket_minutes": bucket_minutes, "points": series}

    return JSONResponse(await self.db(load))

  async def device_presence(self, request: Request) -> Response:
    key = request.path_params["key"]
    weeks = _int(request.query_params.get("weeks"), "weeks", 4, 1, 12) or 4
    return JSONResponse(await self.db(lambda: presence.device_presence(self.repo, key, weeks)))

  async def devices_bulk(self, request: Request) -> Response:
    body = await _body(request)
    keys = body.get("keys")
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
      raise ApiError(422, "invalid", "keys must be a list of device keys", "keys")
    action = body.get("action")
    results = await self.db(lambda: inventory.bulk_action(self.repo, keys, str(action), self.actor(request), body))
    return JSONResponse({"results": results, "ok": sum(r["ok"] for r in results), "failed": sum(not r["ok"] for r in results)})

  # review and events ->
  async def review_queue(self, request: Request) -> Response:
    params = request.query_params
    network_id = _int(params.get("network"), "network")
    include = _bool(params.get("snoozed"), "snoozed") or False
    page = _int(params.get("page"), "page", 1, 1) or 1
    size = _int(params.get("size"), "size", 20, 1, 200) or 20
    cases, total = await self.db(lambda: review.review_page(self.repo, network_id, include, page, size))
    return JSONResponse({"items": [c.to_dict() for c in cases], "total": total, "page": page, "size": size})

  async def events(self, request: Request) -> Response:
    params = request.query_params
    types = [_enum(t, EventType, "type") for t in params.getlist("type") if t]
    severities = [_enum(s, Severity, "severity") for s in params.getlist("severity") if s]
    flt = EventFilter(
      network_id=_int(params.get("network"), "network"),
      device_key=params.get("device") or None,
      types=types or None,
      severities=severities or None,
      acked=_bool(params.get("acked"), "acked"),
      pending_only=bool(_bool(params.get("pending"), "pending")),
      since=_time(params.get("since"), "since"),
      until=_time(params.get("until"), "until"),
      q=params.get("q") or None,
      before_id=_int(params.get("before"), "before", None, 1),
    )
    size = _int(params.get("size"), "size", 50, 1, 500) or 50

    def load() -> dict[str, Any]:
      items = self.repo.query_events(flt, limit=size)
      total = self.repo.count_events(replace(flt, before_id=None))
      return {
        "items": [event_dict(e) for e in items],
        "next_before": items[-1].id if len(items) == size else None,
        "total": total,
      }

    return JSONResponse(await self.db(load))

  async def event_ack(self, request: Request) -> Response:
    event_id = request.path_params["event_id"]

    def ack() -> dict[str, Any]:
      if self.repo.get_event(event_id) is None:
        raise NotFoundError(f"event {event_id} not found")
      return {"acknowledged": self.repo.ack_event(event_id, self.actor(request))}

    return JSONResponse(await self.db(ack))

  # identities ->
  async def identities(self, request: Request) -> Response:
    network_id = _int(request.query_params.get("network"), "network")
    return JSONResponse(await self.db(lambda: identity.overview(self.repo, network_id)))

  async def identity_link(self, request: Request) -> Response:
    body = await _body(request)
    new, old, trust = body.get("new"), body.get("old"), body.get("trust", False)
    if not isinstance(new, str) or not isinstance(old, str) or not isinstance(trust, bool):
      raise ApiError(422, "invalid", "send new and old device keys, and trust as true or false")
    return JSONResponse(await self.db(lambda: identity.link(self.repo, new, old, self.actor(request), trust)))

  async def identity_unlink(self, request: Request) -> Response:
    body = await _body(request)
    key = body.get("key")
    if not isinstance(key, str):
      raise ApiError(422, "invalid", "key is required", "key")
    if not await self.db(lambda: self.repo.unlink_device(key, self.actor(request))):
      raise ApiError(409, "not_linked", f"{key} is not linked to any identity")
    return JSONResponse({"unlinked": key})

  async def identity_reject(self, request: Request) -> Response:
    body = await _body(request)
    new, candidate = body.get("new"), body.get("candidate")
    if not isinstance(new, str) or not isinstance(candidate, str):
      raise ApiError(422, "invalid", "send the new and candidate device keys")
    await self.db(lambda: self.repo.reject_candidate(new, candidate, self.actor(request)))
    return JSONResponse({"rejected": [new, candidate]})

  # analysis ->
  async def network_presence(self, request: Request) -> Response:
    network_id = _int(request.query_params.get("network"), "network")
    hours = _int(request.query_params.get("hours"), "hours", 24, 1, 24 * 14) or 24
    return JSONResponse(await self.db(lambda: presence.network_presence(self.repo, network_id, hours)))

  async def services(self, request: Request) -> Response:
    network_id = _int(request.query_params.get("network"), "network")
    q = request.query_params.get("q")
    return JSONResponse(await self.db(lambda: catalog.services_overview(self.repo, network_id, q)))

  async def networks(self, _request: Request) -> Response:
    return JSONResponse({"items": await self.db(lambda: self.repo.list_networks())})

  async def network(self, request: Request) -> Response:
    body = await _body(request)
    name = body.get("name")
    if name is not None and (not isinstance(name, str) or len(name) > 64):
      raise ApiError(422, "invalid", "name is text of at most 64 characters", "name")
    network_id = request.path_params["network_id"]
    await self.db(lambda: self.repo.rename_network(network_id, name, self.actor(request)))
    return JSONResponse(await self.db(lambda: self.repo.get_network(network_id)))

  async def interfaces(self, _request: Request) -> Response:
    def load() -> list[dict[str, Any]]:
      return [
        {"name": i.name, "ip": str(i.ip), "network": str(i.network), "mac": i.mac, "gateway": str(i.gateway) if i.gateway else None}
        for i in list_interfaces()
      ]

    return JSONResponse({"items": await self.db(load)})

  # scans and jobs ->
  async def scans(self, request: Request) -> Response:
    params = request.query_params
    network_id = _int(params.get("network"), "network")
    status = params.get("status") or None
    size = _int(params.get("size"), "size", 25, 1, 200) or 25
    page = _int(params.get("page"), "page", 1, 1) or 1

    def load() -> dict[str, Any]:
      return {
        "items": self.repo.list_scans(size, (page - 1) * size, network_id, status),
        "total": self.repo.count_scans(network_id, status),
        "page": page,
        "size": size,
      }

    return JSONResponse(await self.db(load))

  async def scan(self, request: Request) -> Response:
    scan_id = request.path_params["scan_id"]
    return JSONResponse(await self.db(lambda: scan_service.scan_detail(self.repo, scan_id)))

  async def scans_compare(self, request: Request) -> Response:
    before = _int(request.query_params.get("before"), "before", None, 1)
    after = _int(request.query_params.get("after"), "after", None, 1)
    if before is None or after is None:
      raise ApiError(422, "invalid", "before and after scan ids are required")
    return JSONResponse(await self.db(lambda: scan_service.compare(self.repo, before, after)))

  async def jobs(self, request: Request) -> Response:
    if request.method == "GET":
      return JSONResponse({"items": self.worker.jobs()})
    body = await _body(request)
    profile_id = body.get("profile_id")
    if profile_id is not None and (not isinstance(profile_id, int) or isinstance(profile_id, bool)):
      raise ApiError(422, "invalid", "profile_id must be a number", "profile_id")
    if profile_id is not None and await self.db(lambda: self.repo.get_profile(profile_id)) is None:
      raise NotFoundError(f"profile {profile_id} not found")
    job = await self.db(lambda: self.worker.submit("scan", "web", profile_id))
    return JSONResponse(job.to_dict(), status_code=202)

  async def job(self, request: Request) -> Response:
    job_id = request.path_params["job_id"]
    if request.method == "DELETE":
      if not self.worker.cancel(job_id):
        raise ApiError(409, "not_active", "the job is not queued or running")
      return JSONResponse({"cancelled": job_id}, status_code=202)
    job = self.worker.job(job_id)
    if job is None:
      raise NotFoundError(f"job {job_id} not found")
    return JSONResponse(job)

  async def monitor(self, request: Request) -> Response:
    if request.method == "GET":
      return JSONResponse(self.worker.monitor.to_dict())
    body = await _body(request)
    action = body.get("action")
    if action == "stop":
      return JSONResponse(await self.db(self.worker.stop_monitor))
    if action != "start":
      raise ApiError(422, "invalid", "action must be start or stop", "action")
    profile_id = body.get("profile_id")
    interval = body.get("interval")
    if interval is None:
      interval = await self.db(lambda: app_settings.load(self.repo)["monitor_interval"])
    if not isinstance(interval, int) or isinstance(interval, bool):
      raise ApiError(422, "invalid", "interval must be a number of seconds", "interval")
    if profile_id is not None and await self.db(lambda: self.repo.get_profile(profile_id)) is None:
      raise NotFoundError(f"profile {profile_id} not found")
    return JSONResponse(await self.db(lambda: self.worker.start_monitor(profile_id, interval)))

  # profiles and settings ->
  async def profiles(self, request: Request) -> Response:
    if request.method == "GET":
      return JSONResponse({"items": await self.db(lambda: self.repo.list_profiles())})
    body = await _body(request)
    created = await self.db(lambda: profiles.create(self.repo, body, self.actor(request)))
    return JSONResponse(created, status_code=201)

  async def profile(self, request: Request) -> Response:
    profile_id = request.path_params["profile_id"]
    if request.method == "GET":
      found = await self.db(lambda: self.repo.get_profile(profile_id))
      if found is None:
        raise NotFoundError(f"profile {profile_id} not found")
      return JSONResponse(found)
    if request.method == "DELETE":
      if not await self.db(lambda: self.repo.delete_profile(profile_id, self.actor(request))):
        raise NotFoundError(f"profile {profile_id} not found")
      return JSONResponse({"deleted": profile_id})
    body = await _body(request)
    version = _version(request, body)
    changes = {k: v for k, v in body.items() if k != "version"}
    return JSONResponse(await self.db(lambda: profiles.update(self.repo, profile_id, changes, version, self.actor(request))))

  async def settings(self, request: Request) -> Response:
    if request.method == "GET":
      return JSONResponse(await self.db(lambda: app_settings.load(self.repo)))
    body = await _body(request)
    return JSONResponse(await self.db(lambda: app_settings.update(self.repo, body, self.actor(request))))

  # administration ->
  async def diagnostics(self, _request: Request) -> Response:
    def load() -> dict[str, Any]:
      repo = self.repo
      settings = self.workspace.settings
      db_size = settings.db_path.stat().st_size if settings.db_path.exists() else 0
      return {
        "version": __version__,
        "paths": {"data": str(settings.data_dir), "database": str(settings.db_path), "vendors": str(settings.oui_path)},
        "database": {"bytes": db_size, "tables": repo.table_sizes(), "schema": repo.conn.execute("PRAGMA user_version").fetchone()[0]},
        "leases": repo.list_leases(),
        "recent_failures": repo.list_scans(10, 0, None, "failed"),
        "timezone": app_settings.timezone_name(repo),
        "retention_preview": repo.retention_preview(app_settings.retention(repo)),
      }

    data = await self.db(load)
    data["capabilities"] = await self.db(self.capabilities)
    return JSONResponse(data)

  async def audit(self, request: Request) -> Response:
    params = request.query_params
    size = _int(params.get("size"), "size", 50, 1, 500) or 50
    page = _int(params.get("page"), "page", 1, 1) or 1
    items = await self.db(lambda: self.repo.list_audit(params.get("entity"), params.get("id"), size, (page - 1) * size))
    return JSONResponse({"items": items, "page": page, "size": size})

  async def retention(self, request: Request) -> Response:
    body = await _body(request)
    preview = body.get("preview", True)
    if not isinstance(preview, bool):
      raise ApiError(422, "invalid", "preview must be true or false", "preview")

    def run() -> dict[str, Any]:
      policy = app_settings.retention(self.repo)
      if preview:
        return {"preview": True, "would_delete": self.repo.retention_preview(policy), "policy": policy.to_dict()}
      return {"preview": False, "deleted": self.repo.apply_retention(policy, self.actor(request)), "policy": policy.to_dict()}

    return JSONResponse(await self.db(run))

  async def backup(self, request: Request) -> Response:
    def run() -> dict[str, Any]:
      settings = self.workspace.settings
      target = settings.data_dir / "backups" / f"beacon-{utcnow():%Y%m%dT%H%M%SZ}.db"
      backup_to(self.repo.conn, target)
      self.repo.record_audit(self.actor(request), "backup", "database", None, path=str(target))
      return {"path": str(target), "bytes": target.stat().st_size}

    return JSONResponse(await self.db(run), status_code=201)

  # alerts ->
  async def policies(self, request: Request) -> Response:
    if request.method == "GET":
      return JSONResponse({"items": await self.db(lambda: self.repo.list_policies()), "event_types": alert_service.EVENT_TYPES})
    body = await _body(request)
    values = {"window_seconds": 0, "threshold": 1, "cooldown_seconds": 900, **body}
    clean = alert_service.validate_policy(values)
    return JSONResponse(await self.db(lambda: self.repo.create_policy(clean, self.actor(request))), status_code=201)

  async def policy(self, request: Request) -> Response:
    policy_id = request.path_params["policy_id"]
    if request.method == "DELETE":
      if not await self.db(lambda: self.repo.delete_policy(policy_id, self.actor(request))):
        raise NotFoundError(f"policy {policy_id} not found")
      return JSONResponse({"deleted": policy_id})
    body = await _body(request)
    version = _version(request, body)
    clean = alert_service.validate_policy({k: v for k, v in body.items() if k != "version"}, partial=True)
    return JSONResponse(await self.db(lambda: self.repo.update_policy(policy_id, clean, version, self.actor(request))))

  async def silences(self, request: Request) -> Response:
    if request.method == "GET":
      expired = _bool(request.query_params.get("expired"), "expired") or False
      return JSONResponse({"items": await self.db(lambda: self.repo.list_silences(include_expired=expired))})
    clean = alert_service.validate_silence(await _body(request))
    return JSONResponse(await self.db(lambda: self.repo.create_silence(clean, self.actor(request))), status_code=201)

  async def silence(self, request: Request) -> Response:
    silence_id = request.path_params["silence_id"]
    if not await self.db(lambda: self.repo.delete_silence(silence_id, self.actor(request))):
      raise NotFoundError(f"silence {silence_id} not found")
    return JSONResponse({"deleted": silence_id})

  async def channels(self, request: Request) -> Response:
    if request.method == "GET":
      return JSONResponse({"items": await self.db(lambda: self.repo.list_channels())})
    body = await _body(request)
    kind, name, secret = body.get("kind"), str(body.get("name") or "").strip(), body.get("secret")
    config = alert_service.validate_channel(str(kind), body.get("config") or {})
    if not 1 <= len(name) <= 64:
      raise ApiError(422, "invalid", "name is required (at most 64 characters)", "name")
    if secret is not None and (not isinstance(secret, str) or not 16 <= len(secret) <= 256):
      raise ApiError(422, "invalid", "a signing secret has 16 to 256 characters", "secret")
    created = await self.db(lambda: self.repo.create_channel(str(kind), name, config, secret, self.actor(request)))
    return JSONResponse(created, status_code=201)

  async def channel(self, request: Request) -> Response:
    channel_id = request.path_params["channel_id"]
    if request.method == "DELETE":
      if not await self.db(lambda: self.repo.delete_channel(channel_id, self.actor(request))):
        raise NotFoundError(f"channel {channel_id} not found")
      return JSONResponse({"deleted": channel_id})
    body = await _body(request)
    current = await self.db(lambda: self.repo.get_channel(channel_id))
    if current is None:
      raise NotFoundError(f"channel {channel_id} not found")
    values: dict[str, Any] = {}
    if "name" in body:
      values["name"] = str(body["name"]).strip()[:64]
    if "config" in body:
      values["config"] = alert_service.validate_channel(current["kind"], body["config"])
    if "enabled" in body:
      if not isinstance(body["enabled"], bool):
        raise ApiError(422, "invalid", "enabled must be true or false", "enabled")
      values["enabled"] = body["enabled"]
    if "secret" in body:
      values["secret"] = body["secret"] or None
    return JSONResponse(await self.db(lambda: self.repo.update_channel(channel_id, values, self.actor(request))))

  async def channel_test(self, request: Request) -> Response:
    channel_id = request.path_params["channel_id"]
    if await self.db(lambda: self.repo.get_channel(channel_id)) is None:
      raise NotFoundError(f"channel {channel_id} not found")
    return JSONResponse(await self.db(lambda: alert_service.test_channel(self.repo, channel_id, self.actor(request))))

  async def deliveries(self, request: Request) -> Response:
    size = _int(request.query_params.get("size"), "size", 50, 1, 500) or 50
    return JSONResponse({"items": await self.db(lambda: self.repo.list_deliveries(size))})

  # reports ->
  def _report_options(self, request: Request) -> dict[str, Any]:
    from beacon.export import FORMATS, REPORT_FIELDS

    params = request.query_params
    fmt = params.get("format") or "html"
    if fmt not in FORMATS:
      raise ApiError(422, "invalid", f"format must be one of: {', '.join(FORMATS)}", "format")
    fields = [f for f in (params.get("fields") or "").split(",") if f]
    unknown = [f for f in fields if f not in REPORT_FIELDS]
    if unknown:
      raise ApiError(422, "invalid", f"unknown fields: {', '.join(unknown)}", "fields")
    return {
      "format": fmt,
      "network_id": _int(params.get("network"), "network"),
      "online": bool(_bool(params.get("online"), "online")),
      "events": _int(params.get("events"), "events", 50, 0, 1000),
      "fields": fields or None,
      "include_presence": bool(_bool(params.get("include_presence"), "include_presence")),
      "include_fingerprint": bool(_bool(params.get("include_fingerprint"), "include_fingerprint")),
      "anonymize": bool(_bool(params.get("anonymize"), "anonymize")),
      "since": _time(params.get("since"), "since"),
    }

  async def report_preview(self, request: Request) -> Response:
    from beacon.services.reports import preview

    options = self._report_options(request)
    return JSONResponse(await self.db(lambda: preview(self.repo, options)))

  async def report_export(self, request: Request) -> Response:
    from beacon.services.reports import build

    options = self._report_options(request)
    content, media, filename = await self.db(lambda: build(self.repo, options))
    return Response(content, media_type=media, headers={"content-disposition": f'attachment; filename="{filename}"'})
