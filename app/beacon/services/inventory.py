 # import libraries ->
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.risk import RiskAssessment, RiskLevel
from beacon.services import cache
from beacon.services.risk import assess_devices
from beacon.services.serialize import device_detail, device_summary, event_dict
from beacon.storage import ConflictError, DeviceFilter, NotFoundError, Repository
from beacon.storage.devices import _ip_order
from beacon.storage.events import EventFilter


 # constants ->
SORTS = ("ip", "name", "risk", "last_seen", "first_seen", "vendor", "latency", "status")
MAX_PAGE_SIZE = 500
BULK_ACTIONS = ("trust", "untrust", "ack", "snooze", "unsnooze", "tag", "untag", "essential", "not-essential")
MAX_BULK = 1000


class ValidationError(ValueError):
  """a request that can never succeed as sent; the message says which field and why."""

  def __init__(self, message: str, field_name: str | None = None) -> None:
    super().__init__(message)
    self.field = field_name


 # queries ->
@dataclass(slots=True)
class DeviceQuery:
  network_id: int | None = None
  q: str | None = None
  status: DeviceStatus | None = None
  trusted: bool | None = None
  tag: str | None = None
  category: str | None = None
  essential: bool | None = None
  has_open_ports: bool | None = None
  port: int | None = None
  min_risk: RiskLevel | None = None
  incomplete: bool | None = None
  sort: str = "ip"
  descending: bool = False
  page: int = 1
  size: int = 50
  keys: list[str] | None = None

  def validate(self) -> None:
    if self.sort not in SORTS:
      raise ValidationError(f"sort must be one of: {', '.join(SORTS)}", "sort")
    if self.page < 1:
      raise ValidationError("page starts at 1", "page")
    if not 1 <= self.size <= MAX_PAGE_SIZE:
      raise ValidationError(f"size must be between 1 and {MAX_PAGE_SIZE}", "size")
    if self.port is not None and not 1 <= self.port <= 65535:
      raise ValidationError("port must be between 1 and 65535", "port")
    if self.q is not None and len(self.q) > 200:
      raise ValidationError("search text is at most 200 characters", "q")


@dataclass(slots=True)
class Page:
  items: list[dict[str, Any]]
  total: int
  page: int
  size: int
  facets: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    return {
      "items": self.items,
      "total": self.total,
      "page": self.page,
      "size": self.size,
      "pages": max(1, -(-self.total // self.size)),
      "facets": self.facets,
    }


def _sort_key(sort: str, risks: dict[str, RiskAssessment]):
  def latency(d: Device) -> float:
    return d.latency.avg if d.latency and d.latency.avg is not None else float("inf")

  keys = {
    "ip": lambda d: _ip_order(d.ip),
    "name": lambda d: (d.display_name.lower(), _ip_order(d.ip)),
    "risk": lambda d: (risks[d.key].score, _ip_order(d.ip)),
    "last_seen": lambda d: (d.last_seen or datetime.min.replace(tzinfo=utcnow().tzinfo), _ip_order(d.ip)),
    "first_seen": lambda d: (d.first_seen or datetime.min.replace(tzinfo=utcnow().tzinfo), _ip_order(d.ip)),
    "vendor": lambda d: ((d.vendor or "~").lower(), _ip_order(d.ip)),
    "latency": lambda d: (latency(d), _ip_order(d.ip)),
    "status": lambda d: (d.status != DeviceStatus.ONLINE, d.trusted, _ip_order(d.ip)),
  }
  return keys[sort]


def _match(repo: Repository, query: DeviceQuery, now: datetime | None) -> tuple[list[Device], dict[str, RiskAssessment]]:
  """filter in sql, assess risk once, then apply the risk filters and the order.

  the result is reused until anything changes (or the minute turns, since risk windows move), so
  paging, sorting again and live refreshes of an unchanged inventory cost nothing. callers treat
  the returned devices as read-only.
  """
  query.validate()
  if now is not None:
    devices, risks = _compute(repo, query, now)
  else:
    key = (*(getattr(query, f) if f != "keys" else (tuple(query.keys) if query.keys is not None else None)
             for f in DeviceQuery.__slots__ if f not in ("page", "size", "sort", "descending")),
           utcnow().replace(second=0, microsecond=0))
    devices, risks = cache.matches.get(repo, ("devices", key), lambda: _compute(repo, query, None))
  # Sorting a copy keeps the cached match immutable across concurrent requests and sort orders.
  return sorted(devices, key=_sort_key(query.sort, risks), reverse=query.descending), risks


def _compute(repo: Repository, query: DeviceQuery, now: datetime | None) -> tuple[list[Device], dict[str, RiskAssessment]]:
  devices = repo.filter_devices(
    DeviceFilter(
      network_id=query.network_id,
      status=query.status,
      trusted=query.trusted,
      q=query.q,
      tag=query.tag,
      category=query.category,
      essential=query.essential,
      has_open_ports=query.has_open_ports,
      port=query.port,
      keys=query.keys,
    )
  )
  risks = assess_devices(repo, devices, now)
  if query.min_risk is not None:
    devices = [d for d in devices if risks[d.key].level.rank >= query.min_risk.rank]
  if query.incomplete is not None:
    devices = [d for d in devices if (not risks[d.key].complete) == query.incomplete]
  return devices, risks


def query_devices(repo: Repository, query: DeviceQuery, now: datetime | None = None) -> Page:
  """one page of devices; facets count the whole match, not the page."""
  devices, risks = _match(repo, query, now)
  snoozed = repo.snoozed(now)
  start = (query.page - 1) * query.size
  items = [device_summary(d, risks[d.key], snoozed.get(d.key)) for d in devices[start : start + query.size]]
  facets = {
    "online": sum(d.status == DeviceStatus.ONLINE for d in devices),
    "offline": sum(d.status != DeviceStatus.ONLINE for d in devices),
    "untrusted": sum(not d.trusted for d in devices),
    "open_ports": sum(bool(d.open_ports) for d in devices),
    "risk": {str(level): sum(risks[d.key].level == level for d in devices) for level in RiskLevel},
    "incomplete": sum(not risks[d.key].complete for d in devices),
  }
  return Page(items, len(devices), query.page, query.size, facets)


def matching_keys(repo: Repository, query: DeviceQuery, now: datetime | None = None) -> dict[str, Any]:
  """every key a filter matches (for "select all"), capped at the bulk limit and saying so."""
  devices, _ = _match(repo, query, now)
  return {"keys": [d.key for d in devices[:MAX_BULK]], "total": len(devices), "truncated": len(devices) > MAX_BULK}


def get_detail(repo: Repository, key: str, now: datetime | None = None) -> dict[str, Any]:
  device = repo.get_device(key)
  if device is None:
    raise NotFoundError(f"device {key} not found")
  risk = assess_devices(repo, [device], now)[key]
  coverage = repo.port_coverage([key]).get(key)
  members = repo.identity_members(device)
  events = repo.query_events(EventFilter(device_key=key), limit=20)
  pending = repo.count_events(EventFilter(device_key=key, pending_only=True))
  network = repo.get_network(device.network_id)
  return {
    **device_detail(device, risk, repo.snoozed(now).get(key)),
    "network": network,
    "coverage": {
      "examined": (str(coverage[0]) if coverage[0] is not None else None) if coverage else None,
      "examined_count": len(coverage[0]) if coverage and coverage[0] is not None else None,
      "legacy": bool(coverage and coverage[0] is None),
      "checked_at": coverage[1].isoformat() if coverage else None,
      "history": repo.coverage_history(key, limit=10),
    },
    "identity": {
      "id": device.identity_id,
      "members": [device_summary(m) for m in members],
    },
    "events": [event_dict(e) for e in events],
    "pending_events": pending,
    "audit": repo.list_audit("device", key, limit=20),
  }


 # edits ->
def edit_device(
  repo: Repository, key: str, changes: dict[str, Any], expected_version: int | None, actor: str
) -> dict[str, Any]:
  try:
    device = repo.update_device(key, changes, expected_version, actor)
  except ValueError as exc:
    if isinstance(exc, (ConflictError, NotFoundError)):
      raise
    raise ValidationError(str(exc)) from exc
  return device_summary(device, assess_devices(repo, [device])[key])


def set_trust(repo: Repository, key: str, trusted: bool, actor: str, expected_version: int | None = None) -> dict[str, Any]:
  device = repo.get_device(key)
  if device is None:
    raise NotFoundError(f"device {key} not found")
  if expected_version is not None and device.version != expected_version:
    raise ConflictError("device", key, device.version)
  repo.set_trusted(key, trusted, actor, expected_version=expected_version)
  device = repo.get_device(key)
  assert device is not None
  return device_summary(device, assess_devices(repo, [device])[key])


def bulk_action(
  repo: Repository, keys: list[str], action: str, actor: str, params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
  """apply one action to exactly the listed devices and report each outcome separately."""
  params = params or {}
  if action not in BULK_ACTIONS:
    raise ValidationError(f"action must be one of: {', '.join(BULK_ACTIONS)}", "action")
  unique = list(dict.fromkeys(keys))
  if not unique:
    raise ValidationError("select at least one device", "keys")
  if len(unique) > MAX_BULK:
    raise ValidationError(f"at most {MAX_BULK} devices per request", "keys")
  tag = str(params.get("tag") or "").strip().lower()
  if action in ("tag", "untag") and not tag:
    raise ValidationError("a tag is required", "tag")
  until = _until(params.get("until")) if action == "snooze" else None
  results: list[dict[str, Any]] = []
  for key in unique:
    try:
      device = repo.get_device(key)
      if device is None:
        raise NotFoundError("not found")
      if action in ("trust", "untrust"):
        repo.set_trusted(key, action == "trust", actor)
      elif action == "ack":
        repo.ack_events(key, actor)
      elif action == "snooze":
        repo.snooze(key, until, actor)
      elif action == "unsnooze":
        repo.snooze(key, None, actor)
      elif action in ("tag", "untag"):
        tags = [t for t in device.tags if t != tag] + ([tag] if action == "tag" else [])
        repo.update_device(key, {"tags": tags}, actor=actor)
      elif action in ("essential", "not-essential"):
        repo.update_device(key, {"essential": action == "essential"}, actor=actor)
      results.append({"key": key, "ok": True})
    except (NotFoundError, ValueError) as exc:
      results.append({"key": key, "ok": False, "error": str(exc)})
  return results


def _until(value: Any) -> datetime:
  """a snooze end: an iso timestamp or a number of hours; never in the past, at most 90 days ahead."""
  now = utcnow()
  if isinstance(value, (int, float)) and not isinstance(value, bool):
    moment = now + timedelta(hours=float(value))
  elif isinstance(value, str):
    try:
      moment = datetime.fromisoformat(value)
    except ValueError as exc:
      raise ValidationError("until must be an iso date or a number of hours", "until") from exc
    if moment.tzinfo is None:
      raise ValidationError("until needs a timezone", "until")
  else:
    raise ValidationError("until is required", "until")
  if moment <= now or moment > now + timedelta(days=90):
    raise ValidationError("until must be in the next 90 days", "until")
  return moment


def snooze(repo: Repository, key: str, until: Any, actor: str) -> None:
  repo.snooze(key, None if until is None else _until(until), actor)
