 # import libraries ->
import hashlib
import hmac
import json
import logging
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from beacon import __version__
from beacon.core.alerts import evaluate, matches, summary
from beacon.core.events import EventType, Severity
from beacon.core.models import utcnow
from beacon.core.report import ScanReport
from beacon.services.risk import assess_devices
from beacon.storage import EventFilter, Repository


log = logging.getLogger(__name__)


 # constants ->
CHANNEL_KINDS = ("desktop", "webhook")
MAX_ATTEMPTS = 5
BACKOFF = timedelta(seconds=30)
WEBHOOK_TIMEOUT = 5.0
EVENT_TYPES = [str(t) for t in EventType]


class AlertError(ValueError):
  def __init__(self, message: str, field_name: str) -> None:
    super().__init__(message)
    self.field = field_name


 # validation ->
def _int(values: dict[str, Any], name: str, low: int, high: int) -> int | None:
  value = values.get(name)
  if value is None:
    return None
  if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
    raise AlertError(f"{name} must be a whole number between {low} and {high}", name)
  return value


def validate_policy(values: dict[str, Any], partial: bool = False) -> dict[str, Any]:
  clean: dict[str, Any] = {}
  if not partial or "name" in values:
    name = str(values.get("name") or "").strip()
    if not 1 <= len(name) <= 64:
      raise AlertError("name is required (at most 64 characters)", "name")
    clean["name"] = name
  if "enabled" in values:
    if not isinstance(values["enabled"], bool):
      raise AlertError("enabled must be true or false", "enabled")
    clean["enabled"] = values["enabled"]
  if "network_id" in values:
    clean["network_id"] = _int(values, "network_id", 1, 10**9)
  if "event_types" in values:
    types = values["event_types"] or []
    if not isinstance(types, list) or any(t not in EVENT_TYPES for t in types):
      raise AlertError(f"event_types must be a list of: {', '.join(EVENT_TYPES)}", "event_types")
    clean["event_types"] = list(dict.fromkeys(types))
  if "min_severity" in values:
    if values["min_severity"] not in [str(s) for s in Severity]:
      raise AlertError("min_severity must be info, warning or alert", "min_severity")
    clean["min_severity"] = values["min_severity"]
  if "device_filter" in values:
    flt = values["device_filter"] or {}
    allowed = {"trusted": (bool, type(None)), "essential": (bool,), "tag": (str,)}
    if not isinstance(flt, dict) or any(k not in allowed or not isinstance(v, allowed[k]) for k, v in flt.items()):
      raise AlertError("device_filter accepts trusted (true/false/null), essential (true) and tag (text)", "device_filter")
    clean["device_filter"] = flt
  if "min_risk" in values:
    clean["min_risk"] = _int(values, "min_risk", 0, 100)
  for name, low, high in (("window_seconds", 0, 7 * 86400), ("threshold", 1, 10000), ("cooldown_seconds", 0, 7 * 86400)):
    if name in values:
      if values[name] is None:
        raise AlertError(f"{name} is required", name)
      clean[name] = _int(values, name, low, high)
  if "channels" in values:
    channels = values["channels"] or []
    if not isinstance(channels, list) or not all(isinstance(c, int) and not isinstance(c, bool) for c in channels):
      raise AlertError("channels must be a list of channel ids", "channels")
    clean["channels"] = channels
  return clean


def validate_silence(values: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
  now = now or utcnow()
  try:
    starts = datetime.fromisoformat(values["starts_at"]) if values.get("starts_at") else now
    ends = datetime.fromisoformat(values["ends_at"]) if values.get("ends_at") else None
  except (TypeError, ValueError) as exc:
    raise AlertError("starts_at and ends_at must be iso dates with a timezone", "ends_at") from exc
  if ends is None and isinstance(values.get("hours"), (int, float)) and not isinstance(values.get("hours"), bool):
    ends = starts + timedelta(hours=float(values["hours"]))
  if ends is None:
    raise AlertError("give ends_at or hours", "ends_at")
  if starts.tzinfo is None or ends.tzinfo is None:
    raise AlertError("dates need a timezone", "ends_at")
  if ends <= starts or ends <= now or ends - starts > timedelta(days=90):
    raise AlertError("a silence ends after it starts, in the future, and lasts at most 90 days", "ends_at")
  types = values.get("event_types") or []
  if not isinstance(types, list) or any(t not in EVENT_TYPES for t in types):
    raise AlertError("event_types must be known event types", "event_types")
  reason = values.get("reason")
  if reason is not None and (not isinstance(reason, str) or len(reason) > 200):
    raise AlertError("reason is text of at most 200 characters", "reason")
  device = values.get("device_key")
  if device is not None and not isinstance(device, str):
    raise AlertError("device_key must be a device key", "device_key")
  return {
    "starts_at": starts, "ends_at": ends, "event_types": types, "reason": reason, "device_key": device,
    "network_id": _int(values, "network_id", 1, 10**9),
  }


def validate_channel(kind: str, config: dict[str, Any]) -> dict[str, Any]:
  if kind not in CHANNEL_KINDS:
    raise AlertError(f"kind must be one of: {', '.join(CHANNEL_KINDS)}", "kind")
  if kind == "desktop":
    return {}
  url = str((config or {}).get("url") or "")
  parts = urlsplit(url)
  if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or len(url) > 500:
    raise AlertError("a webhook needs an http(s) url without credentials in it", "config.url")
  return {"url": url}


 # evaluation ->
def evaluate_report(repo: Repository, report: ScanReport, now: datetime | None = None) -> list[dict[str, Any]]:
  """turn a saved scan's events into queued notifications. only writes deliveries; sending is separate,
  so a slow webhook never holds up a scan."""
  now = now or utcnow()
  policies = [p for p in repo.policies() if p.enabled]
  if not policies or not report.events:
    return []
  keys = {e.device_key for e in report.events if e.device_key}
  devices = repo.get_devices(keys)
  risks = {k: r.score for k, r in assess_devices(repo, devices.values(), now).items()}
  recent: dict[int, int] = {}
  for policy in policies:
    if policy.window_seconds and policy.threshold > 1:
      earlier = repo.query_events(
        EventFilter(network_id=report.network_id, since=now - timedelta(seconds=policy.window_seconds), until=report.started_at), limit=1000
      )
      recent[policy.id] = sum(
        1 for e in earlier if matches(policy, e, report.network_id, devices.get(e.device_key or ""), risks.get(e.device_key or ""))
      )
  decisions = evaluate(policies, report.events, report.network_id, now, devices, risks, repo.silences(now), recent)
  names = {k: d.display_name for k, d in devices.items()}
  outcome = []
  for decision in decisions:
    outcome.append({"policy": decision.policy.name, "notify": decision.notify, "reason": decision.reason, "silenced": decision.silenced})
    if not decision.notify:
      continue
    payload = summary(decision, names)
    fingerprint = hashlib.sha256(json.dumps([report.scan_id, decision.policy.id, [e.message for e in decision.events]]).encode()).hexdigest()[:24]
    for channel_id in decision.policy.channels:
      repo.enqueue_delivery(f"{fingerprint}:{channel_id}", decision.policy.id, channel_id, payload, now)
    repo.mark_fired(decision.policy.id, now)
  return outcome


 # sending ->
def _desktop(payload: dict[str, Any], _channel: dict[str, Any]) -> None:
  """a local desktop notification; arguments are passed as a list, never through a shell."""
  title = payload["title"][:120]
  body = "\n".join(e["message"] for e in payload["events"][:5])[:600]
  if shutil.which("notify-send"):
    urgency = "critical" if payload["severity"] == "alert" else "normal"
    subprocess.run(["notify-send", "--app-name=beacon", f"--urgency={urgency}", title, body], check=True, timeout=10)
  elif sys.platform == "darwin" and shutil.which("osascript"):
    script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run"
    subprocess.run(["osascript", "-e", script, title, body], check=True, timeout=10)
  else:
    raise RuntimeError("no desktop notifier found (install notify-send)")


def _webhook(payload: dict[str, Any], channel: dict[str, Any]) -> None:
  body = json.dumps({"source": f"beacon {__version__}", **payload}).encode()
  headers = {"content-type": "application/json", "user-agent": f"beacon/{__version__}"}
  if channel.get("secret"):
    headers["x-beacon-signature"] = "sha256=" + hmac.new(channel["secret"].encode(), body, hashlib.sha256).hexdigest()
  request = urllib.request.Request(channel["config"]["url"], data=body, headers=headers, method="POST")
  with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT) as response:  # noqa: S310 - configured by the user
    if response.status >= 300:
      raise RuntimeError(f"webhook answered {response.status}")


SENDERS: dict[str, Callable[[dict[str, Any], dict[str, Any]], None]] = {"desktop": _desktop, "webhook": _webhook}


def dispatch(repo: Repository, now: datetime | None = None, senders: dict[str, Callable] | None = None) -> dict[str, int]:
  """send what is due. a failure is retried with growing waits, up to `MAX_ATTEMPTS`, then marked failed."""
  senders = senders or SENDERS
  counts = {"sent": 0, "retry": 0, "failed": 0}
  for delivery in repo.due_deliveries(now):
    now_ = now or utcnow()
    attempts = delivery["attempts"] + 1
    channel = repo.get_channel(delivery["channel_id"], with_secret=True) if delivery["channel_id"] else None
    if channel is None or not channel["enabled"]:
      repo.finish_delivery(delivery["id"], "dropped", attempts, None, "channel missing or disabled")
      continue
    try:
      senders[channel["kind"]](delivery["payload"], channel)
    except (OSError, RuntimeError, subprocess.SubprocessError, urllib.error.URLError, ValueError) as exc:
      error = f"{type(exc).__name__}: {exc}"[:300]
      if attempts >= MAX_ATTEMPTS:
        repo.finish_delivery(delivery["id"], "failed", attempts, None, error)
        counts["failed"] += 1
      else:
        repo.finish_delivery(delivery["id"], "pending", attempts, now_ + BACKOFF * 2 ** (attempts - 1), error)
        counts["retry"] += 1
      log.info("delivery %s failed (%s)", delivery["id"], error)
      continue
    repo.finish_delivery(delivery["id"], "sent", attempts, None, None)
    counts["sent"] += 1
  return counts


def test_channel(repo: Repository, channel_id: int, actor: str) -> dict[str, Any]:
  """queue a harmless test notification on one channel and send it right away."""
  payload = {
    "policy": "test", "severity": "info", "count": 1, "title": "beacon: test notification",
    "events": [{"type": "test", "severity": "info", "message": "if you can read this, the channel works", "device": None, "ip": None, "at": utcnow().isoformat()}],
  }
  key = f"test:{channel_id}:{utcnow().isoformat()}"
  repo.enqueue_delivery(key, None, channel_id, payload)
  repo.record_audit(actor, "test", "channel", str(channel_id))
  dispatch(repo)
  delivery = next((d for d in repo.list_deliveries(20) if d["idempotency_key"] == key), None)
  return {"status": delivery["status"] if delivery else "unknown", "error": delivery["last_error"] if delivery else None}
