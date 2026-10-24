 # import libraries ->
import hashlib
import hmac
import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from beacon.core.alerts import Policy, Silence, evaluate
from beacon.core.events import Event, EventType, Severity
from beacon.core.models import ScanMode
from beacon.core.report import ScanReport
from beacon.services import alerts
from conftest import T0, make_device


CAMERA = "00:1b:c5:00:00:50"
ROUTER = "34:5d:9e:3f:2a:77"


def new_device(key=CAMERA, at=T0, severity=Severity.ALERT):
  return Event(EventType.NEW_DEVICE, severity, f"new device {key}", device_key=key, timestamp=at)


def policy(**kwargs):
  return Policy(id=kwargs.pop("id", 1), name=kwargs.pop("name", "new devices"), **kwargs)


 # evaluation ->
def test_a_matching_event_notifies_and_others_do_not():
  devices = {CAMERA: make_device("192.168.1.50", CAMERA)}
  [decision] = evaluate([policy(event_types=["new-device"])], [new_device()], 1, T0, devices, {})
  assert decision.notify and decision.events[0].device_key == CAMERA
  quiet = evaluate([policy(event_types=["port-opened"])], [new_device()], 1, T0, devices, {})
  assert quiet == []
  info = evaluate([policy(min_severity=Severity.ALERT)], [new_device(severity=Severity.INFO)], 1, T0, devices, {})
  assert info == []


def test_device_filters_and_minimum_risk():
  trusted = make_device("192.168.1.50", CAMERA, trusted=True, essential=True, tags=["iot"])
  devices = {CAMERA: trusted}
  assert evaluate([policy(device_filter={"trusted": False})], [new_device()], 1, T0, devices, {}) == []
  assert evaluate([policy(device_filter={"essential": True, "tag": "iot"})], [new_device()], 1, T0, devices, {})[0].notify
  assert evaluate([policy(min_risk=50)], [new_device()], 1, T0, devices, {CAMERA: 30}) == []
  assert evaluate([policy(min_risk=50)], [new_device()], 1, T0, devices, {CAMERA: 60})[0].notify


def test_silences_and_maintenance_windows_hold_notifications_back():
  devices = {CAMERA: make_device("192.168.1.50", CAMERA)}
  mute = Silence(1, T0 - timedelta(hours=1), T0 + timedelta(hours=1), device_key=CAMERA)
  [decision] = evaluate([policy()], [new_device()], 1, T0, devices, {}, [mute])
  assert not decision.notify and decision.reason == "silenced" and decision.silenced == 1
  later = Silence(2, T0 + timedelta(hours=2), T0 + timedelta(hours=3))
  assert evaluate([policy()], [new_device()], 1, T0, devices, {}, [later])[0].notify


def test_threshold_in_a_window_and_cooldown():
  devices = {CAMERA: make_device("192.168.1.50", CAMERA)}
  grouped = policy(threshold=3, window_seconds=600)
  assert not evaluate([grouped], [new_device()], 1, T0, devices, {}, recent_counts={1: 1})[0].notify
  assert evaluate([grouped], [new_device()], 1, T0, devices, {}, recent_counts={1: 2})[0].notify
  cooling = policy(cooldown_seconds=900, last_fired_at=T0 - timedelta(minutes=5))
  assert evaluate([cooling], [new_device()], 1, T0, devices, {})[0].reason == "cooling down"


 # queue and delivery ->
def report_with(events, scan_id=7):
  report = ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0, events=events)
  report.scan_id = scan_id
  return report


@pytest.fixture
def wired(repo):
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, T0, finished_at=T0, devices=[make_device("192.168.1.50", CAMERA)]))
  channel = repo.create_channel("webhook", "lab", {"url": "http://127.0.0.1:9/hook"}, "s" * 32)
  repo.create_policy({"name": "new devices", "event_types": ["new-device"], "channels": [channel["id"]], "cooldown_seconds": 0})
  return repo, channel


def test_queued_notifications_are_idempotent(wired):
  repo, _ = wired
  alerts.evaluate_report(repo, report_with([new_device()]), now=T0)
  alerts.evaluate_report(repo, report_with([new_device()]), now=T0 + timedelta(seconds=1))
  assert len(repo.list_deliveries()) == 1
  payload = repo.list_deliveries()[0]["payload"]
  assert payload["count"] == 1 and "presence" not in json.dumps(payload)


def test_failed_sends_back_off_and_stop(wired):
  repo, _ = wired
  alerts.evaluate_report(repo, report_with([new_device()]), now=T0)

  def broken(_payload, _channel):
    raise OSError("connection refused")

  now = T0
  for attempt in range(1, alerts.MAX_ATTEMPTS + 1):
    counts = alerts.dispatch(repo, now=now, senders={"webhook": broken})
    delivery = repo.list_deliveries()[0]
    assert delivery["attempts"] == attempt
    now += timedelta(hours=2)
  assert counts == {"sent": 0, "retry": 0, "failed": 1} and delivery["status"] == "failed"
  assert alerts.dispatch(repo, now=now, senders={"webhook": broken}) == {"sent": 0, "retry": 0, "failed": 0}


def test_a_webhook_receives_a_signed_minimal_payload(repo):
  received = {}

  class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
      received["body"] = self.rfile.read(int(self.headers["content-length"]))
      received["signature"] = self.headers["x-beacon-signature"]
      self.send_response(204)
      self.end_headers()

    def log_message(self, *_args):
      pass

  server = HTTPServer(("127.0.0.1", 0), Handler)
  thread = threading.Thread(target=server.handle_request, daemon=True)
  thread.start()
  secret = "a-long-shared-secret-1234"
  channel = repo.create_channel("webhook", "lab", {"url": f"http://127.0.0.1:{server.server_port}/hook"}, secret)
  result = alerts.test_channel(repo, channel["id"], "test")
  thread.join(5)
  server.server_close()
  assert result["status"] == "sent"
  expected = "sha256=" + hmac.new(secret.encode(), received["body"], hashlib.sha256).hexdigest()
  assert received["signature"] == expected
  assert json.loads(received["body"])["title"] == "beacon: test notification"


def test_desktop_notifications_never_go_through_a_shell(monkeypatch):
  calls = []
  monkeypatch.setattr(alerts.shutil, "which", lambda name: "/usr/bin/" + name if name == "notify-send" else None)
  monkeypatch.setattr(alerts.subprocess, "run", lambda args, **kw: calls.append((args, kw)))
  payload = {"title": "beacon: 1 event · x", "severity": "alert", "events": [{"message": "$(rm -rf ~); `id`"}]}
  alerts._desktop(payload, {})
  args, kwargs = calls[0]
  assert isinstance(args, list) and "shell" not in kwargs and args[-1] == "$(rm -rf ~); `id`"


 # validation ->
def test_channel_and_policy_validation():
  with pytest.raises(alerts.AlertError):
    alerts.validate_channel("webhook", {"url": "file:///etc/passwd"})
  with pytest.raises(alerts.AlertError):
    alerts.validate_channel("webhook", {"url": "https://user:pass@example.com/hook"})
  with pytest.raises(alerts.AlertError):
    alerts.validate_channel("sms", {})
  with pytest.raises(alerts.AlertError):
    alerts.validate_policy({"name": "x", "event_types": ["nonsense"]})
  with pytest.raises(alerts.AlertError):
    alerts.validate_silence({"hours": 24 * 365}, now=T0)
  assert alerts.validate_silence({"hours": 2, "starts_at": T0.isoformat()}, now=T0)["ends_at"] == T0 + timedelta(hours=2)


def test_channel_secrets_never_leave_the_database(repo):
  repo.create_channel("webhook", "lab", {"url": "https://example.com/hook"}, "x" * 40)
  [listed] = repo.list_channels()
  assert listed["has_secret"] is True and "secret" not in listed
  assert repo.get_channel(listed["id"], with_secret=True)["secret"] == "x" * 40
