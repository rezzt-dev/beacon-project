 # import libraries ->
import asyncio
import threading
import time
from datetime import timedelta

import pytest
from starlette.testclient import TestClient

from beacon.config import Settings
from beacon.core.events import Event, EventType, Severity
from beacon.core.models import ScanMode, utcnow
from beacon.core.ports import PortSet
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository
from beacon.web import jobs as jobs_module
from beacon.web.server import LiveConfig, create_app
from beacon.web.stream import ChangeStream, _start_id
from beacon.web.workspace import Workspace
from conftest import make_device


BASE = "http://127.0.0.1:8765"
ROUTER = "34:5d:9e:3f:2a:77"
CAMERA = "00:1b:c5:00:00:50"
PHONE = "8e:e7:35:fe:0c:c6"
PHONE_2 = "9a:11:22:33:44:55"


 # fixtures ->
class FakePipeline:
  """stands in for the network: saves a small scan, or waits until cancelled."""

  gate: threading.Event | None = None

  def __init__(self, repository, vendors, bus=None, progress=None, after_save=None) -> None:
    self.repository = repository
    self.progress = progress
    self.after_save = after_save or []

  async def run(self, options):
    if self.progress is not None:
      self.progress.stage("fake sweep", 1)
    if FakePipeline.gate is not None:
      while not FakePipeline.gate.is_set():
        await asyncio.sleep(0.01)
    now = utcnow()
    report = ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, trigger=options.trigger)
    report.devices = [make_device("192.168.1.1", ROUTER, first_seen=now, last_seen=now)]
    report.scan_id = self.repository.save_scan(report)
    for hook in self.after_save:
      hook(report)
    return report


@pytest.fixture
def settings(tmp_path, monkeypatch):
  monkeypatch.setenv("BEACON_HOME", str(tmp_path))
  monkeypatch.delenv("BEACON_DB", raising=False)
  return Settings.load()


@pytest.fixture
def seeded(settings):
  repo = Repository(Database(settings.db_path))
  now = utcnow()
  devices = [
    make_device("192.168.1.1", ROUTER, vendor="Sagemcom", trusted=True, is_gateway=True, first_seen=now - timedelta(days=30), last_seen=now),
    make_device("192.168.1.50", CAMERA, ports=(23, 80), vendor=None, first_seen=now, last_seen=now),
    make_device("192.168.1.9", PHONE, randomized_mac=True, hostname="iphone-de-ana", services=["_airplay._tcp"], first_seen=now - timedelta(days=2), last_seen=now - timedelta(days=1)),
  ]
  events = [Event(EventType.NEW_DEVICE, Severity.ALERT, "camera joined", device_key=CAMERA, timestamp=now)]
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=devices, events=events, port_spec=PortSet([23, 80, 443])))
  repo.db.close()
  return settings


@pytest.fixture
def client(seeded, monkeypatch):
  monkeypatch.setattr(jobs_module, "ScanPipeline", FakePipeline)
  monkeypatch.setattr(jobs_module, "lease_scope", lambda target, iface: f"net:{target or '192.168.1.0/24'}")
  FakePipeline.gate = None
  app = create_app(seeded, LiveConfig())
  with TestClient(app, base_url=BASE) as test_client:
    test_client.app_state = app.state
    yield test_client


def login(client) -> dict[str, str]:
  response = client.post("/api/v1/session", json={"token": client.app_state.auth.token})
  assert response.status_code == 200
  return {"x-beacon-csrf": response.json()["csrf"]}


@pytest.fixture
def auth(client):
  return login(client)


 # security ->
def test_unknown_hosts_are_refused_to_stop_dns_rebinding(client):
  response = client.get("/api/v1/health", headers={"host": "evil.example:8765"})
  assert response.status_code == 421


def test_everything_but_health_needs_a_session(client):
  assert client.get("/api/v1/health").status_code == 200
  response = client.get("/api/v1/devices")
  assert response.status_code == 401 and response.json()["error"]["code"] == "unauthenticated"
  assert client.post("/api/v1/session", json={"token": "nope"}).status_code == 401


def test_writes_need_the_csrf_header_and_the_same_origin(client, auth):
  assert client.patch(f"/api/v1/devices/{CAMERA}", json={"alias": "cam"}).status_code == 403
  cross = client.patch(f"/api/v1/devices/{CAMERA}", json={"alias": "cam"}, headers={**auth, "origin": "http://evil.example"})
  assert cross.status_code == 403 and cross.json()["error"]["code"] == "bad_origin"
  same = client.patch(f"/api/v1/devices/{CAMERA}", json={"alias": "cam"}, headers={**auth, "origin": BASE})
  assert same.status_code == 200


def test_session_cookie_is_httponly_and_strict(client):
  response = client.post("/api/v1/session", json={"token": client.app_state.auth.token})
  cookie = response.headers["set-cookie"]
  assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_security_headers_and_no_store(client, auth):
  response = client.get("/api/v1/devices")
  csp = response.headers["content-security-policy"]
  assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp
  assert response.headers["x-content-type-options"] == "nosniff"
  assert response.headers["cache-control"] == "no-store"


def test_bodies_are_limited_and_validated(client, auth):
  big = client.patch(f"/api/v1/devices/{CAMERA}", content=b"{" + b" " * 70_000 + b"}", headers={**auth, "content-type": "application/json"})
  assert big.status_code == 413
  bad = client.patch(f"/api/v1/devices/{CAMERA}", content=b"{nope", headers={**auth, "content-type": "application/json"})
  assert bad.status_code == 400
  unknown = client.patch(f"/api/v1/devices/{CAMERA}", json={"trusted": True}, headers=auth)
  assert unknown.status_code == 422 and "not editable" in unknown.json()["error"]["message"]
  long = client.patch(f"/api/v1/devices/{CAMERA}", json={"alias": "x" * 100}, headers=auth)
  assert long.status_code == 422


def test_logins_are_rate_limited(client):
  codes = [client.post("/api/v1/session", json={"token": "bad"}).status_code for _ in range(12)]
  assert codes[-1] == 429


 # devices ->
def test_device_list_filters_sorts_and_paginates(client, auth):
  page = client.get("/api/v1/devices", params={"sort": "risk", "order": "desc", "size": 2}).json()
  assert page["total"] == 3 and page["pages"] == 2 and len(page["items"]) == 2
  assert page["items"][0]["key"] == CAMERA and page["items"][0]["risk"]["level"] == "high"
  assert page["facets"]["untrusted"] == 2
  assert [d["key"] for d in client.get("/api/v1/devices", params={"q": "iphone"}).json()["items"]] == [PHONE]
  assert [d["key"] for d in client.get("/api/v1/devices", params={"port": 23}).json()["items"]] == [CAMERA]
  assert [d["key"] for d in client.get("/api/v1/devices", params={"trusted": "true"}).json()["items"]] == [ROUTER]
  assert client.get("/api/v1/devices", params={"sort": "nonsense"}).status_code == 422


def test_device_detail_explains_risk_coverage_and_ports(client, auth):
  response = client.get(f"/api/v1/devices/{CAMERA}")
  detail = response.json()
  assert response.headers["etag"] == '"0"'
  assert detail["risk"]["complete"] is True and detail["coverage"]["examined"] == "23,80,443"
  assert {p["port"]: p["basis"] for p in detail["ports"]} == {23: "inferred", 80: "inferred"}
  assert any(r["code"] == "admin-plaintext" for r in detail["risk"]["reasons"])
  assert detail["pending_events"] == 1
  assert client.get("/api/v1/devices/nope").status_code == 404


def test_stale_edits_are_rejected_and_edits_reach_the_cli(client, auth, seeded):
  ok = client.patch(f"/api/v1/devices/{CAMERA}", json={"alias": "garage cam", "tags": ["IoT", "iot"], "version": 0}, headers=auth)
  assert ok.status_code == 200 and ok.json()["version"] == 1 and ok.json()["tags"] == ["iot"]
  stale = client.patch(f"/api/v1/devices/{CAMERA}", json={"alias": "other"}, headers={**auth, "if-match": '"0"'})
  assert stale.status_code == 409 and stale.json()["error"]["current_version"] == 1
  # another process (the cli) reads the same database
  other = Repository(Database(seeded.db_path))
  assert other.get_device(CAMERA).alias == "garage cam"
  assert other.list_audit("device", CAMERA)[0]["actor"].startswith("web:")


def test_trust_and_review_actions(client, auth):
  assert client.post(f"/api/v1/devices/{CAMERA}/trust", json={"trusted": True}, headers=auth).json()["trusted"] is True
  assert client.get("/api/v1/review").json()["total"] == 0
  # trusting reviewed the events but kept the exposure evidence
  assert client.get(f"/api/v1/devices/{CAMERA}").json()["risk"]["score"] > 0
  client.post(f"/api/v1/devices/{CAMERA}/trust", json={"trusted": False}, headers=auth)
  assert client.post(f"/api/v1/devices/{CAMERA}/review", json={"action": "snooze", "until": 24}, headers=auth).status_code == 200
  assert client.post(f"/api/v1/devices/{CAMERA}/review", json={"action": "snooze", "until": 24 * 365}, headers=auth).status_code == 422
  assert client.post(f"/api/v1/devices/{CAMERA}/review", json={"action": "dance"}, headers=auth).status_code == 422


def test_review_queue_hides_snoozed_devices_until_asked(client, auth):
  assert [c["device"]["key"] for c in client.get("/api/v1/review").json()["items"]] == [CAMERA]
  client.post(f"/api/v1/devices/{CAMERA}/review", json={"action": "snooze", "until": 2}, headers=auth)
  assert client.get("/api/v1/review").json()["total"] == 0
  snoozed = client.get("/api/v1/review", params={"snoozed": "true"}).json()["items"]
  assert snoozed[0]["snoozed_until"] is not None


def test_bulk_actions_report_each_device(client, auth):
  response = client.post("/api/v1/devices/bulk", json={"keys": [CAMERA, PHONE, "ghost"], "action": "tag", "tag": "lab"}, headers=auth)
  body = response.json()
  assert body["ok"] == 2 and body["failed"] == 1
  assert {r["key"]: r["ok"] for r in body["results"]} == {CAMERA: True, PHONE: True, "ghost": False}
  assert client.post("/api/v1/devices/bulk", json={"keys": [], "action": "trust"}, headers=auth).status_code == 422


def test_events_page_with_a_stable_cursor(client, auth):
  first = client.get("/api/v1/events", params={"size": 1}).json()
  assert first["total"] == 1 and first["items"][0]["type"] == "new-device"
  assert client.post(f"/api/v1/events/{first['items'][0]['id']}/ack", headers=auth).json()["acknowledged"] is True
  assert client.get("/api/v1/events", params={"acked": "false"}).json()["total"] == 0
  assert client.get("/api/v1/events", params={"type": "bogus"}).status_code == 422


 # identities ->
def test_identity_candidates_can_be_rejected_for_good(client, auth, seeded):
  repo = Repository(Database(seeded.db_path))
  now = utcnow()
  newer = make_device("192.168.1.10", PHONE_2, randomized_mac=True, hostname="iphone-de-ana", services=["_airplay._tcp"], first_seen=now, last_seen=now)
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=[newer]))
  candidates = client.get("/api/v1/identities").json()["candidates"]
  assert [(c["new"]["key"], c["candidate"]["key"]) for c in candidates] == [(PHONE_2, PHONE)]
  assert candidates[0]["evidence"] and candidates[0]["ambiguous"] is False
  client.post("/api/v1/identities/reject", json={"new": PHONE_2, "candidate": PHONE}, headers=auth)
  assert client.get("/api/v1/identities").json()["candidates"] == []
  linked = client.post("/api/v1/identities/link", json={"new": PHONE_2, "old": PHONE}, headers=auth).json()
  assert linked["trusted"] is False
  assert client.get(f"/api/v1/devices/{PHONE_2}").json()["trusted"] is False
  assert client.post("/api/v1/identities/unlink", json={"key": PHONE_2}, headers=auth).status_code == 200


 # jobs and monitor ->
def wait_for(predicate, timeout=5.0):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if predicate():
      return True
    time.sleep(0.02)
  return False


def test_a_scan_job_runs_once_and_lands_in_the_history(client, auth):
  response = client.post("/api/v1/jobs", json={}, headers=auth)
  assert response.status_code == 202
  job_id = response.json()["id"]
  assert wait_for(lambda: client.get(f"/api/v1/jobs/{job_id}").json()["state"] == "completed")
  job = client.get(f"/api/v1/jobs/{job_id}").json()
  assert job["scan_status"] == "complete" and job["trigger"] == "web"
  assert client.get("/api/v1/scans").json()["items"][0]["id"] == job["scan_id"]


def test_duplicate_jobs_are_refused_and_running_ones_cancel(client, auth):
  FakePipeline.gate = threading.Event()
  job_id = client.post("/api/v1/jobs", json={}, headers=auth).json()["id"]
  assert wait_for(lambda: client.get(f"/api/v1/jobs/{job_id}").json()["state"] == "running")
  assert client.post("/api/v1/jobs", json={}, headers=auth).status_code == 409
  assert client.delete(f"/api/v1/jobs/{job_id}", headers=auth).status_code == 202
  assert wait_for(lambda: client.get(f"/api/v1/jobs/{job_id}").json()["state"] == "cancelled")
  FakePipeline.gate = None


def test_a_network_scanned_by_another_process_blocks_the_job(client, auth, seeded):
  other = Repository(Database(seeded.db_path))
  assert other.acquire_lease("net:192.168.1.0/24", "watch", timedelta(minutes=5), owner="laptop:4242") is None
  job_id = client.post("/api/v1/jobs", json={}, headers=auth).json()["id"]
  assert wait_for(lambda: client.get(f"/api/v1/jobs/{job_id}").json()["state"] == "blocked")
  assert "watch" in client.get(f"/api/v1/jobs/{job_id}").json()["error"]
  status = client.get("/api/v1/status").json()
  assert status["external"][0]["kind"] == "watch"


def test_monitor_starts_scans_and_stops_without_overlap(client, auth):
  started = client.post("/api/v1/monitor", json={"action": "start", "interval": 10}, headers=auth).json()
  assert started["enabled"] is True
  assert wait_for(lambda: client.get("/api/v1/monitor").json()["cycles"] >= 1)
  assert client.get("/api/v1/monitor").json()["state"] == "waiting"
  stopped = client.post("/api/v1/monitor", json={"action": "stop"}, headers=auth).json()
  assert stopped["enabled"] is False and stopped["state"] == "stopped"
  assert client.post("/api/v1/monitor", json={"action": "start", "interval": 1}, headers=auth).status_code == 422


def test_status_reports_health_and_capabilities(client, auth):
  status = client.get("/api/v1/status").json()
  assert status["health"]["state"] in ("idle", "ok") and status["health"]["last_valid_at"]
  assert "privileged_mode" in status["capabilities"] and status["networks"][0]["cidr"] == "192.168.1.0/24"


def test_summary_points_at_the_next_action(client, auth):
  summary = client.get("/api/v1/summary").json()
  assert summary["devices"]["total"] == 3 and summary["pending_review"] == 1
  assert summary["next_action"]["code"] == "review"


 # profiles and settings ->
def test_profiles_only_accept_private_scopes(client, auth):
  public = client.post("/api/v1/profiles", json={"name": "internet", "target": "8.8.8.0/24"}, headers=auth)
  assert public.status_code == 422 and public.json()["error"]["field"] == "target"
  huge = client.post("/api/v1/profiles", json={"name": "huge", "target": "10.0.0.0/8"}, headers=auth)
  assert huge.status_code == 422
  created = client.post("/api/v1/profiles", json={"name": "home", "target": "192.168.1.0/24", "ports": "top", "options": {"latency_samples": 2}}, headers=auth)
  assert created.status_code == 201
  profile = created.json()
  edit = client.patch(f"/api/v1/profiles/{profile['id']}", json={"ports": "web", "version": profile["version"]}, headers=auth)
  assert edit.json()["ports"] == "web"
  stale = client.patch(f"/api/v1/profiles/{profile['id']}", json={"ports": "admin", "version": profile["version"]}, headers=auth)
  assert stale.status_code == 409


def test_settings_are_validated_as_a_whole(client, auth):
  assert client.patch("/api/v1/settings", json={"theme": "dark", "language": "es"}, headers=auth).json()["theme"] == "dark"
  bad = client.patch("/api/v1/settings", json={"theme": "light", "timezone": "Mars/Base"}, headers=auth)
  assert bad.status_code == 422 and bad.json()["error"]["field"] == "timezone"
  assert client.get("/api/v1/settings").json()["theme"] == "dark"


 # reports ->
def test_reports_leave_presence_out_and_can_hide_identifiers(client, auth):
  plain = client.get("/api/v1/reports/export", params={"format": "json"})
  assert plain.headers["content-disposition"].startswith("attachment") and ROUTER in plain.text
  assert '"presence"' not in plain.text and "_airplay" not in plain.text
  hidden = client.get("/api/v1/reports/export", params={"format": "json", "anonymize": "true"}).text
  assert ROUTER not in hidden and "192.168.1.50" not in hidden and "iphone-de-ana" not in hidden
  preview = client.get("/api/v1/reports/preview", params={"format": "csv", "include_presence": "true", "fields": "ip,risk"}).json()
  assert preview["includes_presence"] is True and any("trust" in w for w in preview["warnings"])
  assert client.get("/api/v1/reports/export", params={"format": "xml"}).status_code == 422
  html = client.get("/api/v1/reports/export", params={"format": "html"}).text
  assert "<script>" in html and "Content-Security-Policy" in html


def test_retention_preview_then_apply(client, auth):
  preview = client.post("/api/v1/maintenance/retention", json={"preview": True}, headers=auth).json()
  assert preview["preview"] is True and "events" in preview["would_delete"]
  assert client.post("/api/v1/maintenance/retention", json={"preview": False}, headers=auth).json()["preview"] is False


 # live stream ->
class _Request:
  def __init__(self, headers=None, query=None, polls=2):
    self.headers = headers or {}
    self.query_params = query or {}
    self._polls = polls

  async def is_disconnected(self):
    self._polls -= 1
    return self._polls < 0


def collect(stream, request):
  async def run():
    return [frame async for frame in stream._events(request, _start_id(request))]

  return asyncio.run(run())


def test_the_stream_resumes_after_the_last_event_and_resets_when_history_is_gone(seeded):
  workspace = Workspace(seeded)
  repo = workspace.repository
  _, newest = repo.change_bounds()
  repo.set_alias(CAMERA, "cam")
  stream = ChangeStream(lambda: workspace.repository, lambda: {"health": "ok"})
  frames = collect(stream, _Request(headers={"last-event-id": str(newest)}))
  changes = [f for f in frames if f.startswith("id:") and "event: change" in f]
  assert changes and f"id: {newest + 1}" in changes[0] and "device.updated" in "".join(changes)
  reset = collect(stream, _Request(query={"after": "999999"}))
  assert any("event: reset" in f for f in reset)
  fresh = collect(stream, _Request())
  assert "event: hello" in fresh[1]


 # alerts ->
def test_alert_rules_channels_and_silences_through_the_api(client, auth):
  channel = client.post("/api/v1/alerts/channels", json={"kind": "webhook", "name": "lab", "config": {"url": "https://example.com/hook"}, "secret": "s" * 20}, headers=auth)
  assert channel.status_code == 201 and "secret" not in channel.json() and channel.json()["has_secret"] is True
  assert client.post("/api/v1/alerts/channels", json={"kind": "webhook", "name": "x", "config": {"url": "ftp://x"}}, headers=auth).status_code == 422
  policy = client.post("/api/v1/alerts/policies", json={"name": "strangers", "event_types": ["new-device"], "channels": [channel.json()["id"]]}, headers=auth)
  assert policy.status_code == 201 and policy.json()["threshold"] == 1
  stale = client.patch(f"/api/v1/alerts/policies/{policy.json()['id']}", json={"threshold": 2, "version": 99}, headers=auth)
  assert stale.status_code == 409
  silence = client.post("/api/v1/alerts/silences", json={"hours": 2, "reason": "router firmware update"}, headers=auth)
  assert silence.status_code == 201
  assert [s["reason"] for s in client.get("/api/v1/alerts/silences").json()["items"]] == ["router firmware update"]
  assert "s" * 20 not in client.get("/api/v1/alerts/channels").text


def test_review_pages_bound_evidence_and_count_all_pending(client, auth, seeded):
  repo = Repository(Database(seeded.db_path))
  repo.record_events([Event(EventType.NEW_DEVICE, Severity.WARNING, f"event {i}", device_key=PHONE) for i in range(12)], network_id=1)
  first = client.get("/api/v1/review", params={"page": 1, "size": 1}).json()
  second = client.get("/api/v1/review", params={"page": 2, "size": 1}).json()
  assert first["total"] == second["total"] == 2
  assert len(first["items"]) == len(second["items"]) == 1
  assert first["items"][0]["device"]["key"] != second["items"][0]["device"]["key"]
  phone = next(c for c in first["items"] + second["items"] if c["device"]["key"] == PHONE)
  assert phone["pending"] == 12 and len(phone["events"]) == 5
  assert client.get("/api/v1/review?size=201").status_code == 422
  repo.db.close()
