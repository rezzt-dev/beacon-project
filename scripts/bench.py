"""reproducible benchmarks of beacon on simulated data. nothing is sent to any network.

usage: python scripts/bench.py [--sizes 50,500,5000] [--events 100000] [--out results.json] [--baseline <dir>]

- builds one database per size with `beacon.demo.populate` (deterministic seed)
- measures api reads (p50/p95 over repeated requests, in process), the time a persisted change
  takes to reach a live client over sse, and the visual response of the device filter in chromium
- with --baseline, runs the same storage operations with the code of another checkout (for
  example the commit before the evolution) on an equivalent dataset
"""

 # import libraries ->
import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))


def hardware() -> dict:
  info = {"platform": platform.platform(), "python": sys.version.split()[0], "cpus": os.cpu_count()}
  try:
    for line in Path("/proc/cpuinfo").read_text().splitlines():
      if line.startswith("model name"):
        info["cpu"] = line.split(":", 1)[1].strip()
        break
    for line in Path("/proc/meminfo").read_text().splitlines():
      if line.startswith("MemTotal"):
        info["memory_gb"] = round(int(line.split()[1]) / 1048576, 1)
        break
  except OSError:
    pass
  return info


def percentiles(samples: list[float]) -> dict:
  ordered = sorted(samples)
  return {
    "p50_ms": round(statistics.median(ordered) * 1000, 1),
    "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] * 1000, 1),
    "max_ms": round(ordered[-1] * 1000, 1),
    "n": len(ordered),
  }


 # api ->
def bench_api(home: Path, repeat: int) -> dict:
  os.environ["BEACON_HOME"] = str(home)
  from starlette.testclient import TestClient

  from beacon.config import Settings
  from beacon.web.server import LiveConfig, create_app

  settings = Settings.load()
  app = create_app(settings, LiveConfig())
  results = {}
  with TestClient(app, base_url="http://127.0.0.1:8765") as client:
    csrf = client.post("/api/v1/session", json={"token": app.state.auth.token}).json()["csrf"]
    first = client.get("/api/v1/devices", params={"size": 1}).json()["items"][0]["key"]
    endpoints = {
      "devices page (50, sorted by ip)": ("/api/v1/devices", {"size": 50}),
      "devices page sorted by risk": ("/api/v1/devices", {"size": 50, "sort": "risk", "order": "desc"}),
      "devices search q=phone": ("/api/v1/devices", {"q": "phone", "size": 50}),
      "device detail": (f"/api/v1/devices/{first}", None),
      "events page (50)": ("/api/v1/events", {"size": 50}),
      "events filtered (alerts)": ("/api/v1/events", {"severity": "alert", "size": 50}),
      "summary": ("/api/v1/summary", None),
      "review queue": ("/api/v1/review", None),
      "services": ("/api/v1/services", None),
      "status": ("/api/v1/status", None),
    }
    for name, (path, params) in endpoints.items():
      samples = []
      size = 0
      for _ in range(repeat):
        started = time.perf_counter()
        response = client.get(path, params=params)
        samples.append(time.perf_counter() - started)
        assert response.status_code == 200, (path, response.status_code, response.text[:200])
        size = len(response.content)
      results[name] = {**percentiles(samples), "first_ms": round(samples[0] * 1000, 1), "bytes": size}
    samples = []
    for i in range(repeat):
      started = time.perf_counter()
      response = client.patch(f"/api/v1/devices/{first}", json={"alias": f"bench {i}"}, headers={"x-beacon-csrf": csrf})
      assert response.status_code == 200, response.text[:200]
      samples.append(time.perf_counter() - started)
    results["edit alias (write)"] = percentiles(samples)
  return results


 # service query budget ->
def bench_queries(home: Path) -> dict:
  """Count actual SQL statements and separate an empty application cache from its reuse."""
  from beacon.services import cache, inventory
  from beacon.storage import Database, Repository

  cache.matches.clear()
  results = {}
  with Database(home / "beacon.db") as db:
    repo = Repository(db)
    statements = []
    db.conn.set_trace_callback(statements.append)
    for name, query in (
      ("inventory_uncached", inventory.DeviceQuery()),
      ("inventory_cached", inventory.DeviceQuery()),
      ("inventory_resorted", inventory.DeviceQuery(sort="risk", descending=True)),
    ):
      statements.clear()
      started = time.perf_counter()
      page = inventory.query_devices(repo, query)
      results[name] = {"ms": round((time.perf_counter() - started) * 1000, 1),
                       "sql_statements": len(statements), "total": page.total}
    db.conn.set_trace_callback(None)
  return results


 # live propagation ->
def bench_propagation(home: Path, rounds: int = 10) -> dict:
  """time from a committed change (as the cli would make it) to its sse frame in a connected client."""
  import socket

  import httpx
  import uvicorn

  from beacon.config import Settings
  from beacon.storage import Database, Repository
  from beacon.web.server import LiveConfig, create_app

  os.environ["BEACON_HOME"] = str(home)
  settings = Settings.load()
  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
  app = create_app(settings, LiveConfig(port=port))
  server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
  thread = threading.Thread(target=server.run, daemon=True)
  thread.start()
  while not server.started:
    time.sleep(0.05)
  base = f"http://127.0.0.1:{port}"
  repo = Repository(Database(settings.db_path))
  key = repo.list_devices()[0].key
  delays = []
  with httpx.Client(base_url=base) as client:
    client.post("/api/v1/session", json={"token": app.state.auth.token})
    with client.stream("GET", "/api/v1/stream", timeout=30) as stream:
      lines = stream.iter_lines()
      for line in lines:
        if line.startswith("event: hello"):
          break
      for index in range(rounds):
        started = time.perf_counter()
        repo.set_alias(key, f"propagation {index}", actor="bench")
        for line in lines:
          if line.startswith("data:") and "device.updated" in line:
            delays.append(time.perf_counter() - started)
            break
  app.state.stream.close()
  server.should_exit = True
  thread.join(10)
  return percentiles(delays)


 # browser filter ->
def bench_filter(home: Path, rounds: int = 8) -> dict | None:
  """from typing in the device search to the table showing the filtered rows, in chromium."""
  try:
    from playwright.sync_api import sync_playwright
  except ImportError:
    return None
  import socket

  import uvicorn

  from beacon.config import Settings
  from beacon.web.server import LiveConfig, create_app

  os.environ["BEACON_HOME"] = str(home)
  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
  app = create_app(Settings.load(), LiveConfig(port=port))
  server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
  thread = threading.Thread(target=server.run, daemon=True)
  thread.start()
  while not server.started:
    time.sleep(0.05)
  base = f"http://127.0.0.1:{port}"
  samples = []
  with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(f"{base}/login#token={app.state.auth.token}")
    page.wait_for_selector("main h1")
    page.goto(base + "/devices")
    page.wait_for_selector("table.devices tbody tr")
    terms = ["phone", "tv", "nas", "camera", "printer", "laptop", "router", "speaker"]
    for term in terms[:rounds]:
      page.fill("#devices-q", "")
      page.wait_for_timeout(400)
      started = page.evaluate("performance.now()")
      page.fill("#devices-q", term)
      # done when the url carries the term and every visible row is a match
      check = (
        f"location.search.includes('q={term}') && document.querySelectorAll('table.devices tbody tr').length > 0"
        f" && [...document.querySelectorAll('table.devices tbody tr')].every(r => r.innerText.toLowerCase().includes('{term}'))"
      )
      deadline = time.monotonic() + 10
      while time.monotonic() < deadline:
        if page.evaluate(check):
          samples.append((page.evaluate("performance.now()") - started) / 1000)
          break
        time.sleep(0.005)
      else:
        raise AssertionError(f"filter did not finish: {term}")
    browser.close()
  app.state.stream.close()
  server.should_exit = True
  thread.join(10)
  # the search box waits 75 ms after the last keystroke before asking (debounce): reported separately
  result = percentiles(samples)
  result["debounce_ms"] = 75
  return result


 # baseline ->
BASELINE_SCRIPT = r'''
import sys, time, json, statistics
from datetime import UTC, datetime, timedelta
sys.path.insert(0, sys.argv[1])
from beacon.core.models import Device, PortInfo, PortState, ScanMode, Latency
from beacon.core.events import Event, EventType, Severity
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository
from beacon.export import render
n, events, path = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
repo = Repository(Database(path))
now = datetime.now(UTC).replace(microsecond=0)
devices = []
for i in range(n):
  mac = f"02:be:ac:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}"
  ip = f"198.18.{(i + 2) // 254}.{(i + 2) % 254 + 1}"
  d = Device(ip=ip, mac=mac, ips=[ip], hostname=f"host-{i}", vendor="Acme", first_seen=now, last_seen=now,
             ports=[PortInfo(80, PortState.OPEN), PortInfo(443, PortState.OPEN)], latency=Latency("icmp", 3, [1.0, 2.0]))
  devices.append(d)
kw = {"ports_scanned": True} if "ports_scanned" in ScanReport.__dataclass_fields__ else {}
for step in range(3):
  repo.save_scan(ScanReport("198.18.0.0/16", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=devices, **kw))
batch = [Event(EventType.NEW_DEVICE, Severity.WARNING, "x", device_key=devices[i % n].key, timestamp=now) for i in range(events)]
if batch:
  repo.conn.executemany("INSERT INTO events (timestamp, type, severity, device_key, message) VALUES (?, ?, ?, ?, ?)",
                        [(e.timestamp.isoformat(), str(e.type), str(e.severity), e.device_key, e.message) for e in batch])
  repo.conn.commit()
def timed(fn, repeat=10):
  samples = []
  for _ in range(repeat):
    t = time.perf_counter(); fn(); samples.append(time.perf_counter() - t)
  return round(statistics.median(samples) * 1000, 1)
out = {
  "load_devices_ms": timed(lambda: repo.load_devices()),
  "find_device_by_ip_ms": timed(lambda: repo.find_device(devices[n // 2].ip)),
  "list_events_50_ms": timed(lambda: repo.list_events(limit=50)),
  "pending_events_ms": timed(lambda: repo.list_pending_events(), 3),
  "html_report_ms": timed(lambda: render("html", repo.list_devices(), repo.list_events(limit=50), {}), 3),
}
print(json.dumps(out))
'''


def bench_storage(code_dir: Path, sizes: list[int], events: int) -> dict:
  """the same storage operations on an equivalent dataset with the code in `code_dir/app`."""
  results = {}
  with tempfile.TemporaryDirectory() as tmp:
    script = Path(tmp) / "baseline.py"
    script.write_text(BASELINE_SCRIPT)
    for size in sizes:
      db = Path(tmp) / f"b{size}.db"
      out = subprocess.run(
        [sys.executable, "-I", str(script), str(code_dir / "app"), str(size), str(events if size == max(sizes) else 0), str(db)],
        capture_output=True, text=True, check=True, timeout=1800,
      )
      results[str(size)] = json.loads(out.stdout.strip().splitlines()[-1])
  return results


 # main ->
def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--sizes", default="50,500,5000")
  parser.add_argument("--events", type=int, default=100_000)
  parser.add_argument("--repeat", type=int, default=30)
  parser.add_argument("--out", type=Path, default=ROOT / ".docs" / "project-info" / "evolucion" / "benchmarks.json")
  parser.add_argument("--baseline", type=Path, help="a checkout of the code to compare with (its app/ folder is used)")
  args = parser.parse_args()
  sizes = [int(s) for s in args.sizes.split(",")]
  from beacon.demo import populate

  report = {"hardware": hardware(), "dataset": {}, "api": {}, "propagation": {}, "filter": {}, "storage": {}}
  with tempfile.TemporaryDirectory() as tmp:
    for size in sizes:
      home = Path(tmp) / f"home{size}"
      home.mkdir()
      events = args.events if size == max(sizes) else min(args.events, size * 20)
      days = 3 if size >= 5000 else 7
      started = time.perf_counter()
      counts = populate(home / "beacon.db", devices=size, events=events, days=days)
      counts["generate_seconds"] = round(time.perf_counter() - started, 1)
      counts["db_mb"] = round((home / "beacon.db").stat().st_size / 1048576, 1)
      report["dataset"][str(size)] = counts
      print(f"dataset {size}: {counts}", flush=True)
      report["api"][str(size)] = bench_api(home, args.repeat)
      report.setdefault("queries", {})[str(size)] = bench_queries(home)
      import psutil
      report.setdefault("process_rss_mb", {})[str(size)] = round(psutil.Process().memory_info().rss / 1048576, 1)
      print(f"api {size}: done", flush=True)
      if size == 500 or size == sizes[0] and 500 not in sizes:
        report["propagation"][str(size)] = bench_propagation(home)
        report["filter"][str(size)] = bench_filter(home)
    report["storage"]["current"] = bench_storage(ROOT, sizes, args.events)
    if args.baseline:
      report["storage"]["baseline"] = bench_storage(args.baseline, sizes, args.events)
  args.out.parent.mkdir(parents=True, exist_ok=True)
  args.out.write_text(json.dumps(report, indent=2))
  print(json.dumps(report, indent=2))


if __name__ == "__main__":
  main()
