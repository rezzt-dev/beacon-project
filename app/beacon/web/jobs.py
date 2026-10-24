 # import libraries ->
import asyncio
import contextlib
import itertools
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from beacon.core.events import Event, EventBus
from beacon.core.models import utcnow
from beacon.pipeline import ScanPipeline
from beacon.scanners.network import resolve_target
from beacon.services import profiles as profile_service
from beacon.storage import Database, Repository
from beacon.web.workspace import Workspace


log = logging.getLogger(__name__)


 # constants ->
MAX_QUEUED = 4
MAX_HISTORY = 50
ONE_SHOT_LEASE = timedelta(minutes=15)
DISPATCH_EVERY = 5.0
PASSIVE_DEBOUNCE = 60.0


def lease_scope(target: str | None, interface: str | None) -> str:
  """the network a scan touches: one owner at a time, whatever process it runs in."""
  _iface, network = resolve_target(target, interface)
  return f"net:{network}"


class JobRejected(RuntimeError):
  def __init__(self, message: str, code: str = "busy", holder: dict[str, Any] | None = None) -> None:
    super().__init__(message)
    self.code = code
    self.holder = holder


 # jobs ->
@dataclass(slots=True)
class Job:
  id: int
  kind: str
  trigger: str
  profile_id: int | None = None
  target: str | None = None
  network_id: int | None = None
  state: str = "queued"
  created_at: datetime = field(default_factory=utcnow)
  started_at: datetime | None = None
  finished_at: datetime | None = None
  scan_id: int | None = None
  scan_status: str | None = None
  stage: str | None = None
  done: int = 0
  total: int | None = None
  error: str | None = None
  scope: str | None = None
  _task: asyncio.Task | None = None
  _finished: threading.Event = field(default_factory=threading.Event)

  @property
  def active(self) -> bool:
    return self.state in ("queued", "running")

  def to_dict(self) -> dict[str, Any]:
    return {
      "id": self.id,
      "kind": self.kind,
      "trigger": self.trigger,
      "profile_id": self.profile_id,
      "target": self.target,
      "network_id": self.network_id,
      "state": self.state,
      "created_at": self.created_at.isoformat(),
      "started_at": self.started_at.isoformat() if self.started_at else None,
      "finished_at": self.finished_at.isoformat() if self.finished_at else None,
      "scan_id": self.scan_id,
      "scan_status": self.scan_status,
      "stage": self.stage,
      "progress": {"done": self.done, "total": self.total},
      "error": self.error,
      "scope": self.scope,
    }


class _JobProgress:
  def __init__(self, job: Job, lock: threading.Lock) -> None:
    self.job = job
    self.lock = lock

  def stage(self, name: str, total: int | None = None) -> None:
    with self.lock:
      self.job.stage, self.job.total, self.job.done = name, total, 0

  def advance(self, amount: int = 1) -> None:
    with self.lock:
      self.job.done += amount


@dataclass(slots=True)
class MonitorState:
  enabled: bool = False
  profile_id: int | None = None
  interval: int = 60
  state: str = "stopped"  # stopped, waiting, scanning, blocked
  next_at: datetime | None = None
  last_started: datetime | None = None
  last_finished: datetime | None = None
  last_error: str | None = None
  blocked_by: dict[str, Any] | None = None
  scope: str | None = None
  cycles: int = 0
  passive: str = "off"  # off, listening, unavailable

  def to_dict(self) -> dict[str, Any]:
    return {
      "enabled": self.enabled,
      "profile_id": self.profile_id,
      "interval": self.interval,
      "state": self.state,
      "next_at": self.next_at.isoformat() if self.next_at else None,
      "last_started": self.last_started.isoformat() if self.last_started else None,
      "last_finished": self.last_finished.isoformat() if self.last_finished else None,
      "last_error": self.last_error,
      "blocked_by": self.blocked_by,
      "scope": self.scope,
      "cycles": self.cycles,
      "passive": self.passive,
    }


 # worker ->
class ScanWorker:
  """every scan of the live process runs on this one thread and its event loop.

  - jobs are queued (at most `MAX_QUEUED`) and run one at a time: no overlapping scans.
  - a scan holds the database lease of its network, so `beacon watch` or another server cannot
    scan the same network at the same time; they are told who holds it instead.
  - the monitor schedules the next scan after the previous one ended, never on top of it.
  - api threads only enqueue, cancel and read state; slow clients never touch the scanner.
  """

  def __init__(self, workspace: Workspace, on_event: Callable[[Event], None] | None = None) -> None:
    self.workspace = workspace
    self.on_event = on_event
    self.monitor = MonitorState()
    self._lock = threading.Lock()
    self._jobs: dict[int, Job] = {}
    self._history: deque[int] = deque(maxlen=MAX_HISTORY)
    self._ids = itertools.count(1)
    self._loop: asyncio.AbstractEventLoop | None = None
    self._queue: asyncio.Queue[Job] | None = None
    self._thread: threading.Thread | None = None
    self._ready = threading.Event()
    self._monitor_task: asyncio.Task | None = None
    self._monitor_wake: asyncio.Event | None = None
    self._held_scopes: set[str] = set()
    self._listener = None
    self._last_passive_scan = 0.0

  # lifecycle ->
  def start(self) -> None:
    if self._thread is not None:
      return
    self._thread = threading.Thread(target=self._run, name="beacon-scanner", daemon=True)
    self._thread.start()
    self._ready.wait(5)

  def _run(self) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    self._loop = loop
    self._queue = asyncio.Queue()
    self._monitor_wake = asyncio.Event()
    with contextlib.suppress(Exception):
      self.repo.abort_stale_scans()
    consumer = loop.create_task(self._consume())
    loop.create_task(self._dispatch_loop())
    self._ready.set()
    try:
      loop.run_forever()
    finally:
      consumer.cancel()
      pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
      for task in pending:
        task.cancel()
      loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
      for scope in list(self._held_scopes):
        with contextlib.suppress(Exception):
          self.repo.release_lease(scope)
      loop.close()

  def stop(self, timeout: float = 10.0) -> None:
    """cancel the running scan (it is recorded as cancelled), release leases and join the thread."""
    loop = self._loop
    if loop is None or self._thread is None:
      return
    loop.call_soon_threadsafe(loop.stop)
    self._thread.join(timeout)
    self._thread = None

  @property
  def repo(self) -> Repository:
    return self.workspace.repository

  def _call(self, func: Callable[..., Any], *args: Any) -> Any:
    """run `func` on the scanner loop and wait for its result."""
    if self._loop is None:
      raise RuntimeError("the scan worker is not running")

    async def call() -> Any:
      return func(*args)

    return asyncio.run_coroutine_threadsafe(call(), self._loop).result(10)

  # jobs ->
  def submit(
    self,
    kind: str = "scan",
    trigger: str = "web",
    profile_id: int | None = None,
    target: str | None = None,
    network_id: int | None = None,
  ) -> Job:
    """queue a scan. refused when the queue is full or the same scope already has a queued one."""
    with self._lock:
      active = [j for j in self._jobs.values() if j.active]
      if len(active) >= MAX_QUEUED:
        raise JobRejected("too many scans waiting; try again when the current one finishes", "queue_full")
      if any(j.profile_id == profile_id and j.target == target and j.kind == kind for j in active):
        raise JobRejected("the same scan is already queued or running", "duplicate")
      job = Job(next(self._ids), kind, trigger, profile_id, target, network_id)
      self._jobs[job.id] = job
      self._history.append(job.id)
      for stale in [i for i in self._jobs if i not in self._history and not self._jobs[i].active]:
        self._jobs.pop(stale, None)
    self._call(lambda: self._queue.put_nowait(job))  # type: ignore[union-attr]
    return job

  def cancel(self, job_id: int) -> bool:
    with self._lock:
      job = self._jobs.get(job_id)
      if job is None or not job.active:
        return False
      if job.state == "queued":
        job.state = "cancelled"
        job.finished_at = utcnow()
        job._finished.set()
        return True
      task = job._task
    if task is not None and self._loop is not None:
      self._loop.call_soon_threadsafe(task.cancel)
    return True

  def jobs(self) -> list[dict[str, Any]]:
    with self._lock:
      return [self._jobs[i].to_dict() for i in reversed(self._history) if i in self._jobs]

  def job(self, job_id: int) -> dict[str, Any] | None:
    with self._lock:
      job = self._jobs.get(job_id)
      return job.to_dict() if job else None

  def wait(self, job_id: int, timeout: float | None = None) -> dict[str, Any] | None:
    with self._lock:
      job = self._jobs.get(job_id)
    if job is None:
      return None
    job._finished.wait(timeout)
    return self.job(job_id)

  async def _consume(self) -> None:
    assert self._queue is not None
    while True:
      job = await self._queue.get()
      if job.state != "queued":
        continue
      await self._execute(job)

  async def _execute(self, job: Job) -> None:
    repo = self.repo
    profile = repo.get_profile(job.profile_id) if job.profile_id else None
    options = profile_service.scan_options(profile, trigger=job.trigger)
    if job.target:
      options.target = job.target
      options.network_id = job.network_id
    with self._lock:
      job.state, job.started_at = "running", utcnow()
    try:
      scope = await asyncio.to_thread(lease_scope, options.target, options.interface)
      job.scope = scope
      monitor_owned = scope in self._held_scopes
      if not monitor_owned:
        holder = repo.acquire_lease(scope, "live-scan", ONE_SHOT_LEASE)
        if holder is not None:
          raise JobRejected(f"{scope[4:]} is being scanned by {holder['kind']} (pid {holder['pid']})", "leased", holder)
      try:
        bus = EventBus()
        if self.on_event is not None:
          bus.subscribe(self.on_event)
        pipeline = ScanPipeline(repo, self.workspace.vendors, bus, _JobProgress(job, self._lock), [self._alert])
        run = asyncio.ensure_future(pipeline.run(options))
        with self._lock:
          job._task = run
        report = await run
        with self._lock:
          job.state, job.scan_id, job.scan_status = "completed", report.scan_id, str(report.status)
      finally:
        if not monitor_owned:
          repo.release_lease(scope)
    except asyncio.CancelledError:
      with self._lock:
        job.state = "cancelled"
      current = asyncio.current_task()
      if current is not None and current.cancelling():
        raise  # the worker itself is shutting down, not just this job
    except JobRejected as exc:
      with self._lock:
        job.state, job.error = "blocked", str(exc)
    except Exception as exc:  # the job records the failure; the worker keeps serving
      log.debug("scan job %s failed", job.id, exc_info=True)
      with self._lock:
        job.state, job.error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
      with self._lock:
        job.finished_at = utcnow()
        job._task = None
        job._finished.set()

  # notifications ->
  def _alert(self, report: Any) -> None:
    from beacon.services.alerts import evaluate_report

    evaluate_report(self.repo, report)

  async def _dispatch_loop(self) -> None:
    """send queued notifications every few seconds, in a thread with its own connection."""
    from beacon.services.alerts import dispatch

    def send() -> None:
      db = Database(self.workspace.settings.db_path)
      try:
        dispatch(Repository(db))
      finally:
        db.close()

    while True:
      await asyncio.sleep(DISPATCH_EVERY)
      try:
        await asyncio.to_thread(send)
      except Exception:  # a broken channel must not stop the worker
        log.exception("notification dispatch failed")

  # monitor ->
  def start_monitor(self, profile_id: int | None, interval: int) -> dict[str, Any]:
    if not 10 <= interval <= 86400:
      raise ValueError("interval must be between 10 and 86400 seconds")

    def start() -> None:
      self.monitor.enabled, self.monitor.profile_id, self.monitor.interval = True, profile_id, interval
      self.monitor.last_error = None
      if self._monitor_task is None or self._monitor_task.done():
        self._monitor_task = asyncio.ensure_future(self._monitor_loop())
      elif self._monitor_wake is not None:
        self._monitor_wake.set()

    self._call(start)
    return self.monitor.to_dict()

  def stop_monitor(self) -> dict[str, Any]:
    """stop scheduling scans; a scan in progress finishes normally, its result is kept."""

    def stop() -> None:
      self.monitor.enabled = False
      self.monitor.next_at = None
      if self._monitor_task is not None:
        self._monitor_task.cancel()
      if self.monitor.scope:
        with contextlib.suppress(Exception):
          self.repo.release_lease(self.monitor.scope)
        self._held_scopes.discard(self.monitor.scope)
      self.monitor.state = "stopped"

    self._call(stop)
    return self.monitor.to_dict()

  # passive listening ->
  def _start_passive(self, interface: str | None) -> None:
    """listen for arp, dhcp and mdns while monitoring, when enabled and possible."""
    from beacon.scanners.privileges import privileged_mode_available
    from beacon.services import settings as app_settings

    if not app_settings.load(self.repo)["passive"]["enabled"]:
      self.monitor.passive = "off"
      return
    if not privileged_mode_available():
      self.monitor.passive = "unavailable"
      return
    from beacon.scanners.passive import PassiveListener

    loop = self._loop

    def seen(sighting) -> None:
      if loop is not None:
        loop.call_soon_threadsafe(self._on_sighting, sighting)

    try:
      self._listener = PassiveListener(interface, seen)
      self._listener.start()
      self.monitor.passive = "listening"
    except Exception:  # no permission after all, missing libpcap...
      log.warning("passive listening could not start", exc_info=True)
      self._listener = None
      self.monitor.passive = "unavailable"

  def _on_sighting(self, sighting) -> None:
    """an unknown mac on the wire: scan now instead of waiting for the next cycle (at most once a minute)."""
    if not self.monitor.enabled or time.monotonic() - self._last_passive_scan < PASSIVE_DEBOUNCE:
      return
    known = self.repo.conn.execute("SELECT 1 FROM devices WHERE mac = ? LIMIT 1", (sighting.mac,)).fetchone()
    if known:
      return
    self._last_passive_scan = time.monotonic()
    if self._monitor_wake is not None:
      log.info("passive sighting of %s: scanning now", sighting.mac)
      self._monitor_wake.set()

  def _stop_passive(self) -> None:
    if self._listener is not None:
      self._listener.stop()
      self._listener = None
    self.monitor.passive = "off"

  async def _monitor_loop(self) -> None:
    repo = self.repo
    try:
      while self.monitor.enabled:
        profile = repo.get_profile(self.monitor.profile_id) if self.monitor.profile_id else None
        options = profile_service.scan_options(profile, "monitor")
        try:
          scope = await asyncio.to_thread(lease_scope, options.target, options.interface)
        except Exception as exc:  # the interface is gone: keep trying, say why
          self.monitor.state, self.monitor.last_error = "blocked", f"{type(exc).__name__}: {exc}"
          await self._sleep(self.monitor.interval)
          continue
        ttl = timedelta(seconds=max(120, 3 * self.monitor.interval))
        holder = repo.acquire_lease(scope, "live-monitor", ttl)
        if holder is not None:
          self.monitor.state, self.monitor.blocked_by = "blocked", holder
          self.monitor.last_error = f"{scope[4:]} is monitored by {holder['kind']} (pid {holder['pid']})"
          await self._sleep(self.monitor.interval)
          continue
        self.monitor.scope, self.monitor.blocked_by = scope, None
        self._held_scopes.add(scope)
        if self._listener is None and self.monitor.passive == "off":
          self._start_passive(options.interface)
        started = time.monotonic()
        self.monitor.state, self.monitor.last_started, self.monitor.next_at = "scanning", utcnow(), None
        job = Job(next(self._ids), "scan", "monitor", self.monitor.profile_id)
        with self._lock:
          self._jobs[job.id] = job
          self._history.append(job.id)
        await self._execute(job)
        self.monitor.cycles += 1
        self.monitor.last_finished = utcnow()
        self.monitor.last_error = job.error
        repo.acquire_lease(scope, "live-monitor", ttl)  # renew for the wait
        wait = max(0.0, self.monitor.interval - (time.monotonic() - started))
        self.monitor.state = "waiting"
        self.monitor.next_at = utcnow() + timedelta(seconds=wait)
        await self._sleep(wait)
    except asyncio.CancelledError:
      pass
    finally:
      if not self.monitor.enabled:
        self.monitor.state = "stopped"
        self._stop_passive()

  async def _sleep(self, seconds: float) -> None:
    assert self._monitor_wake is not None
    self._monitor_wake.clear()
    with contextlib.suppress(TimeoutError):
      await asyncio.wait_for(self._monitor_wake.wait(), seconds)

  def status(self) -> dict[str, Any]:
    with self._lock:
      running = next((j.to_dict() for j in self._jobs.values() if j.state == "running"), None)
      queued = sum(j.state == "queued" for j in self._jobs.values())
    return {"monitor": self.monitor.to_dict(), "running": running, "queued": queued}
