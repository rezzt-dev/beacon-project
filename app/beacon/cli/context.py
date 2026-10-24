 # import libraries ->
import asyncio
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from functools import cached_property

import typer
from rich.markup import escape

from beacon.config import Settings
from beacon.core.events import EventBus
from beacon.core.models import Device
from beacon.core.report import ScanReport
from beacon.core.risk import RiskAssessment
from beacon.core.vendors import VendorDatabase
from beacon.pipeline import ProgressReporter, ScanOptions, ScanPipeline
from beacon.services.risk import assess_devices
from beacon.storage import Database, Repository
from beacon.ui.console import err_console, error, warn
from beacon.ui.progress import RichProgress


 # application context ->
@dataclass
class AppContext:
  """lazily built services shared by every command of one cli invocation."""

  settings: Settings
  verbose: bool = False
  _db: Database | None = field(default=None, init=False, repr=False)
  _senders: list = field(default_factory=list, init=False, repr=False)

  @cached_property
  def repository(self) -> Repository:
    self.settings.ensure_dirs()
    self._db = Database(self.settings.db_path)
    return Repository(self._db)

  @cached_property
  def vendors(self) -> VendorDatabase:
    vendors = VendorDatabase.load_default(self.settings.oui_path)
    if not len(vendors):
      warn("oui vendor database not found, vendors will show as unknown. run `beacon vendors update` once.")
    return vendors

  def close(self) -> None:
    self.wait_for_notifications()
    if self._db is not None:
      self._db.close()

  def find_device_or_exit(self, ref: str) -> Device:
    device = self.repository.find_device(ref)
    if device is None:
      error(f"no device matches {escape(repr(ref))}", "use a mac, ip, alias or hostname from `beacon devices list`")
      raise typer.Exit(1)
    return device

  def assess_devices(self, devices: Iterable[Device]) -> dict[str, RiskAssessment]:
    return assess_devices(self.repository, devices)

  def run_scan(
    self,
    options: ScanOptions,
    show_progress: bool = True,
    bus: EventBus | None = None,
    progress: ProgressReporter | None = None,
  ) -> ScanReport:
    hooks = [self._alert]
    if progress is not None:
      pipeline = ScanPipeline(self.repository, self.vendors, bus or EventBus(), progress, hooks)
      return asyncio.run(pipeline.run(options))
    with RichProgress(err_console, enabled=show_progress) as rich_progress:
      pipeline = ScanPipeline(self.repository, self.vendors, bus or EventBus(), rich_progress, hooks)
      return asyncio.run(pipeline.run(options))

  def _alert(self, report: ScanReport) -> None:
    """queue notifications for the alert policies, then send them off the main thread with their own connection."""
    from beacon.services.alerts import dispatch, evaluate_report

    evaluate_report(self.repository, report)
    if self.repository.due_deliveries():
      settings = self.settings

      def send() -> None:
        db = Database(settings.db_path)
        try:
          dispatch(Repository(db))
        finally:
          db.close()

      thread = threading.Thread(target=send, name="beacon-notify", daemon=True)
      thread.start()
      self._senders.append(thread)

  def wait_for_notifications(self, timeout: float = 15.0) -> None:
    for thread in self._senders:
      thread.join(timeout)


class LeaseBusy(RuntimeError):
  pass


def take_lease(repo: Repository, options: ScanOptions, kind: str, ttl: timedelta) -> str | None:
  """claim the network this scan touches so the live app or another watch does not scan it too.

  returns the scope to release later, or `None` when the network cannot be resolved yet (the scan
  itself will then fail and say why). raises `LeaseBusy` with the holder when someone else has it.
  """
  from beacon.web.jobs import lease_scope

  try:
    scope = lease_scope(options.target, options.interface)
  except (OSError, ValueError):
    return None
  holder = repo.acquire_lease(scope, kind, ttl)
  if holder is not None:
    raise LeaseBusy(f"{scope[4:]} is already being scanned by {holder['kind']} (pid {holder['pid']}, until {holder['expires_at']})")
  return scope


def get_app(ctx: typer.Context) -> AppContext:
  app = ctx.find_object(AppContext)
  if app is None:  # only happens when a command is invoked without the root callback
    app = AppContext(settings=Settings.load())
    ctx.obj = app
    ctx.call_on_close(app.close)
  return app
