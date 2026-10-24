 # import libraries ->
import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cached_property

import typer
from rich.markup import escape

from beacon.config import Settings
from beacon.core.events import EventBus, EventType
from beacon.core.models import Device, utcnow
from beacon.core.report import ScanReport
from beacon.core.risk import RECENT_WINDOW, RiskAssessment, assess
from beacon.core.vendors import VendorDatabase
from beacon.pipeline import ProgressReporter, ScanOptions, ScanPipeline
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
    if self._db is not None:
      self._db.close()

  def find_device_or_exit(self, ref: str) -> Device:
    device = self.repository.find_device(ref)
    if device is None:
      error(f"no device matches {escape(repr(ref))}", "use a mac, ip, alias or hostname from `beacon devices list`")
      raise typer.Exit(1)
    return device

  def assess_devices(self, devices: Iterable[Device]) -> dict[str, RiskAssessment]:
    """risk per device from the stored state: unreviewed new ports and conflicts of the last day."""
    repo = self.repository
    cutoff = utcnow() - RECENT_WINDOW
    events = [
      *repo.list_events(limit=-1, types=[EventType.PORT_OPENED], pending_only=True),
      *(e for e in repo.list_events(limit=100, types=[EventType.IP_CONFLICT]) if e.timestamp >= cutoff),
    ]
    ports_known = repo.ports_ever_scanned()
    return {d.key: assess(d, events, ports_known) for d in devices}

  def run_scan(
    self,
    options: ScanOptions,
    show_progress: bool = True,
    bus: EventBus | None = None,
    progress: ProgressReporter | None = None,
  ) -> ScanReport:
    if progress is not None:
      pipeline = ScanPipeline(self.repository, self.vendors, bus or EventBus(), progress)
      return asyncio.run(pipeline.run(options))
    with RichProgress(err_console, enabled=show_progress) as rich_progress:
      pipeline = ScanPipeline(self.repository, self.vendors, bus or EventBus(), rich_progress)
      return asyncio.run(pipeline.run(options))


def get_app(ctx: typer.Context) -> AppContext:
  app = ctx.find_object(AppContext)
  if app is None:  # only happens when a command is invoked without the root callback
    app = AppContext(settings=Settings.load())
    ctx.obj = app
    ctx.call_on_close(app.close)
  return app
