 # import libraries ->
import asyncio
from dataclasses import dataclass, field
from functools import cached_property

import typer

from beacon.config import Settings
from beacon.core.events import EventBus
from beacon.core.models import Device
from beacon.core.report import ScanReport
from beacon.core.vendors import VendorDatabase
from beacon.pipeline import ProgressReporter, ScanOptions, ScanPipeline
from beacon.storage import Database, Repository
from beacon.ui.console import err_console, warn
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
      err_console.print(f"[alert]error:[/alert] no device matches {ref!r} (use a mac, ip, alias or hostname)")
      raise typer.Exit(1)
    return device

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
