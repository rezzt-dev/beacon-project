 # import libraries ->
import contextlib
import threading
import weakref
from functools import cached_property

from beacon.config import Settings
from beacon.core.vendors import VendorDatabase
from beacon.storage import Database, Repository


 # workspace ->
class Workspace:
  """what the live server shares between threads: settings, vendors and one repository per thread.

  sqlite connections never cross threads; each thread lazily opens its own and wal lets readers
  and the single scanning writer work at the same time.
  """

  def __init__(self, settings: Settings) -> None:
    self.settings = settings
    self._local = threading.local()
    self._lock = threading.Lock()
    self._databases: weakref.WeakSet[Database] = weakref.WeakSet()

  @property
  def repository(self) -> Repository:
    repo = getattr(self._local, "repo", None)
    if repo is None:
      self.settings.ensure_dirs()
      db = Database(self.settings.db_path)
      with self._lock:
        self._databases.add(db)
      repo = Repository(db)
      self._local.repo = repo
    return repo

  @cached_property
  def vendors(self) -> VendorDatabase:
    with self._lock:
      return VendorDatabase.load_default(self.settings.oui_path)

  def close(self) -> None:
    with self._lock:
      for db in list(self._databases):
        # a connection owned by another thread is closed by that thread or at exit
        with contextlib.suppress(Exception):
          db.close()
