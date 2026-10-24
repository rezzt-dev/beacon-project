 # import libraries ->
import threading
from collections import OrderedDict
from collections.abc import Callable, Hashable
from typing import Any, TypeVar

from beacon.storage import Repository


T = TypeVar("T")


 # cache ->
class CursorCache:
  """results that stay valid until anything changes. every write appends to the change feed, so its
  newest id (the cursor) is part of the key: a scan, an edit or an acknowledgement invalidates all.
  """

  def __init__(self, size: int = 32) -> None:
    self.size = size
    self._items: OrderedDict[Hashable, Any] = OrderedDict()
    self._lock = threading.Lock()

  def get(self, repo: Repository, key: Hashable, compute: Callable[[], T]) -> T:
    # Memory databases have independent contents even when both are named :memory:.
    # Uncommitted writes must never publish results to other connections.
    if repo.conn.in_transaction:
      return compute()
    database = repo.db if repo.db.is_memory else str(repo.db.path)
    full = (database, repo.change_bounds()[1], key)
    with self._lock:
      if full in self._items:
        self._items.move_to_end(full)
        return self._items[full]
    value = compute()
    with self._lock:
      self._items[full] = value
      while len(self._items) > self.size:
        self._items.popitem(last=False)
    return value

  def clear(self) -> None:
    with self._lock:
      self._items.clear()


matches = CursorCache()
