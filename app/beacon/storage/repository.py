 # import libraries ->
from beacon.storage.admin import AdminStore, RetentionPolicy
from beacon.storage.alerts import AlertStore
from beacon.storage.base import ConflictError, NotFoundError
from beacon.storage.database import Database
from beacon.storage.devices import DeviceFilter, DeviceStore
from beacon.storage.events import EventFilter, EventStore
from beacon.storage.identities import IdentityStore
from beacon.storage.measurements import MeasurementStore
from beacon.storage.presence import PresenceStore
from beacon.storage.profiles import ProfileStore
from beacon.storage.scans import ScanStore


 # repository ->
class Repository(
  MeasurementStore, ScanStore, DeviceStore, EventStore, IdentityStore, PresenceStore, ProfileStore, AlertStore, AdminStore
):
  """all sql lives here; the rest of the app only sees domain models.

  it is assembled from one store per area (devices, scans, events, identities, presence,
  measurements, administration) that share one connection. a repository belongs to one thread.
  """

  def __init__(self, db: Database) -> None:
    super().__init__(db)


__all__ = ["ConflictError", "DeviceFilter", "EventFilter", "NotFoundError", "Repository", "RetentionPolicy"]
