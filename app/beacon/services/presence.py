 # import libraries ->
from datetime import datetime, timedelta, tzinfo
from typing import Any

from beacon.core.models import Device, DeviceStatus, utcnow
from beacon.core.presence import (
  MIN_MONITORED,
  MIN_PROFILE_DAYS,
  MIN_PROFILE_SESSIONS,
  PROFILE_WEEKS,
  SESSION_GAP,
  build_profile,
  is_profilable,
  usual_schedule,
  watched_seconds,
)
from beacon.services import settings as app_settings
from beacon.services.serialize import device_summary
from beacon.storage import NotFoundError, Repository


 # helpers ->
def _status(device: Device, sessions: int, profile_days: int) -> str:
  if not is_profilable(device):
    return "fragmented"
  if sessions == 0:
    return "no-data"
  if profile_days < MIN_PROFILE_DAYS or sessions < MIN_PROFILE_SESSIONS:
    return "learning"
  return "ready"


 # views ->
def device_presence(
  repo: Repository, key: str, weeks: int = PROFILE_WEEKS, now: datetime | None = None, tz: tzinfo | None = None
) -> dict[str, Any]:
  """the weekly rhythm of one device (or of its linked identity), with what beacon could not see.

  every cell says how many hours were watched; a cell nobody watched is `null`, never zero.
  """
  device = repo.get_device(key)
  if device is None:
    raise NotFoundError(f"device {key} not found")
  now = now or utcnow()
  tz = tz or app_settings.timezone(repo)
  since = now - timedelta(weeks=weeks)
  sessions = repo.sessions_by_identity([device], since=since)[key]
  windows = repo.observation_windows(since, app_settings.presence_gap(repo), device.network_id)
  profile = build_profile(sessions, now, weeks, tz, observed=windows)
  grid = []
  for weekday in range(7):
    row = []
    for hour in range(24):
      present, total = profile.cells.get((weekday, hour), (0, 0))
      row.append({"present": present, "watched": total, "frequency": round(present / total, 3) if total else None})
    grid.append(row)
  status = _status(device, len(sessions), profile.days)
  return {
    "device": device_summary(device),
    "status": status,
    "timezone": getattr(tz, "key", None) or str(tz),
    "weeks": weeks,
    "learning": {
      "days": profile.days,
      "days_needed": MIN_PROFILE_DAYS,
      "sessions": len(sessions),
      "sessions_needed": MIN_PROFILE_SESSIONS,
    },
    "grid": grid,
    "schedule": usual_schedule(profile) if status == "ready" else None,
    "presence_while_watched": round(profile.coverage, 3) if sessions else None,
    "monitored": round(profile.monitored, 3) if profile.monitored is not None else None,
    "monitored_enough": profile.monitored is not None and profile.monitored >= MIN_MONITORED,
    "sessions": [s.to_dict() for s in sessions[-100:]],
    "observation_windows": [{"start": a.isoformat(), "end": b.isoformat()} for a, b in windows[-200:]],
  }


def network_presence(repo: Repository, network_id: int | None = None, hours: int = 24, now: datetime | None = None) -> dict[str, Any]:
  """who was connected in the last `hours`, per identity, plus the periods beacon was watching."""
  now = now or utcnow()
  since = now - timedelta(hours=hours)
  devices = [d for d in repo.list_devices(network_id=network_id) if d.last_seen and d.last_seen >= since or d.status == DeviceStatus.ONLINE]
  latest: dict[Any, Device] = {}
  for device in sorted(devices, key=lambda d: d.last_seen or now):
    latest[device.identity_id if device.identity_id is not None else device.key] = device
  chosen = list(latest.values())
  sessions = repo.sessions_by_identity(chosen, since=since)
  windows = repo.observation_windows(since, app_settings.presence_gap(repo), network_id)
  watched = watched_seconds(since, now, windows, SESSION_GAP)
  return {
    "since": since.isoformat(),
    "until": now.isoformat(),
    "timezone": app_settings.timezone_name(repo),
    "devices": [
      {
        "device": device_summary(d),
        "profilable": is_profilable(d),
        "sessions": [s.to_dict() for s in sessions.get(d.key, [])],
      }
      for d in chosen
      if sessions.get(d.key)
    ],
    "observation_windows": [{"start": a.isoformat(), "end": b.isoformat()} for a, b in windows],
    "watched_share": round(min(1.0, watched / (hours * 3600)), 3) if hours else None,
    "enabled": app_settings.load(repo)["presence"]["enabled"],
  }


def watched_share(repo: Repository, network_id: int | None = None, hours: int = 24, now: datetime | None = None) -> float | None:
  """share of the last `hours` beacon was watching, without loading any session."""
  now = now or utcnow()
  since = now - timedelta(hours=hours)
  windows = repo.observation_windows(since, app_settings.presence_gap(repo), network_id)
  return round(min(1.0, watched_seconds(since, now, windows, SESSION_GAP) / (hours * 3600)), 3) if hours else None
