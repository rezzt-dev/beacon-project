 # import libraries ->
import copy
from datetime import UTC, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from beacon.core.presence import SESSION_GAP, local_tz
from beacon.storage import Repository
from beacon.storage.admin import RetentionPolicy


 # defaults ->
# every user preference with its default; anything stored is validated against this shape
DEFAULTS: dict[str, Any] = {
  "language": "auto",
  "theme": "system",
  "density": "comfortable",
  "timezone": "local",
  "monitor_interval": 60,
  "presence": {"enabled": True, "in_reports": False},
  "retention": RetentionPolicy().to_dict(),
  "notifications": {"desktop": False},
  # passive listening needs privileges; off unless chosen
  "passive": {"enabled": False},
  "onboarded": False,
}
LANGUAGES = ("auto", "es", "en")
THEMES = ("system", "light", "dark")
DENSITIES = ("comfortable", "compact")


class SettingsError(ValueError):
  def __init__(self, message: str, field_name: str) -> None:
    super().__init__(message)
    self.field = field_name


 # access ->
def load(repo: Repository) -> dict[str, Any]:
  stored = repo.all_settings()
  merged = copy.deepcopy(DEFAULTS)
  for key, value in stored.items():
    if key not in DEFAULTS:
      continue
    if isinstance(DEFAULTS[key], dict) and isinstance(value, dict):
      merged[key] = {**merged[key], **value}
    else:
      merged[key] = value
  return merged


def update(repo: Repository, changes: dict[str, Any], actor: str) -> dict[str, Any]:
  """validate every change first, then store them; an invalid field changes nothing."""
  current = load(repo)
  validated: dict[str, Any] = {}
  for key, value in changes.items():
    if key not in DEFAULTS:
      raise SettingsError(f"unknown setting {key!r}", key)
    validated[key] = _validate(key, value, current[key])
  for key, value in validated.items():
    repo.set_setting(key, value, actor)
  return load(repo)


def _validate(key: str, value: Any, current: Any) -> Any:
  if key == "language" and value not in LANGUAGES:
    raise SettingsError(f"language must be one of {', '.join(LANGUAGES)}", key)
  if key == "theme" and value not in THEMES:
    raise SettingsError(f"theme must be one of {', '.join(THEMES)}", key)
  if key == "density" and value not in DENSITIES:
    raise SettingsError(f"density must be one of {', '.join(DENSITIES)}", key)
  if key == "timezone" and (not isinstance(value, str) or (value != "local" and not _zone(value))):
    raise SettingsError("timezone must be 'local' or an iana name such as Europe/Madrid", key)
  if key == "monitor_interval" and (not isinstance(value, int) or isinstance(value, bool) or not 10 <= value <= 86400):
    raise SettingsError("monitor_interval is a number of seconds between 10 and 86400", key)
  if key == "onboarded" and not isinstance(value, bool):
    raise SettingsError("onboarded must be true or false", key)
  if key in ("presence", "notifications", "passive"):
    if not isinstance(value, dict) or any(k not in current or not isinstance(v, bool) for k, v in value.items()):
      raise SettingsError(f"{key} accepts only {', '.join(current)} as true/false", key)
    return {**current, **value}
  if key == "retention":
    if not isinstance(value, dict):
      raise SettingsError("retention is an object of day counts", key)
    try:
      return RetentionPolicy.from_dict({**current, **value}).to_dict()
    except ValueError as exc:
      raise SettingsError(str(exc), key) from exc
  return value


def _zone(name: str) -> tzinfo | None:
  try:
    return ZoneInfo(name)
  except (ZoneInfoNotFoundError, ValueError):
    return None


def timezone(repo: Repository) -> tzinfo:
  name = load(repo)["timezone"]
  return (local_tz() if name == "local" else _zone(name)) or UTC


def timezone_name(repo: Repository) -> str:
  name = load(repo)["timezone"]
  if name != "local":
    return name
  zone = local_tz()
  return getattr(zone, "key", None) or str(zone)


def presence_gap(repo: Repository) -> timedelta:
  """two scans further apart than this leave an unwatched gap; it follows the monitor's pace."""
  return max(SESSION_GAP, timedelta(seconds=3 * load(repo)["monitor_interval"]))


def retention(repo: Repository) -> RetentionPolicy:
  return RetentionPolicy.from_dict(load(repo)["retention"])
