 # import libraries ->
from ipaddress import IPv4Network, ip_network
from typing import Any

from beacon.core.models import ScanMode
from beacon.pipeline import ScanOptions
from beacon.scanners.ports import parse_port_spec
from beacon.storage import Repository


 # validation ->
OPTION_TYPES: dict[str, tuple[type, Any, Any]] = {
  # name: (type, minimum, maximum) - booleans have no range
  "discovery_timeout": (float, 0.1, 30.0),
  "port_timeout": (float, 0.1, 30.0),
  "latency_samples": (int, 0, 50),
  "host_concurrency": (int, 1, 512),
  "port_concurrency": (int, 1, 4096),
  "resolve_hostnames": (bool, None, None),
  "grab_banners": (bool, None, None),
  "identity": (bool, None, None),
  "presence": (bool, None, None),
  "tls": (bool, None, None),
  "ipv6": (bool, None, None),
}
MAX_EXCLUDE = 256
# scanning is only offered on private ranges: the live app must never become a scanner of the internet
_ALLOWED = [
  ip_network("10.0.0.0/8"),
  ip_network("172.16.0.0/12"),
  ip_network("192.168.0.0/16"),
  ip_network("100.64.0.0/10"),
  ip_network("169.254.0.0/16"),
]


class ProfileError(ValueError):
  def __init__(self, message: str, field_name: str) -> None:
    super().__init__(message)
    self.field = field_name


def check_scope(target: str) -> IPv4Network:
  """a scan target must be a private ipv4 range of at most /16."""
  try:
    network = IPv4Network(target, strict=False)
  except ValueError as exc:
    raise ProfileError(f"invalid network {target!r}: {exc}", "target") from exc
  if network.prefixlen < 16:
    raise ProfileError("the target is too large: use a /16 or smaller", "target")
  if not any(network.subnet_of(allowed) for allowed in _ALLOWED):
    raise ProfileError("only private ranges can be scanned (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16)", "target")
  return network


def validate(values: dict[str, Any], partial: bool = False) -> dict[str, Any]:
  """check and normalize profile fields; `partial` validates only what is present (edits)."""
  clean: dict[str, Any] = {}
  if not partial or "name" in values:
    name = str(values.get("name") or "").strip()
    if not 1 <= len(name) <= 64:
      raise ProfileError("name is required (at most 64 characters)", "name")
    clean["name"] = name
  if "target" in values:
    clean["target"] = str(check_scope(values["target"])) if values["target"] else None
  if "interface" in values:
    interface = values["interface"]
    if interface is not None and (not isinstance(interface, str) or not 1 <= len(interface) <= 64):
      raise ProfileError("interface must be an interface name", "interface")
    clean["interface"] = interface or None
  if "exclude" in values:
    exclude = values["exclude"] or []
    if not isinstance(exclude, list) or len(exclude) > MAX_EXCLUDE:
      raise ProfileError(f"exclude is a list of at most {MAX_EXCLUDE} addresses or ranges", "exclude")
    try:
      clean["exclude"] = [str(ip_network(str(item).strip(), strict=False)) for item in exclude if str(item).strip()]
    except ValueError as exc:
      raise ProfileError(f"invalid exclusion: {exc}", "exclude") from exc
  if "ports" in values:
    spec = values["ports"]
    if spec:
      try:
        parse_port_spec(str(spec))
      except ValueError as exc:
        raise ProfileError(str(exc), "ports") from exc
    clean["ports"] = str(spec) if spec else None
  if "interval_seconds" in values:
    interval = values["interval_seconds"]
    if interval is not None and (not isinstance(interval, int) or isinstance(interval, bool) or not 10 <= interval <= 86400):
      raise ProfileError("interval_seconds is between 10 and 86400, or null for manual scans", "interval_seconds")
    clean["interval_seconds"] = interval
  if "enabled" in values:
    if not isinstance(values["enabled"], bool):
      raise ProfileError("enabled must be true or false", "enabled")
    clean["enabled"] = values["enabled"]
  if "network_id" in values:
    if values["network_id"] is not None and not isinstance(values["network_id"], int):
      raise ProfileError("network_id must be a network id or null", "network_id")
    clean["network_id"] = values["network_id"]
  if "options" in values:
    clean["options"] = _options(values["options"] or {})
  return clean


def _options(options: dict[str, Any]) -> dict[str, Any]:
  if not isinstance(options, dict):
    raise ProfileError("options must be an object", "options")
  clean: dict[str, Any] = {}
  for key, value in options.items():
    if key == "mode":
      if value not in [m.value for m in ScanMode]:
        raise ProfileError("mode must be auto, privileged or unprivileged", "options.mode")
      clean[key] = value
      continue
    if key not in OPTION_TYPES:
      raise ProfileError(f"unknown option {key!r}", f"options.{key}")
    kind, low, high = OPTION_TYPES[key]
    if kind is bool:
      if not isinstance(value, bool):
        raise ProfileError(f"{key} must be true or false", f"options.{key}")
    else:
      if isinstance(value, bool) or not isinstance(value, (int, float)) or (kind is int and not isinstance(value, int)):
        raise ProfileError(f"{key} must be a number", f"options.{key}")
      if not low <= value <= high:
        raise ProfileError(f"{key} must be between {low} and {high}", f"options.{key}")
    clean[key] = value
  return clean


 # use ->
def create(repo: Repository, values: dict[str, Any], actor: str) -> dict[str, Any]:
  return repo.create_profile(validate(values), actor)


def update(repo: Repository, profile_id: int, values: dict[str, Any], version: int | None, actor: str) -> dict[str, Any]:
  return repo.update_profile(profile_id, validate(values, partial=True), version, actor)


def scan_options(profile: dict[str, Any] | None, trigger: str, save: bool = True) -> ScanOptions:
  """the options a scan runs with: the profile's choices on top of the cli defaults."""
  options = ScanOptions(trigger=trigger, save=save)
  if profile is None:
    return options
  options.target = profile["target"]
  options.interface = profile["interface"]
  options.exclude = tuple(profile["exclude"])
  options.ports = parse_port_spec(profile["ports"]) if profile["ports"] else ()
  options.profile_id = profile["id"]
  options.network_id = profile["network_id"]
  for key, value in profile["options"].items():
    if key == "mode":
      options.mode = ScanMode(value)
    else:
      setattr(options, key, value)
  if profile["interval_seconds"]:
    options.offline_grace = 2.0 * profile["interval_seconds"]
    options.presence_gap = max(options.presence_gap, 3.0 * profile["interval_seconds"])
  return options
