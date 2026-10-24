 # import libraries ->
import math
import statistics
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from enum import StrEnum
from typing import Any

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import Device


 # constants ->
# thresholds are a starting hypothesis: calibrate them with data from real networks
PROFILE_WEEKS = 4
MIN_PROFILE_DAYS = 14
MIN_PROFILE_SESSIONS = 6
UNUSUAL_BELOW = 0.10
USUAL_AT_LEAST = 0.50
ROUTINE_COVERAGE = 0.90
ROUTINE_DAYS = 14
MIN_ABSENCE = timedelta(minutes=30)
# a device missing for longer than this between two scans starts a new session instead of extending the old one
SESSION_GAP = timedelta(minutes=15)
# a device gone for longer than this is no longer a routine break but simply a device that left
MAX_ROUTINE_ABSENCE = timedelta(days=7)
ABSENCE_GAP_FACTOR = 3
# below this share of monitored time an absence cannot be told apart from beacon not watching
MIN_MONITORED = 0.5
HOUR = timedelta(hours=1)
DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_FULL_BUCKET = 0.5


 # sessions ->
@dataclass(slots=True)
class Session:
  """one continuous stay of a device on the network. `ended_at` is empty while it is still open."""

  device_key: str
  started_at: datetime
  last_seen: datetime
  ended_at: datetime | None = None

  @property
  def end(self) -> datetime:
    return self.ended_at or self.last_seen

  @property
  def is_open(self) -> bool:
    return self.ended_at is None

  def to_dict(self) -> dict[str, Any]:
    return {
      "device_key": self.device_key,
      "started_at": self.started_at.isoformat(),
      "ended_at": self.ended_at.isoformat() if self.ended_at else None,
      "last_seen": self.last_seen.isoformat(),
      "open": self.is_open,
    }


def local_tz() -> tzinfo:
  return datetime.now().astimezone().tzinfo or UTC


def _hour_start(moment: datetime, tz: tzinfo) -> datetime:
  """the start of the local hour containing `moment`, in utc (zones with half-hour offsets stay aligned)."""
  return moment.astimezone(tz).replace(minute=0, second=0, microsecond=0).astimezone(UTC)


 # profile ->
@dataclass(slots=True)
class PresenceProfile:
  """how often a device was present in each (weekday, hour) cell over the observed window."""

  cells: dict[tuple[int, int], tuple[int, int]] = field(default_factory=dict)
  sessions: int = 0
  span: timedelta = timedelta(0)
  coverage: float = 0.0
  typical_gap: timedelta = timedelta(0)
  # share of the recent window beacon was actually watching; none when that is unknown
  monitored: float | None = None

  @property
  def observed(self) -> bool:
    """long enough history to judge absences. a device that never leaves has one endless session."""
    return self.span >= timedelta(days=MIN_PROFILE_DAYS)

  @property
  def ready(self) -> bool:
    """enough history to judge arrivals: it needs several stays, not only a long one."""
    return self.observed and self.sessions >= MIN_PROFILE_SESSIONS

  @property
  def days(self) -> int:
    return self.span.days

  def frequency(self, weekday: int, hour: int) -> float | None:
    """share of observed (weekday, hour) slots in which the device was present, or none if never observed."""
    present, total = self.cells.get((weekday, hour), (0, 0))
    return present / total if total else None


def _overlaps(start: datetime, end: datetime, windows: Sequence[tuple[datetime, datetime]]) -> bool:
  return any(low <= end and high >= start for low, high in windows)


def build_profile(
  sessions: Sequence[Session],
  now: datetime,
  weeks: int = PROFILE_WEEKS,
  tz: tzinfo | None = None,
  observed: Sequence[tuple[datetime, datetime]] | None = None,
) -> PresenceProfile:
  """weekly presence grid from the sessions of the last `weeks` weeks. pure: `now` and `tz` are injected.

  hours are walked in utc and labelled in `tz`, so a daylight saving change makes a 23 or 25 hour
  day instead of shifting the grid. with `observed` (the windows beacon was really watching) an
  hour nobody watched is neither "present" nor "absent": it simply does not count.
  """
  tz = tz or local_tz()
  ordered = sorted(sessions, key=lambda s: s.started_at)
  if not ordered:
    return PresenceProfile()

  window_start = max(now - timedelta(weeks=weeks), ordered[0].started_at)
  origin = _hour_start(window_start, tz)
  slots = max(0, int((_hour_start(now, tz) - origin) / HOUR))
  present: set[int] = set()
  for session in ordered:
    if session.end < window_start:
      continue
    first = math.floor((max(session.started_at, window_start) - origin) / HOUR)
    last = max(first, math.ceil((session.end - origin) / HOUR) - 1)
    present.update(range(max(first, 0), min(last, slots - 1) + 1))

  windows = sorted(observed) if observed is not None else None
  counts: dict[tuple[int, int], list[int]] = {}
  for index in range(slots):
    slot = origin + index * HOUR
    if windows is not None and index not in present and not _overlaps(slot, slot + HOUR, windows):
      continue
    local = slot.astimezone(tz)
    cell = counts.setdefault((local.weekday(), local.hour), [0, 0])
    cell[0] += index in present
    cell[1] += 1

  return PresenceProfile(
    cells={cell: (hit, total) for cell, (hit, total) in counts.items()},
    sessions=len(ordered),
    span=now - ordered[0].started_at,
    coverage=_coverage(ordered, now, windows),
    typical_gap=_typical_gap(ordered),
    monitored=_monitored(ordered, now, windows),
  )


def _recent_start(sessions: Sequence[Session], now: datetime) -> datetime:
  return max(now - timedelta(days=ROUTINE_DAYS), sessions[0].started_at)


def watched_seconds(start: datetime, end: datetime, windows: Sequence[tuple[datetime, datetime]], slack: timedelta) -> float:
  """seconds of `[start, end]` covered by observation windows, each widened by `slack` (a scan vouches for a while)."""
  total = 0.0
  cursor = start
  for low, high in windows:
    low, high = max(low - slack, cursor), min(high + slack, end)
    if high > low:
      total += (high - low).total_seconds()
      cursor = high
  return total


def _coverage(sessions: Sequence[Session], now: datetime, windows: Sequence[tuple[datetime, datetime]] | None = None) -> float:
  """share of the last `ROUTINE_DAYS` (or of the observed span, if shorter) the device was present.

  with observation windows the share is of the time beacon was watching, not of wall-clock time.
  """
  start = _recent_start(sessions, now)
  window = (now - start).total_seconds()
  if windows is not None:
    window = watched_seconds(start, now, windows, SESSION_GAP)
  if window <= 0:
    return 0.0
  covered = sum(
    max(0.0, (min(s.end, now) - max(s.started_at, start)).total_seconds()) for s in sessions
  )
  return min(1.0, covered / window)


def _monitored(sessions: Sequence[Session], now: datetime, windows: Sequence[tuple[datetime, datetime]] | None) -> float | None:
  if windows is None:
    return None
  start = _recent_start(sessions, now)
  span = (now - start).total_seconds()
  if span <= 0:
    return None
  return min(1.0, watched_seconds(start, now, windows, SESSION_GAP) / span)


def _typical_gap(sessions: Sequence[Session]) -> timedelta:
  """median pause between consecutive sessions; zero when the device never left."""
  gaps = [
    (nxt.started_at - prev.end).total_seconds() for prev, nxt in zip(sessions, sessions[1:], strict=False)
  ]
  return timedelta(seconds=statistics.median(gaps)) if gaps else timedelta(0)


def is_profilable(device: Device) -> bool:
  """a randomized mac that is not linked to an identity rotates, so its sessions are fragments."""
  return not (device.randomized_mac and device.identity_id is None)


 # anomaly detection ->
def format_days(days: Collection[int]) -> str:
  """`mon-fri`, `sat,sun` or `mon,wed-fri` from weekday numbers."""
  ordered = sorted(days)
  runs: list[list[int]] = []
  for day in ordered:
    if runs and day == runs[-1][-1] + 1:
      runs[-1].append(day)
    else:
      runs.append([day])
  return ",".join(
    DAY_NAMES[run[0]] if len(run) == 1 else f"{DAY_NAMES[run[0]]}-{DAY_NAMES[run[-1]]}" for run in runs
  )


def usual_schedule(profile: PresenceProfile) -> str:
  """the days and hours the device is usually present, e.g. `mon-fri 08:00-19:00`."""
  usual = [cell for cell in profile.cells if (profile.frequency(*cell) or 0) >= USUAL_AT_LEAST]
  if not usual:
    return "at no fixed schedule"
  hours = [hour for _, hour in usual]
  return f"{format_days({day for day, _ in usual})} {min(hours):02d}:00-{max(hours) + 1:02d}:00"


def _name(device: Device) -> str:
  return device.alias or device.hostname or device.ip


def detect_anomalies(
  profiles: Mapping[str, PresenceProfile],
  arrivals: Iterable[Device],
  absent: Iterable[Device],
  now: datetime,
  already_flagged: Collection[str] = (),
  tz: tzinfo | None = None,
) -> list[Event]:
  """presence signals from learned profiles. pure: no database, no clock.

  `arrivals` are devices that just came back after being offline; `absent` are known devices the
  scan did not see. arrivals need a `ready` profile and absences an `observed` one.
  """
  tz = tz or local_tz()
  events: list[Event] = []

  for device in arrivals:
    profile = profiles.get(device.key)
    if profile is None or not profile.ready:
      continue
    local = now.astimezone(tz)
    frequency = profile.frequency(local.weekday(), local.hour)
    if frequency is None or frequency >= UNUSUAL_BELOW:
      continue
    events.append(
      Event(
        type=EventType.UNUSUAL_PRESENCE,
        severity=Severity.WARNING if device.trusted else Severity.ALERT,
        message=(
          f"{_name(device)} [{device.ip}] usually connects {usual_schedule(profile)}; "
          f"now it is {DAY_NAMES[local.weekday()]} {local:%H:%M}"
        ),
        device_key=device.key,
        ip=device.ip,
        mac=device.mac,
        details={"frequency": round(frequency, 2), "weekday": local.weekday(), "hour": local.hour},
        timestamp=now,
      )
    )

  for device in absent:
    profile = profiles.get(device.key)
    if profile is None or not profile.observed or device.key in already_flagged or device.last_seen is None:
      continue
    if profile.coverage < ROUTINE_COVERAGE:
      continue
    if profile.monitored is not None and profile.monitored < MIN_MONITORED:
      continue  # beacon was mostly not watching: an absence would only be a guess
    limit = max(ABSENCE_GAP_FACTOR * profile.typical_gap, MIN_ABSENCE)
    away = now - device.last_seen
    if away <= limit or away > MAX_ROUTINE_ABSENCE:
      continue
    events.append(
      Event(
        type=EventType.ROUTINE_BROKEN,
        severity=Severity.WARNING,
        message=(
          f"{_name(device)} [{device.ip}] is almost always online ({profile.coverage:.0%} of the last "
          f"{ROUTINE_DAYS} days) and has been missing for {format_duration(away)}"
        ),
        device_key=device.key,
        ip=device.ip,
        mac=device.mac,
        details={"coverage": round(profile.coverage, 2), "missing_seconds": int(away.total_seconds())},
        timestamp=now,
      )
    )
  return events


def format_duration(value: timedelta) -> str:
  seconds = int(value.total_seconds())
  if seconds < 3600:
    return f"{max(1, seconds // 60)} min"
  hours, minutes = divmod(seconds // 60, 60)
  if hours < 48:
    return f"{hours} h {minutes:02d} min" if minutes else f"{hours} h"
  return f"{hours // 24} d"


 # timeline ->
class Cell(StrEnum):
  ABSENT = "absent"
  PARTIAL = "partial"
  PRESENT = "present"


def timeline_cells(sessions: Iterable[Session], start: datetime, end: datetime, buckets: int) -> list[Cell]:
  """presence per equal slice of `[start, end)`: present when the device was there for most of the slice."""
  width = (end - start) / buckets
  covered = [0.0] * buckets
  touched = [False] * buckets
  for session in sessions:
    low, high = max(session.started_at, start), min(session.end, end)
    if low > high:
      continue
    first = min(buckets - 1, int((low - start) / width))
    last = min(buckets - 1, int((high - start) / width))
    for index in range(first, last + 1):
      slot_start = start + index * width
      overlap = (min(high, slot_start + width) - max(low, slot_start)) / width
      covered[index] += max(0.0, overlap)
      touched[index] = True
  return [
    Cell.PRESENT if covered[i] >= _FULL_BUCKET else Cell.PARTIAL if touched[i] else Cell.ABSENT
    for i in range(buckets)
  ]
