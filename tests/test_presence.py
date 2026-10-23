 # import libraries ->
from datetime import UTC, datetime, timedelta, timezone

import pytest

from beacon.core.events import EventType, Severity
from beacon.core.presence import (
  MIN_PROFILE_DAYS,
  Cell,
  Session,
  build_profile,
  detect_anomalies,
  format_days,
  format_duration,
  is_profilable,
  timeline_cells,
  usual_schedule,
)
from conftest import make_device


KEY = "34:5d:9e:3f:2a:77"
# 2026-10-26 is a monday; the history covers five weeks of weekday office hours
MONDAY = datetime(2026, 9, 21, tzinfo=UTC)
NOW_SUNDAY_NIGHT = datetime(2026, 10, 25, 3, 12, tzinfo=UTC)
NOW_MONDAY_NOON = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def office_sessions(days=35, start_hour=9, end_hour=18):
  """one session per weekday from 9 to 18 h, utc."""
  sessions = []
  for offset in range(days):
    day = MONDAY + timedelta(days=offset)
    if day.weekday() < 5:
      sessions.append(
        Session(KEY, day.replace(hour=start_hour), day.replace(hour=end_hour), day.replace(hour=end_hour))
      )
  return sessions


def always_on(days=20, now=NOW_MONDAY_NOON):
  return [Session(KEY, now - timedelta(days=days), now - timedelta(minutes=5))]


 # sessions ->
def test_open_session_ends_at_last_seen():
  start = MONDAY
  open_session = Session(KEY, start, start + timedelta(hours=2))
  assert open_session.is_open and open_session.end == start + timedelta(hours=2)
  assert not Session(KEY, start, start + timedelta(hours=2), start + timedelta(hours=1)).is_open


# profile ->
def test_profile_grid_reflects_office_hours():
  profile = build_profile(office_sessions(), NOW_SUNDAY_NIGHT, tz=UTC)
  assert profile.frequency(0, 10) == 1.0  # monday 10:00
  assert profile.frequency(0, 3) == 0.0  # monday 03:00
  assert profile.frequency(6, 10) == 0.0  # sunday 10:00
  assert profile.ready


def test_profile_uses_the_given_time_zone():
  tz = timezone(timedelta(hours=2))
  profile = build_profile(office_sessions(), NOW_SUNDAY_NIGHT, tz=tz)
  assert profile.frequency(0, 12) == 1.0  # 10:00 utc is 12:00 at +02:00
  assert profile.frequency(0, 10) == 0.0


def test_half_hour_zone_keeps_cells_aligned():
  tz = timezone(timedelta(hours=5, minutes=30))
  profile = build_profile(office_sessions(), NOW_SUNDAY_NIGHT, tz=tz)
  assert profile.frequency(0, 15) == 1.0  # 10:00 utc is 15:30 local, inside the 9-18 h utc stay


def test_a_young_history_is_not_ready():
  profile = build_profile(office_sessions(days=10), MONDAY + timedelta(days=10), tz=UTC)
  assert not profile.ready and profile.days < MIN_PROFILE_DAYS


def test_too_few_sessions_is_not_ready():
  sessions = office_sessions(days=35)[:3]
  assert not build_profile(sessions, NOW_MONDAY_NOON, tz=UTC).ready


def test_empty_history_gives_an_empty_profile():
  profile = build_profile([], NOW_MONDAY_NOON, tz=UTC)
  assert not profile.ready and profile.frequency(0, 0) is None


def test_profile_ignores_sessions_older_than_the_window():
  old = [Session(KEY, MONDAY - timedelta(days=200), MONDAY - timedelta(days=200, hours=-1))]
  profile = build_profile(old + office_sessions(), NOW_SUNDAY_NIGHT, weeks=4, tz=UTC)
  assert profile.frequency(0, 10) == 1.0


def test_coverage_and_typical_gap():
  always = build_profile(always_on(), NOW_MONDAY_NOON, tz=UTC)
  assert always.coverage > 0.99 and always.typical_gap == timedelta(0)
  office = build_profile(office_sessions(), NOW_MONDAY_NOON, tz=UTC)
  assert office.coverage < 0.5 and office.typical_gap >= timedelta(hours=14)


def test_unlinked_randomized_devices_are_not_profilable():
  assert not is_profilable(make_device("192.168.1.9", KEY, randomized_mac=True))
  assert is_profilable(make_device("192.168.1.9", KEY, randomized_mac=True, identity_id=1))
  assert is_profilable(make_device("192.168.1.9", KEY))


def test_schedule_text():
  profile = build_profile(office_sessions(), NOW_SUNDAY_NIGHT, tz=UTC)
  assert usual_schedule(profile) == "mon-fri 09:00-18:00"
  assert format_days({0, 1, 2, 3, 4}) == "mon-fri"
  assert format_days({5, 6}) == "sat-sun"
  assert format_days({0, 2, 3, 4}) == "mon,wed-fri"


def test_durations_are_readable():
  assert format_duration(timedelta(minutes=5)) == "5 min"
  assert format_duration(timedelta(hours=3, minutes=10)) == "3 h 10 min"
  assert format_duration(timedelta(hours=5)) == "5 h"
  assert format_duration(timedelta(days=4)) == "4 d"


 # anomalies ->
def test_unusual_presence_on_a_sunday_at_3am_but_not_at_work_time():
  device = make_device("192.168.1.20", KEY, trusted=True, alias="office-laptop")
  profile = build_profile(office_sessions(), NOW_SUNDAY_NIGHT, tz=UTC)
  night = detect_anomalies({KEY: profile}, [device], [], NOW_SUNDAY_NIGHT, tz=UTC)
  assert [e.type for e in night] == [EventType.UNUSUAL_PRESENCE]
  assert night[0].severity == Severity.WARNING
  assert "usually connects mon-fri 09:00-18:00" in night[0].message
  assert "now it is sun 03:12" in night[0].message

  monday = datetime(2026, 10, 26, 10, 0, tzinfo=UTC)
  profile = build_profile(office_sessions(), monday, tz=UTC)
  assert detect_anomalies({KEY: profile}, [device], [], monday, tz=UTC) == []


def test_unusual_presence_of_an_untrusted_device_is_an_alert():
  device = make_device("192.168.1.20", KEY, trusted=False)
  profile = build_profile(office_sessions(), NOW_SUNDAY_NIGHT, tz=UTC)
  events = detect_anomalies({KEY: profile}, [device], [], NOW_SUNDAY_NIGHT, tz=UTC)
  assert events[0].severity == Severity.ALERT


def test_no_anomaly_before_the_learning_period_ends():
  device = make_device("192.168.1.20", KEY, trusted=True)
  now = MONDAY + timedelta(days=10, hours=-6)
  profile = build_profile(office_sessions(days=10), now, tz=UTC)
  assert not profile.ready
  assert detect_anomalies({KEY: profile}, [device], [], now, tz=UTC) == []
  assert detect_anomalies({}, [device], [], now, tz=UTC) == []


def test_routine_broken_for_an_always_on_device_missing_too_long():
  device = make_device("192.168.1.20", KEY, trusted=True, last_seen=NOW_MONDAY_NOON - timedelta(minutes=45))
  profile = build_profile(always_on(), NOW_MONDAY_NOON, tz=UTC)
  events = detect_anomalies({KEY: profile}, [], [device], NOW_MONDAY_NOON, tz=UTC)
  assert [e.type for e in events] == [EventType.ROUTINE_BROKEN]
  assert events[0].severity == Severity.WARNING
  assert "missing for 45 min" in events[0].message


def test_routine_is_not_broken_before_the_minimum_absence_or_when_already_reported():
  profile = build_profile(always_on(), NOW_MONDAY_NOON, tz=UTC)
  recent = make_device("192.168.1.20", KEY, last_seen=NOW_MONDAY_NOON - timedelta(minutes=10))
  assert detect_anomalies({KEY: profile}, [], [recent], NOW_MONDAY_NOON, tz=UTC) == []
  gone = make_device("192.168.1.20", KEY, last_seen=NOW_MONDAY_NOON - timedelta(hours=2))
  assert detect_anomalies({KEY: profile}, [], [gone], NOW_MONDAY_NOON, already_flagged={KEY}, tz=UTC) == []


def test_routine_is_not_broken_for_devices_that_come_and_go():
  profile = build_profile(office_sessions(), NOW_MONDAY_NOON, tz=UTC)
  gone = make_device("192.168.1.20", KEY, last_seen=NOW_MONDAY_NOON - timedelta(hours=3))
  assert detect_anomalies({KEY: profile}, [], [gone], NOW_MONDAY_NOON, tz=UTC) == []


def test_a_device_gone_for_over_a_week_is_not_a_routine_break():
  profile = build_profile(always_on(), NOW_MONDAY_NOON, tz=UTC)
  gone = make_device("192.168.1.20", KEY, last_seen=NOW_MONDAY_NOON - timedelta(days=9))
  assert detect_anomalies({KEY: profile}, [], [gone], NOW_MONDAY_NOON, tz=UTC) == []


 # timeline ->
def test_timeline_cells_mark_present_partial_and_absent():
  start = datetime(2026, 10, 24, 0, 0, tzinfo=UTC)
  end = start + timedelta(hours=4)
  sessions = [
    Session(KEY, start + timedelta(minutes=30), start + timedelta(hours=1, minutes=30), start + timedelta(hours=1, minutes=30)),
    Session(KEY, start + timedelta(hours=3, minutes=10), start + timedelta(hours=3, minutes=10)),
  ]
  assert timeline_cells(sessions, start, end, 4) == [Cell.PRESENT, Cell.PRESENT, Cell.ABSENT, Cell.PARTIAL]


def test_timeline_cells_without_sessions_are_absent():
  start = datetime(2026, 10, 24, tzinfo=UTC)
  assert timeline_cells([], start, start + timedelta(hours=1), 3) == [Cell.ABSENT] * 3


@pytest.mark.parametrize("buckets", [1, 8, 48])
def test_timeline_cells_cover_the_whole_window(buckets):
  start = datetime(2026, 10, 24, tzinfo=UTC)
  sessions = [Session(KEY, start - timedelta(hours=1), start + timedelta(hours=30), start + timedelta(hours=30))]
  assert set(timeline_cells(sessions, start, start + timedelta(hours=24), buckets)) == {Cell.PRESENT}
