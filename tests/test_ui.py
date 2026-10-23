 # import libraries ->
from rich.console import Console

from beacon.ui.console import THEME
from beacon.ui.live import WatchView
from beacon.ui.render import devices_table, visible_columns
from conftest import make_device


 # helpers ->
def render(table, width: int) -> str:
  console = Console(width=width, record=True, force_terminal=False, theme=THEME)
  console.print(table)
  return console.export_text()


 # responsive device table ->
def test_wide_terminal_shows_every_column():
  assert visible_columns(160) == {"last seen", "os", "latency", "vendor", "open ports"}


def test_ports_column_only_when_requested():
  assert "open ports" not in visible_columns(160, show_ports=False)


def test_narrow_terminal_drops_optional_columns_first():
  assert visible_columns(100) == {"vendor"}
  assert visible_columns(80) == set()


def test_risk_column_is_opt_in_and_outlasts_the_other_optional_columns():
  assert "risk" not in visible_columns(160)
  assert visible_columns(160, show_risk=True) >= {"risk", "last seen"}
  assert visible_columns(80, show_risk=True) == {"risk"}
  assert visible_columns(60, show_risk=True) == set()


def test_ip_and_mac_are_never_truncated_on_narrow_terminals():
  device = make_device("192.168.100.200", "aa:bb:cc:dd:ee:ff")
  for width in (60, 80, 100, 120, 160):
    text = render(devices_table([device], width=width), width)
    assert "192.168.100.200" in text
    assert "aa:bb:cc:dd:ee:ff" in text


 # watch view ->
def test_watch_view_keeps_running_after_a_failed_scan():
  view = WatchView(interval=30)
  view.fail("no active ipv4 interface found")
  assert view.cycle == 1
  assert view.next_scan_at is not None
  text = render(view, 100)
  assert "no active ipv4 interface found" in text
  assert "retrying" in text


 # risk, identity and presence rendering ->
def test_risk_is_spelled_out_not_only_colored():
  from beacon.core.risk import assess
  from beacon.ui.render import risk_text

  device = make_device("192.168.1.9", "aa:bb:cc:dd:ee:ff", ports=(23,), trusted=False)
  text = risk_text(assess(device)).plain
  assert text.startswith("● high ")
  assert risk_text(None).plain == "—"


def test_devices_table_shows_risk_only_when_given_assessments():
  from beacon.core.risk import assess

  device = make_device("192.168.1.9", "aa:bb:cc:dd:ee:ff")
  assert "risk" not in render(devices_table([device], width=160), 160)
  shown = render(devices_table([device], width=160, risks={device.key: assess(device)}), 160)
  assert "risk" in shown and "medium" in shown


def test_linked_devices_carry_a_visible_mark():
  from beacon.ui.render import fmt_name

  assert "⛓" in fmt_name(make_device("192.168.1.9", "aa:bb:cc:dd:ee:ff", identity_id=2)).plain
  assert "⛓" not in fmt_name(make_device("192.168.1.9", "aa:bb:cc:dd:ee:ff")).plain


def test_heatmap_has_a_row_per_weekday_and_explains_a_young_profile():
  from datetime import UTC, datetime, timedelta

  from beacon.core.presence import Session, build_profile
  from beacon.ui.render import presence_heatmap

  now = datetime(2026, 10, 25, 3, 0, tzinfo=UTC)
  profile = build_profile([Session("k", now - timedelta(days=3, hours=-9), now - timedelta(days=3, hours=-12))], now, tz=UTC)
  text = render(presence_heatmap(profile), 100)
  assert all(day in text for day in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"))
  assert "█" in text and "still learning: 2/14 days · 1/6 sessions" in text


def test_timeline_table_marks_presence_with_shapes():
  from datetime import UTC, datetime, timedelta

  from beacon.core.presence import Cell
  from beacon.ui.render import timeline_table

  end = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
  device = make_device("192.168.1.9", "aa:bb:cc:dd:ee:ff", hostname="laptop")
  row = [Cell.PRESENT, Cell.PARTIAL, Cell.ABSENT] * 4
  text = render(timeline_table([(device, row)], end - timedelta(hours=12), end), 100)
  assert "laptop" in text and "█▒·█▒·" in text
