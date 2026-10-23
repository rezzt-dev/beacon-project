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
