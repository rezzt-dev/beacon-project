"""browser tests of beacon live: real chromium, real server, simulated network.

they need playwright and its chromium (`python -m playwright install chromium`); without them
the module is skipped. the scanner is replaced by a fake, so no packet leaves the machine.
"""

 # import libraries ->
import socket
import threading
import time
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest


playwright = pytest.importorskip("playwright.sync_api")

from beacon.config import Settings  # noqa: E402
from beacon.core.events import Event, EventType, Severity  # noqa: E402
from beacon.core.models import ScanMode, utcnow  # noqa: E402
from beacon.core.ports import PortSet  # noqa: E402
from beacon.core.report import ScanReport  # noqa: E402
from beacon.scanners.network import InterfaceInfo  # noqa: E402
from beacon.storage import Database, Repository  # noqa: E402
from beacon.web import jobs as jobs_module  # noqa: E402
from beacon.web.server import LiveConfig, create_app  # noqa: E402
from conftest import make_device  # noqa: E402


pytestmark = pytest.mark.browser
ROUTER = "34:5d:9e:3f:2a:77"
CAMERA = "00:1b:c5:00:00:50"
PHONE = "8e:e7:35:fe:0c:c6"
PHONE_2 = "9a:11:22:33:44:55"
LAPTOP = "b0:a7:b9:dc:71:4a"


 # fake network ->
class FakePipeline:
  def __init__(self, repository, vendors, bus=None, progress=None, after_save=None) -> None:
    self.repository = repository
    self.progress = progress
    self.after_save = after_save or []

  async def run(self, options):
    import asyncio

    if self.progress is not None:
      self.progress.stage("fake sweep", 3)
      for _ in range(3):
        await asyncio.sleep(0.05)
        self.progress.advance()
    now = utcnow()
    devices = [
      make_device("192.168.1.1", ROUTER, vendor="Sagemcom", is_gateway=True, first_seen=now, last_seen=now),
      make_device("192.168.1.20", LAPTOP, vendor="TP-Link", hostname="ana-laptop", first_seen=now, last_seen=now),
      make_device("192.168.1.50", CAMERA, ports=(23, 80), first_seen=now, last_seen=now),
    ]
    first = not self.repository.load_devices()
    events = [Event(EventType.NEW_DEVICE, Severity.WARNING, f"device found: {d.ip}", device_key=d.key, timestamp=now) for d in devices] if first else []
    report = ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=devices, events=events, trigger=options.trigger, port_spec=PortSet([23, 80, 443]))
    report.scan_id = self.repository.save_scan(report)
    for hook in self.after_save:
      hook(report)
    return report


def _free_port() -> int:
  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    return sock.getsockname()[1]


class LiveServer:
  def __init__(self, settings: Settings) -> None:
    import uvicorn

    self.port = _free_port()
    self.app = create_app(settings, LiveConfig(port=self.port))
    self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error", timeout_graceful_shutdown=1))
    self.thread = threading.Thread(target=self.server.run, daemon=True)

  @property
  def base(self) -> str:
    return f"http://127.0.0.1:{self.port}"

  def __enter__(self) -> "LiveServer":
    self.thread.start()
    deadline = time.monotonic() + 10
    while not self.server.started and time.monotonic() < deadline:
      time.sleep(0.05)
    return self

  def __exit__(self, *_exc) -> None:
    self.app.state.stream.close()
    self.server.should_exit = True
    self.thread.join(10)


 # fixtures ->
@pytest.fixture
def settings(tmp_path, monkeypatch):
  monkeypatch.setenv("BEACON_HOME", str(tmp_path))
  monkeypatch.delenv("BEACON_DB", raising=False)
  monkeypatch.setattr(jobs_module, "ScanPipeline", FakePipeline)
  monkeypatch.setattr(jobs_module, "lease_scope", lambda target, iface: "net:192.168.1.0/24")
  iface = InterfaceInfo("eth0", IPv4Address("192.168.1.5"), IPv4Network("192.168.1.0/24"), "aa:aa:aa:aa:aa:aa", gateway=IPv4Address("192.168.1.1"))
  monkeypatch.setattr("beacon.web.api.list_interfaces", lambda: [iface])
  return Settings.load()


def seed(settings: Settings) -> Repository:
  repo = Repository(Database(settings.db_path))
  now = utcnow()
  devices = [
    make_device("192.168.1.1", ROUTER, vendor="Sagemcom", trusted=True, is_gateway=True, first_seen=now - timedelta(days=20), last_seen=now),
    make_device("192.168.1.50", CAMERA, ports=(23, 80), vendor=None, first_seen=now, last_seen=now),
    make_device("192.168.1.20", LAPTOP, vendor="TP-Link", trusted=True, hostname="ana-laptop", first_seen=now - timedelta(days=20), last_seen=now),
    make_device("192.168.1.9", PHONE, randomized_mac=True, hostname="iphone-de-ana", services=["_airplay._tcp"], first_seen=now - timedelta(days=3), last_seen=now - timedelta(days=1)),
  ]
  events = [Event(EventType.NEW_DEVICE, Severity.ALERT, "camera joined", device_key=CAMERA, timestamp=now)]
  for hours in range(48, 0, -1):
    moment = now - timedelta(hours=hours)
    present = [d for d in devices[:3] if d.first_seen <= moment]
    for d in present:
      d.last_seen = moment
    repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, moment, finished_at=moment, devices=present, port_spec=PortSet([23, 80, 443])))
  for d in devices:
    d.last_seen = now
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=devices, events=events, port_spec=PortSet([23, 80, 443])))
  repo.set_setting("onboarded", True, "test")
  return repo


@pytest.fixture(scope="module")
def browser():
  with playwright.sync_playwright() as p:
    try:
      launched = p.chromium.launch()
    except Exception as exc:  # no browser downloaded
      pytest.skip(f"chromium is not available: {exc}")
    yield launched
    launched.close()


@pytest.fixture
def live(settings):
  with LiveServer(settings) as server:
    yield server


def open_page(browser, server, width=1280, height=900, path="/"):
  context = browser.new_context(viewport={"width": width, "height": height}, locale="en-US")
  page = context.new_page()
  errors: list[str] = []
  page.on("pageerror", lambda e: errors.append(str(e)))
  page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
  page.goto(f"{server.base}/login#token={server.app.state.auth.token}")
  wait_until(page, "location.pathname !== '/login' && document.querySelector('main h1') !== null")
  if path != "/":
    page.goto(server.base + path)
  page.errors = errors
  return page


def wait_until(page, expression: str, timeout: float = 10.0) -> None:
  """poll with `evaluate`: the page's csp forbids the string eval `wait_for_function` relies on."""
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    try:
      if page.evaluate(expression):
        return
    except playwright.Error:  # the page is navigating: try again on the next document
      pass
    time.sleep(0.05)
  raise AssertionError(f"timed out waiting for {expression}")


def overflow(page) -> int:
  return page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")


 # first use ->
def test_first_use_guides_a_discovery_and_trusts_nothing_by_itself(browser, live):
  page = open_page(browser, live)
  page.wait_for_url("**/welcome")
  page.get_by_role("heading", name="which network do you want to watch?").wait_for()
  assert page.locator("input[name=iface]").first.is_checked()
  page.get_by_role("button", name="discover the network").click()
  page.get_by_role("heading", name="which devices do you recognize?").wait_for(timeout=10000)
  boxes = page.locator(".baseline input[type=checkbox]")
  assert boxes.count() == 3 and all(not boxes.nth(i).is_checked() for i in range(3))
  boxes.first.check()
  page.get_by_role("button", name="trust the ticked ones and continue").click()
  page.get_by_role("dialog").get_by_role("button", name="trust").click()
  page.wait_for_url(live.base + "/")
  repo = Repository(Database(Settings.load().db_path))
  assert sum(d.trusted for d in repo.load_devices().values()) == 1
  assert repo.get_setting("onboarded") is True
  assert page.errors == []


 # navigation ->
def test_any_view_opens_directly_and_survives_a_reload(browser, settings, live):
  seed(settings)
  page = open_page(browser, live, path=f"/devices/{CAMERA}")
  page.get_by_role("heading", level=1, name="192.168.1.50").wait_for()
  page.reload()
  page.get_by_role("heading", level=1, name="192.168.1.50").wait_for()
  assert page.locator("a.nav-link[aria-current=page]").inner_text().strip() == "devices"
  page.goto(live.base + "/nowhere")
  page.get_by_role("heading", name="page not found").wait_for()
  assert page.errors == []


def test_filters_live_in_the_url_and_come_back_after_reload(browser, settings, live):
  seed(settings)
  page = open_page(browser, live, path="/devices")
  page.locator("#devices-q").fill("laptop")
  wait_until(page, "location.search.includes('q=laptop')")
  wait_until(page, "document.querySelectorAll('table.devices tbody tr').length === 1")
  page.locator("#f-status").select_option("online")
  wait_until(page, "location.search.includes('status=online')")
  page.reload()
  assert page.locator("#devices-q").input_value() == "laptop"
  wait_until(page, "document.querySelectorAll('table.devices tbody tr').length === 1")
  assert "ana-laptop" in page.locator("table.devices").inner_text()


 # actions ->
def test_editing_an_alias_saves_it_and_stale_edits_are_caught(browser, settings, live):
  repo = seed(settings)
  page = open_page(browser, live, path=f"/devices/{CAMERA}")
  page.get_by_label("alias", exact=True).fill("garage camera")
  page.get_by_role("button", name="save").click()
  page.get_by_role("heading", level=1, name="garage camera").wait_for()
  assert repo.get_device(CAMERA).alias == "garage camera"
  # someone else edits while this page still holds the old version
  page.get_by_label("notes").fill("near the door")
  repo.update_device(CAMERA, {"owner": "ana"}, actor="cli")
  page.get_by_role("button", name="save").click()
  page.get_by_text("this device changed since you opened it.").wait_for()
  page.get_by_role("button", name="load the latest and keep my changes").click()
  page.get_by_role("button", name="save").click()
  wait_until(page, "document.querySelector('.toast') !== null")
  device = repo.get_device(CAMERA)
  assert (device.notes, device.owner) == ("near the door", "ana")


def test_review_trust_moves_focus_to_the_next_case(browser, settings, live):
  repo = seed(settings)
  repo.record_events([Event(EventType.NEW_DEVICE, Severity.WARNING, "phone back", device_key=PHONE)], network_id=1)
  page = open_page(browser, live, path="/review")
  page.locator("article.case").first.wait_for()
  assert page.locator("article.case").count() == 2
  first = page.locator("article.case").first
  name = first.locator("h2").inner_text()
  first.get_by_role("button", name="trust", exact=True).click()
  wait_until(page, "document.querySelectorAll('article.case').length === 1")
  focused = page.evaluate("document.activeElement.tagName + ':' + document.activeElement.textContent")
  assert focused.startswith("H2:") and name not in focused
  trusted = [d for d in repo.load_devices().values() if d.trusted]
  assert len(trusted) == 3


def test_identity_proposals_can_be_rejected_from_the_web(browser, settings, live):
  repo = seed(settings)
  now = utcnow()
  newer = make_device("192.168.1.10", PHONE_2, randomized_mac=True, hostname="iphone-de-ana", services=["_airplay._tcp"], first_seen=now + timedelta(minutes=1), last_seen=now + timedelta(minutes=1))
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=[newer]))
  page = open_page(browser, live, path="/identities")
  page.locator(".candidate").first.wait_for()
  page.get_by_role("button", name="not the same device").click()
  page.get_by_text("no proposals").wait_for()
  assert (PHONE_2, PHONE) in repo.rejected_pairs()


def test_presence_shows_unwatched_hours_and_a_table_alternative(browser, settings, live):
  seed(settings)
  page = open_page(browser, live, path=f"/presence?device={LAPTOP}")
  page.get_by_text("not watched").first.wait_for()
  figure = page.locator(".chart-block").first
  figure.get_by_role("button", name="show as table").click()
  assert figure.locator("table").is_visible()
  assert page.errors == []


def test_reports_download_a_standalone_file(browser, settings, live):
  seed(settings)
  page = open_page(browser, live, path="/reports")
  page.locator("#r-format").select_option("json")
  page.get_by_label("pseudonymize addresses and names").check()
  page.get_by_text("pseudonymized identifiers hide").wait_for()
  with page.expect_download() as download:
    page.get_by_role("link", name="download").click()
  content = Path(download.value.path()).read_text()
  assert '"device_count": 4' in content and ROUTER not in content


def test_alert_policies_and_maintenance_windows_from_the_web(browser, settings, live):
  repo = seed(settings)
  page = open_page(browser, live, path="/alerts")
  page.get_by_text("beacon sends nothing anywhere until you add one.").wait_for()
  page.get_by_role("button", name="new policy").click()
  dialog = page.get_by_role("dialog")
  dialog.get_by_label("name").fill("strangers")
  dialog.get_by_label("new device").check()
  dialog.get_by_role("button", name="save").click()
  page.get_by_text("strangers").wait_for()
  page.get_by_role("button", name="new silence").click()
  page.get_by_role("dialog").get_by_label("reason").fill("router update")
  page.get_by_role("dialog").get_by_role("button", name="save").click()
  page.get_by_text("router update").wait_for()
  [policy] = repo.list_policies()
  assert policy["event_types"] == ["new-device"] and policy["channels"] == []
  assert repo.list_silences()[0]["reason"] == "router update"


 # live connection ->
def test_the_page_reconnects_and_catches_up_after_losing_the_server(browser, settings, live):
  repo = seed(settings)
  page = open_page(browser, live, path=f"/devices/{LAPTOP}")
  page.locator(".live-dot.live").wait_for()
  page.context.set_offline(True)
  page.evaluate("window.dispatchEvent(new Event('offline'))")
  page.locator(".live-dot.offline").wait_for()
  repo.set_alias(LAPTOP, "changed while offline", actor="cli")
  page.context.set_offline(False)
  page.evaluate("window.dispatchEvent(new Event('online'))")
  page.locator(".live-dot.live").wait_for(timeout=15000)
  page.get_by_role("heading", level=1, name="changed while offline").wait_for(timeout=10000)


def test_pausing_updates_does_not_stop_the_monitor(browser, settings, live):
  repo = seed(settings)
  page = open_page(browser, live, path="/devices")
  page.locator(".live-dot.live").wait_for()
  page.keyboard.press("p")
  page.get_by_text("paused").first.wait_for()
  repo.set_alias(CAMERA, "camera while paused", actor="cli")
  page.get_by_text("1 update waiting").wait_for(timeout=10000)
  assert "camera while paused" not in page.locator("table.devices").inner_text()
  page.keyboard.press("p")
  wait_until(page, "document.querySelector('table.devices').innerText.includes('camera while paused')")


 # keyboard and mobile ->
def test_keyboard_shortcuts_and_dialog_focus(browser, settings, live):
  seed(settings)
  page = open_page(browser, live)
  page.get_by_role("heading", level=1, name="overview").wait_for()
  page.keyboard.press("/")
  assert page.evaluate("document.activeElement.id") == "global-q"
  page.keyboard.type("camera")
  page.keyboard.press("Enter")
  page.wait_for_url("**/devices?q=camera")
  page.locator("body").click()
  page.keyboard.press("g")
  page.keyboard.press("e")
  page.wait_for_url("**/events")
  page.keyboard.press("?")
  dialog = page.get_by_role("dialog")
  dialog.wait_for()
  for _ in range(5):
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.closest('[role=dialog]') !== null")
  page.keyboard.press("Escape")
  assert page.get_by_role("dialog").count() == 0


@pytest.mark.parametrize("width", [360, 768, 1280, 1920])
def test_no_view_overflows_the_page(browser, settings, live, width):
  seed(settings)
  page = open_page(browser, live, width=width)
  for path in ["/", "/devices", f"/devices/{CAMERA}", "/review", "/events", "/presence", "/identities", "/services", "/networks", "/scans", "/alerts", "/reports", "/settings"]:
    page.goto(live.base + path)
    page.locator("main h1").first.wait_for()
    page.wait_for_timeout(250)
    assert overflow(page) <= 0, f"{path} overflows at {width}px"
  assert page.errors == []


def test_the_menu_works_on_a_phone(browser, settings, live):
  seed(settings)
  page = open_page(browser, live, width=360, height=740)
  menu = page.get_by_role("button", name="menu")
  menu.click()
  assert menu.get_attribute("aria-expanded") == "true"
  page.locator("#sidebar").get_by_role("link", name="events").click()
  page.wait_for_url("**/events")
  assert menu.get_attribute("aria-expanded") == "false"


 # accessibility evidence ->
NAMES = """() => [...document.querySelectorAll('button, a[href], input, select, textarea')]
  .filter((el) => el.offsetParent !== null && el.type !== 'hidden')
  .filter((el) => {
    const label = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.textContent.trim() || el.title || el.placeholder
      || (el.id && document.querySelector(`label[for="${el.id}"]`)) || el.closest('label');
    return !label;
  }).map((el) => el.outerHTML.slice(0, 120))"""

CONTRAST = """() => {
  const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const rgb = (color) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = color; ctx.fillRect(0, 0, 1, 1); const d = ctx.getImageData(0, 0, 1, 1).data; return [d[0], d[1], d[2], d[3]]; };
  const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
  const background = (el) => { for (let n = el; n; n = n.parentElement) { const c = rgb(getComputedStyle(n).backgroundColor); if (c[3] > 200) return c; } return rgb(getComputedStyle(document.body).backgroundColor); };
  const failures = [];
  const walker = document.createTreeWalker(document.querySelector('main'), NodeFilter.SHOW_TEXT);
  let checked = 0;
  while (walker.nextNode() && checked < 400) {
    const el = walker.currentNode.parentElement;
    if (!walker.currentNode.textContent.trim() || !el || el.offsetParent === null || el.closest('svg, [aria-hidden=true]')) continue;
    checked++;
    const style = getComputedStyle(el);
    const fg = rgb(style.color); const bg = background(el);
    const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x);
    const ratio = (a + 0.05) / (b + 0.05);
    const large = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && Number(style.fontWeight) >= 700);
    if (ratio < (large ? 3 : 4.5)) failures.push(`${ratio.toFixed(2)} ${el.tagName}.${el.className}: ${walker.currentNode.textContent.trim().slice(0, 40)}`);
  }
  return { checked, failures };
}"""


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_text_contrast_and_accessible_names(browser, settings, live, theme):
  repo = seed(settings)
  repo.set_setting("theme", theme, "test")
  page = open_page(browser, live)
  for path in ["/", "/devices", f"/devices/{CAMERA}", "/review", "/events", "/scans", "/alerts", "/settings"]:
    page.goto(live.base + path)
    page.locator("main h1").first.wait_for()
    page.wait_for_timeout(300)
    assert page.evaluate(NAMES) == [], path
    result = page.evaluate(CONTRAST)
    assert result["checked"] > 5 and result["failures"] == [], f"{path}: {result['failures'][:5]}"


def test_headings_landmarks_and_language(browser, settings, live):
  repo = seed(settings)
  repo.set_setting("language", "es", "test")
  page = open_page(browser, live, path="/devices")
  page.get_by_role("heading", level=1, name="dispositivos").wait_for()
  assert page.evaluate("document.documentElement.lang") == "es"
  assert page.locator("main").count() == 1 and page.locator("nav[aria-label]").count() >= 1
  assert page.evaluate("document.querySelectorAll('main h1').length") == 1
  page.keyboard.press("Tab")
  assert page.evaluate("document.activeElement.className") == "skip-link"


def test_review_pages_are_reachable_and_empty_last_pages_recover(browser, settings, live):
  repo = seed(settings)
  now = utcnow()
  devices = [make_device(f"192.168.1.{i + 60}", f"00:11:22:33:44:{i:02x}", first_seen=now, last_seen=now) for i in range(22)]
  repo.save_scan(ScanReport("192.168.1.0/24", ScanMode.UNPRIVILEGED, now, finished_at=now, devices=devices,
                          events=[Event(EventType.NEW_DEVICE, Severity.WARNING, "joined", device_key=d.key) for d in devices]))
  page = open_page(browser, live, path="/review")
  wait_until(page, "document.querySelectorAll('article.case').length === 20")
  page.locator(".pager button").last.click()
  wait_until(page, "location.search.includes('page=2') && document.querySelectorAll('article.case').length === 3")
  for _ in range(3):
    page.locator("article.case").first.get_by_role("button", name="trust", exact=True).click()
  wait_until(page, "!location.search.includes('page=2') && document.querySelectorAll('article.case').length === 20")
  assert not page.errors
