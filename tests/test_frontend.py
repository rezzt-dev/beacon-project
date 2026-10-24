 # import libraries ->
import re
from pathlib import Path


STATIC = Path(__file__).parents[1] / "app" / "beacon" / "web" / "static"
JS = STATIC / "assets" / "js"
KEY = re.compile(r'"([a-z0-9_.\-]+)":')
# keys built at runtime: prefix -> every suffix the code can produce
DYNAMIC = {
  "event.": "new-device device-online device-offline ip-changed port-opened port-closed ip-conflict identity-candidate unusual-presence routine-broken scan-failed scan-partial",
  "health.": "ok scanning idle empty stale failing blocked",
  "job.": "queued running completed failed cancelled blocked",
  "live.": "connecting live reconnecting offline",
  "scan.status.": "complete partial failed cancelled aborted running",
  "ports.state_": "open closed filtered error",
  "presence.status_": "fragmented no-data learning ready",
  "severity.": "alert warning info",
  "risk.": "low medium high",
  "basis.": "observed inferred history context",
  "exposure.": "remote-admin file-sharing database web media messaging printing other",
  "trigger.": "cli watch web monitor service demo",
  "monitor.passive_": "off listening unavailable",
  "alerts.status_": "pending sent failed dropped",
  "alerts.kind_": "desktop webhook",
}


def dictionaries() -> tuple[set[str], set[str]]:
  source = (JS / "strings.js").read_text()
  english = source[source.index("const en = {") : source.index("const es = {")]
  spanish = source[source.index("const es = {") : source.index("export const STRINGS")]
  return set(KEY.findall(english)), set(KEY.findall(spanish))


def scripts() -> list[Path]:
  return [p for p in JS.rglob("*.js") if p.name != "strings.js"]


 # strings ->
def test_both_languages_have_the_same_keys():
  english, spanish = dictionaries()
  assert english == spanish


def test_every_string_the_code_asks_for_exists():
  english, _ = dictionaries()
  used = {k for p in scripts() for k in re.findall(r'\bt\("([a-z0-9_.\-]+)"', p.read_text())}
  used |= {prefix + suffix for prefix, suffixes in DYNAMIC.items() for suffix in suffixes.split()}
  used = {k for k in used if not k.endswith((".", "_", "step"))}
  assert sorted(used - english) == []


 # safety of the page ->
def test_network_data_is_never_parsed_as_html():
  for path in scripts():
    text = path.read_text()
    assert "innerHTML" not in text and "outerHTML =" not in text and "insertAdjacentHTML" not in text, path
    assert "eval(" not in text and "new Function" not in text, path


def test_the_app_loads_nothing_from_other_origins():
  for path in [*STATIC.rglob("*.html"), *STATIC.rglob("*.css"), *STATIC.rglob("*.js")]:
    text = path.read_text()
    for url in re.findall(r"""(?:src|href|url\()\s*=?\s*["']?(https?://[^"')\s]+)""", text):
      assert url.startswith("http://www.w3.org/"), f"{path}: {url}"
    assert "<script>" not in text and " style=\"" not in text, f"{path} has inline code the csp would block"


def test_html_pages_are_in_the_package():
  for name in ("index.html", "login.html", "assets/css/app.css", "assets/css/tokens.css", "assets/js/main.js", "assets/favicon.svg"):
    assert (STATIC / name).is_file(), name
