 # import libraries ->
from datetime import timedelta

from beacon.core.events import Event, EventType, Severity
from beacon.core.risk import MAX_SCORE, RiskLevel, assess, events_at_risk, suggest_alias
from conftest import T0, make_device


NOW = T0 + timedelta(days=30)
MAC = "b0:a7:b9:dc:71:4a"


def known(mac=MAC, **kwargs):
  """a long-known, trusted device with a known vendor: the zero point of the score."""
  defaults = {"trusted": True, "vendor": "TP-Link", "first_seen": T0}
  return make_device("192.168.1.20", mac, **{**defaults, **kwargs})


def reasons(assessment):
  return [r.text for r in assessment.reasons]


 # factors ->
def test_a_known_trusted_device_has_no_risk():
  result = assess(known(), now=NOW)
  assert result.score == 0 and result.level == RiskLevel.LOW and result.reasons == []


def test_untrusted_is_a_factor():
  result = assess(known(trusted=False), now=NOW)
  assert result.score == 30 and reasons(result) == ["not trusted"]


def test_unknown_vendor_only_counts_when_the_mac_is_not_randomized():
  assert "unknown vendor" in reasons(assess(known(vendor=None), now=NOW))
  assert "unknown vendor" not in reasons(assess(known(vendor=None, randomized_mac=True), now=NOW))


def test_admin_ports_score_the_worst_one_fully_and_the_rest_less():
  result = assess(known(ports=(3389, 445, 23)), now=NOW)
  assert reasons(result)[0] == "telnet exposed (23)"
  assert result.score == 25 + 5 + 5


def test_cleartext_port_counts_once():
  result = assess(known(ports=(21, 22, 80)), now=NOW)
  assert result.score == 10 and len(result.reasons) == 1


def test_new_port_since_baseline_comes_from_events():
  device = known()
  opened = Event(EventType.PORT_OPENED, Severity.WARNING, "opened", device_key=device.key, details={"port": 8080})
  other = Event(EventType.PORT_OPENED, Severity.WARNING, "opened", device_key="someone-else", details={"port": 1})
  assert assess(device, [opened], now=NOW).score == 15
  assert assess(device, [other], now=NOW).score == 0


def test_ip_conflict_involving_the_device():
  device = known()
  conflict = Event(EventType.IP_CONFLICT, Severity.ALERT, "x", details={"macs": [MAC, "aa:bb:cc:dd:ee:ff"]})
  assert assess(device, [conflict], now=NOW).score == 40
  assert assess(known(mac=None), [conflict], now=NOW).score == 0


def test_recent_devices_score_and_missing_first_seen_counts_as_recent():
  assert assess(known(first_seen=NOW - timedelta(hours=2)), now=NOW).score == 10
  assert assess(known(first_seen=None), now=NOW).score == 10


def test_local_host_and_gateway_are_exempt():
  worst = {"trusted": False, "vendor": None, "ports": (23, 3389)}
  assert assess(make_device("192.168.1.5", MAC, is_local=True, **worst), now=NOW).score == 0
  assert assess(make_device("192.168.1.1", MAC, is_gateway=True, **worst), now=NOW).score == 0


def test_score_is_capped_and_levels_follow_thresholds():
  worst = make_device("192.168.1.66", MAC, ports=(23, 3389, 5900, 445, 22), trusted=False, first_seen=None)
  conflict = Event(EventType.IP_CONFLICT, Severity.ALERT, "x", details={"macs": [MAC]})
  result = assess(worst, [conflict], now=NOW)
  assert result.score == MAX_SCORE and result.level == RiskLevel.HIGH
  assert RiskLevel.from_score(24) == RiskLevel.LOW
  assert RiskLevel.from_score(25) == RiskLevel.MEDIUM
  assert RiskLevel.from_score(54) == RiskLevel.MEDIUM
  assert RiskLevel.from_score(55) == RiskLevel.HIGH


def test_ports_not_scanned_is_reported_instead_of_assumed_closed():
  result = assess(known(), ports_known=False, now=NOW)
  assert result.ports_known is False and result.to_dict()["ports_scanned"] is False


 # events at risk ->
def test_events_at_risk_ignores_info_and_low_risk_devices():
  risky = make_device("192.168.1.66", MAC, ports=(3389,), trusted=False)
  calm = known(mac="34:5d:9e:3f:2a:77")
  events = [
    Event(EventType.NEW_DEVICE, Severity.WARNING, "risky", device_key=risky.key),
    Event(EventType.IP_CHANGED, Severity.INFO, "info", device_key=risky.key),
    Event(EventType.NEW_DEVICE, Severity.ALERT, "calm", device_key=calm.key),
  ]
  found = events_at_risk([risky, calm], events, 55)
  assert [e.message for e in found] == ["risky"]
  assert events_at_risk([risky, calm], events, 100) == []


 # aliases ->
def test_suggest_alias_prefers_the_host_part_of_the_hostname():
  assert suggest_alias(make_device("192.168.1.9", MAC, hostname="ana-laptop.lan")) == "ana-laptop"


def test_suggest_alias_falls_back_to_vendor_and_last_octet():
  assert suggest_alias(make_device("192.168.1.9", MAC, vendor="TP-Link Systems Inc")) == "tp-link-9"
  assert suggest_alias(make_device("192.168.1.9", MAC)) == "device-9"
