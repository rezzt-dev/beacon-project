 # import libraries ->
from dataclasses import replace
from datetime import timedelta

from beacon.core.events import Event, EventType, Severity
from beacon.core.exposure import Basis
from beacon.core.models import PortInfo, PortState
from beacon.core.risk import (
  MAX_SCORE,
  NEW_PORT_WINDOW,
  POINTS,
  RULES_VERSION,
  RiskLevel,
  assess,
  events_at_risk,
  suggest_alias,
)
from conftest import T0, make_device


NOW = T0 + timedelta(days=30)
MAC = "b0:a7:b9:dc:71:4a"


def known(mac=MAC, **kwargs):
  """a long-known, trusted device with a known vendor: the zero point of the score."""
  defaults = {"trusted": True, "vendor": "TP-Link", "first_seen": T0}
  return make_device("192.168.1.20", mac, **{**defaults, **kwargs})


def reasons(assessment):
  return [r.text for r in assessment.reasons]


def opened(device, port, at=NOW - timedelta(hours=1), **kwargs):
  return Event(EventType.PORT_OPENED, Severity.WARNING, "opened", device_key=device.key, details={"port": port}, timestamp=at, **kwargs)


 # factors ->
def test_a_known_trusted_device_has_no_risk():
  result = assess(known(), now=NOW)
  assert result.score == 0 and result.level == RiskLevel.LOW and result.reasons == []
  assert result.complete and result.rules_version == RULES_VERSION


def test_untrusted_is_a_factor():
  result = assess(known(trusted=False), now=NOW)
  assert result.score == 30 and reasons(result) == ["not trusted"]


def test_unknown_vendor_only_counts_for_a_real_vendor_mac():
  assert "unknown vendor" in reasons(assess(known(vendor=None), now=NOW))
  assert "unknown vendor" not in reasons(assess(known(vendor=None, randomized_mac=True), now=NOW))
  assert "unknown vendor" not in reasons(assess(known(mac=None, vendor=None), now=NOW))


def test_the_most_serious_exposure_scores_fully_and_the_rest_less():
  result = assess(known(ports=(3389, 445, 23)), now=NOW)
  assert "telnet on 23" in reasons(result)[0] and "unencrypted" in reasons(result)[0]
  assert result.score == POINTS["admin_plaintext"] + 2 * POINTS["extra_exposure"]


 # regression: ssh is administration over an encrypted protocol, never "cleartext" ->
def test_ssh_is_encrypted_remote_administration_not_a_cleartext_protocol():
  result = assess(known(ports=(22,)), now=NOW)
  [reason] = result.reasons
  assert reason.code == "admin-encrypted" and reason.points == POINTS["admin_encrypted"]
  assert "encrypted" in reason.text and "unencrypted" not in reason.text
  assert all(r.code != "plaintext" for r in result.reasons)


def test_a_port_number_is_an_inference_and_a_banner_is_an_observation():
  inferred = assess(known(ports=(22,)), now=NOW).reasons[0]
  assert inferred.basis == Basis.INFERRED and "inferred from the port number" in inferred.text
  device = known()
  device.ports = [PortInfo(2222, PortState.OPEN, protocol_observed="ssh")]
  observed = assess(device, now=NOW).reasons[0]
  assert observed.basis == Basis.OBSERVED and "ssh on 2222" in observed.text and "banner" in observed.text


def test_an_observed_protocol_overrides_the_port_convention():
  device = known()
  device.ports = [PortInfo(23, PortState.OPEN, protocol_observed="ssh")]
  assert assess(device, now=NOW).reasons[0].code == "admin-encrypted"


def test_plaintext_services_count_once():
  result = assess(known(ports=(80, 554, 1883)), now=NOW)
  assert [r.code for r in result.reasons] == ["plaintext"]
  assert result.score == POINTS["plaintext_service"]


def test_only_open_ports_are_exposure():
  device = known()
  device.ports = [PortInfo(23, PortState.CLOSED), PortInfo(3389, PortState.FILTERED)]
  assert assess(device, now=NOW).score == 0


 # regression: the gateway and this host are assessed too ->
def test_local_host_and_gateway_are_not_exempt():
  worst = {"trusted": False, "vendor": None, "ports": (23, 3389)}
  gateway = assess(make_device("192.168.1.1", MAC, is_gateway=True, **worst), now=NOW)
  assert gateway.score > 0 and any("telnet" in r for r in reasons(gateway))
  local = assess(make_device("192.168.1.5", MAC, is_local=True, **worst), now=NOW)
  assert any("telnet" in r for r in reasons(local))
  assert "first seen in the last 24 h" not in reasons(assess(make_device("192.168.1.5", MAC, is_local=True, first_seen=NOW), now=NOW))


def test_never_examined_ports_make_the_assessment_incomplete_instead_of_safe():
  result = assess(known(), ports_known=False, now=NOW)
  assert result.level == RiskLevel.LOW and not result.complete
  assert result.label == "low · incomplete"
  assert result.to_dict()["ports_scanned"] is False and result.to_dict()["risk_complete"] is False
  assert "unknown, not absent" in result.notes[0]


def test_old_port_data_is_flagged_as_possibly_outdated():
  result = assess(known(ports=(22,)), now=NOW, ports_checked_at=NOW - timedelta(days=20))
  assert any("may be outdated" in n for n in result.notes)


def test_an_open_port_that_timed_out_is_kept_and_explained():
  device = known()
  device.ports = [PortInfo(23, PortState.OPEN, last_probe=PortState.FILTERED)]
  result = assess(device, now=NOW)
  assert result.score == POINTS["admin_plaintext"] and any("did not answer" in n for n in result.notes)


 # regression: events count inside their window, reviewed or not ->
def test_a_new_port_counts_while_recent_and_still_open():
  device = known(ports=(8080,))
  assert assess(device, [opened(device, 8080)], now=NOW).score == POINTS["plaintext_service"] + POINTS["new_port"]
  old = opened(device, 8080, at=NOW - NEW_PORT_WINDOW - timedelta(hours=1))
  assert assess(device, [old], now=NOW).score == POINTS["plaintext_service"]
  closed_since = known()
  assert assess(closed_since, [opened(closed_since, 8080)], now=NOW).score == 0


def test_trusting_does_not_erase_the_evidence_of_a_new_port():
  device = known(ports=(8080,))
  reviewed = opened(device, 8080, acked_at=NOW)
  result = assess(device, [reviewed], now=NOW)
  assert any(r.code == "new-port" and "(reviewed)" in r.text for r in result.reasons)


def test_a_first_check_is_not_a_new_port():
  device = known(ports=(8080,))
  first = Event(EventType.PORT_OPENED, Severity.INFO, "found", device_key=device.key, details={"port": 8080, "first_check": True}, timestamp=NOW)
  assert all(r.code != "new-port" for r in assess(device, [first], now=NOW).reasons)


def test_events_of_other_devices_do_not_count():
  device = known(ports=(8080,))
  other = replace(opened(device, 8080), device_key="someone-else")
  assert assess(device, [other], now=NOW).score == POINTS["plaintext_service"]


def test_ip_conflict_counts_for_a_day():
  device = known()
  conflict = Event(EventType.IP_CONFLICT, Severity.ALERT, "x", details={"macs": [MAC, "aa:bb:cc:dd:ee:ff"]}, timestamp=NOW - timedelta(hours=2))
  assert assess(device, [conflict], now=NOW).score == POINTS["ip_conflict"]
  assert assess(known(mac=None), [conflict], now=NOW).score == 0
  stale = replace(conflict, timestamp=NOW - timedelta(days=2))
  assert assess(device, [stale], now=NOW).score == 0


def test_recent_devices_score_and_missing_first_seen_counts_as_recent():
  assert assess(known(first_seen=NOW - timedelta(hours=2)), now=NOW).score == 10
  assert assess(known(first_seen=None), now=NOW).score == 10


def test_reasons_are_serializable_with_their_basis():
  device = known(ports=(23,), trusted=False)
  details = assess(device, now=NOW).to_dict()["risk_details"]
  assert {d["code"] for d in details} == {"untrusted", "admin-plaintext"}
  assert next(d for d in details if d["code"] == "admin-plaintext")["basis"] == "inferred"


def test_score_is_capped_and_levels_follow_thresholds():
  worst = make_device("192.168.1.66", MAC, ports=(23, 3389, 5900, 445, 22, 6379), trusted=False, first_seen=None)
  conflict = Event(EventType.IP_CONFLICT, Severity.ALERT, "x", details={"macs": [MAC]}, timestamp=NOW)
  result = assess(worst, [conflict], now=NOW)
  assert result.score == MAX_SCORE and result.level == RiskLevel.HIGH
  assert RiskLevel.from_score(24) == RiskLevel.LOW
  assert RiskLevel.from_score(25) == RiskLevel.MEDIUM
  assert RiskLevel.from_score(54) == RiskLevel.MEDIUM
  assert RiskLevel.from_score(55) == RiskLevel.HIGH


 # events at risk ->
def test_events_at_risk_ignores_info_and_low_risk_devices():
  risky = make_device("192.168.1.66", MAC, ports=(3389, 23), trusted=False)
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


def test_network_wide_conflicts_do_not_leak_between_networks(repo):
  from beacon.services.risk import assess_devices

  first, other = known(network_id=1), known(network_id=2)
  repo.record_events([Event(EventType.IP_CONFLICT, Severity.ALERT, "conflict", details={"macs": [MAC]}, timestamp=NOW)], network_id=1)
  risks = assess_devices(repo, [first, other], now=NOW)
  assert risks[first.key].score == POINTS["ip_conflict"]
  assert risks[other.key].score == 0
