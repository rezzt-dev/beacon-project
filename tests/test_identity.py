 # import libraries ->
from datetime import timedelta

from beacon.core.identity import (
  AMBIGUITY_MARGIN,
  IdentityResolver,
  LinkLevel,
  fingerprint,
  normalize_hostname,
  score,
  suggest_links,
  ttl_family,
)
from beacon.core.models import DeviceStatus
from conftest import T0, make_device


OLD = "8e:e7:35:fe:0c:c6"
NEW = "9a:11:22:33:44:55"
OTHER = "ae:00:00:00:00:01"
SERVICES = ["_airplay._tcp", "_companion-link._tcp", "_raop._tcp"]


def phone(ip, mac, **kwargs):
  defaults = {"randomized_mac": True, "hostname": "iphone-de-ana", "services": SERVICES, "ttl": 64}
  return make_device(ip, mac, **{**defaults, **kwargs})


 # fingerprint ->
def test_hostnames_are_normalized_and_generic_ones_discarded():
  assert normalize_hostname("iPhone-de-Ana.local") == "iphone-de-ana"
  assert normalize_hostname("iphone-de-ana-2") == "iphone-de-ana"
  assert normalize_hostname("iphone-de-ana(3)") == "iphone-de-ana"
  assert normalize_hostname("android") is None
  assert normalize_hostname("iphone") is None
  assert normalize_hostname(None) is None


def test_ttl_families():
  assert [ttl_family(t) for t in (None, 52, 64, 117, 128, 250)] == [None, 64, 64, 128, 128, 255]


 # scoring ->
def test_same_hostname_and_services_reach_the_probable_threshold_with_evidence():
  value, evidence = score(fingerprint(phone("192.168.1.9", OLD)), fingerprint(phone("192.168.1.10", NEW)))
  assert value >= 0.80
  assert "same hostname iphone-de-ana" in evidence
  assert "same 3 mdns services" in evidence


def test_services_are_weighed_by_jaccard_similarity():
  a = phone("192.168.1.9", OLD, hostname=None, services=["_a._tcp", "_b._tcp"])
  b = phone("192.168.1.10", NEW, hostname=None, services=["_b._tcp", "_c._tcp"])
  value, evidence = score(fingerprint(a), fingerprint(b))
  assert evidence[0] == "1 mdns services in common"
  assert value == round(0.25 / 3 + 0.05 + 0.05, 2)


def test_generic_hostnames_add_no_points():
  a = phone("192.168.1.9", OLD, hostname="android", services=[])
  b = phone("192.168.1.10", NEW, hostname="android", services=[])
  _, evidence = score(fingerprint(a), fingerprint(b))
  assert not any("hostname" in e for e in evidence)


def test_ttl_and_network_alone_never_reach_a_link():
  a = phone("192.168.1.9", OLD, hostname=None, services=[])
  b = phone("192.168.1.10", NEW, hostname=None, services=[])
  value, _ = score(fingerprint(a), fingerprint(b))
  assert value == 0.10
  assert IdentityResolver().match(b, [a]) == []


def test_matching_ports_add_evidence():
  a = phone("192.168.1.9", OLD, hostname=None, services=[], ports=(22, 80))
  b = phone("192.168.1.10", NEW, hostname=None, services=[], ports=(22, 80))
  _, evidence = score(fingerprint(a), fingerprint(b))
  assert "same open ports (22, 80)" in evidence


 # resolver ->
def test_only_randomized_other_devices_are_candidates():
  new = phone("192.168.1.10", NEW)
  pool = [
    phone("192.168.1.9", OLD),
    phone("192.168.1.11", OTHER, randomized_mac=False),
    phone("192.168.1.12", "ae:00:00:00:00:02", is_local=True),
    new,
  ]
  assert [m.candidate_key for m in IdentityResolver().match(new, pool)] == [OLD]


def test_best_returns_a_unique_probable_match():
  new = phone("192.168.1.10", NEW)
  best = IdentityResolver().best(new, [phone("192.168.1.9", OLD), phone("192.168.1.8", OTHER, hostname="other-phone", services=["_x._tcp"])])
  assert best is not None and best.candidate_key == OLD and best.level == LinkLevel.PROBABLE


def test_ambiguous_candidates_do_not_produce_a_proposal():
  new = phone("192.168.1.10", NEW)
  twin = phone("192.168.1.8", OTHER)
  assert IdentityResolver().best(new, [phone("192.168.1.9", OLD), twin]) is None
  matches = IdentityResolver().match(new, [phone("192.168.1.9", OLD), twin])
  assert matches[0].score - matches[1].score < AMBIGUITY_MARGIN


def test_possible_matches_are_listed_but_never_proposed():
  new = phone("192.168.1.10", NEW, services=[])
  old = phone("192.168.1.9", OLD, services=[])
  matches = IdentityResolver().match(new, [old])
  assert [m.level for m in matches] == [LinkLevel.POSSIBLE]
  assert IdentityResolver().best(new, [old]) is None


def test_devices_of_the_same_identity_are_not_proposed_again():
  new = phone("192.168.1.10", NEW, identity_id=3)
  assert IdentityResolver().match(new, [phone("192.168.1.9", OLD, identity_id=3)]) == []


 # stored pairs ->
def test_suggest_links_only_pairs_devices_that_never_overlapped():
  old = phone("192.168.1.9", OLD, first_seen=T0, last_seen=T0 + timedelta(days=1), status=DeviceStatus.OFFLINE)
  new = phone("192.168.1.10", NEW, first_seen=T0 + timedelta(days=2), last_seen=T0 + timedelta(days=3))
  overlapping = phone("192.168.1.8", OTHER, first_seen=T0, last_seen=T0 + timedelta(days=5))
  links = suggest_links([old, new])
  assert [(m.new_key, m.candidate_key) for m in links] == [(NEW, OLD)]
  # two phones online at the same time cannot be the same one
  assert suggest_links([overlapping, new]) == []
