 # import libraries ->
import pytest

from beacon.core.mac import (
  is_locally_administered,
  is_multicast,
  is_randomized,
  is_valid_unicast,
  normalize_mac,
)


 # normalization ->
@pytest.mark.parametrize(
  "raw",
  [
    "34:5d:9e:3f:2a:77",
    "34-5D-9E-3F-2A-77",
    "345d.9e3f.2a77",
    "345D9E3F2A77",
    "  34:5d:9e:3f:2a:77\n",
  ],
)
def test_normalize_common_notations(raw):
  assert normalize_mac(raw) == "34:5d:9e:3f:2a:77"


def test_normalize_restores_stripped_zeros_from_macos():
  assert normalize_mac("0:1b:c5:0:0:a") == "00:1b:c5:00:00:0a"


@pytest.mark.parametrize("raw", [None, "", "zz:zz:zz:zz:zz:zz", "34:5d:9e:3f:2a", "34:5d-9e:3f:2a:77", "(incomplete)"])
def test_normalize_rejects_invalid(raw):
  assert normalize_mac(raw) is None


 # classification ->
def test_multicast_and_broadcast_are_not_unicast():
  assert is_multicast("01:00:5e:00:00:fb")
  assert not is_valid_unicast("ff:ff:ff:ff:ff:ff")
  assert not is_valid_unicast("00:00:00:00:00:00")
  assert not is_valid_unicast("01:00:5e:00:00:fb")
  assert is_valid_unicast("34:5d:9e:3f:2a:77")


def test_randomized_mac_detection():
  # second nibble 2, 6, a or e means locally administered
  for mac in ("02:11:22:33:44:55", "8e:e7:35:fe:0c:c6", "ba:38:e2:69:b9:4f", "fe:00:00:00:00:01"):
    assert is_locally_administered(mac)
    assert is_randomized(mac)
  assert not is_randomized("34:5d:9e:3f:2a:77")
  # locally administered multicast is not a device address
  assert not is_randomized("03:00:00:00:00:01")
