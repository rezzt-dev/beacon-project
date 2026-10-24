 # import libraries ->
import json

from beacon.scanners.ipv6 import parse_ip_neigh6_json, parse_ndp


 # neighbour tables ->
def test_ip_neigh_json_keeps_reachable_unicast_neighbours():
  output = json.dumps(
    [
      {"dst": "fe80::1", "dev": "wlan0", "lladdr": "34:5d:9e:3f:2a:77", "router": None, "state": ["REACHABLE"]},
      {"dst": "2001:db8::42", "dev": "wlan0", "lladdr": "B0:A7:B9:DC:71:4A", "state": ["STALE"]},
      {"dst": "2001:db8::99", "dev": "wlan0", "state": ["FAILED"]},
      {"dst": "ff02::1", "dev": "wlan0", "lladdr": "33:33:00:00:00:01", "state": ["NOARP"]},
      {"dst": "2001:db8::7", "dev": "wlan0", "lladdr": "01:00:5e:00:00:01", "state": ["REACHABLE"]},
    ]
  )
  assert parse_ip_neigh6_json(output) == [("fe80::1", "34:5d:9e:3f:2a:77"), ("2001:db8::42", "b0:a7:b9:dc:71:4a")]


def test_ndp_output_from_macos():
  output = (
    "Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
    "fe80::1%en0                     34:5d:9e:3f:2a:77    en0 23h59m58s S  R\n"
    "2001:db8::42                    b0:a7:b9:dc:71:4a    en0 permanent R\n"
    "ff02::fb                        33:33:0:0:0:fb       en0 permanent R\n"
  )
  assert parse_ndp(output) == [("fe80::1", "34:5d:9e:3f:2a:77"), ("2001:db8::42", "b0:a7:b9:dc:71:4a")]


def test_garbage_is_ignored():
  assert parse_ip_neigh6_json("[]") == [] and parse_ip_neigh6_json("") == []
  assert parse_ndp("header only\nnot a line\n") == []
