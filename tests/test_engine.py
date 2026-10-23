 # import libraries ->
from ipaddress import IPv4Network

from beacon.core.engine import CleaningEngine, clean_banner, clean_hostname
from beacon.core.models import DiscoverySource as Src
from beacon.core.models import Latency, Observation


NET = IPv4Network("192.168.1.0/24")


 # merge and deduplication ->
def test_merges_observations_by_mac_across_notations(vendors):
  engine = CleaningEngine(vendors, NET)
  result = engine.merge(
    [
      Observation(ip="192.168.1.1", mac="34-5D-9E-3F-2A-77", source=Src.ARP_TABLE),
      Observation(ip="192.168.1.1", mac="345d.9e3f.2a77", source=Src.ARP_SWEEP),
      Observation(ip="192.168.1.1", source=Src.ICMP, ttl=63),
    ]
  )
  assert list(result.devices) == ["34:5d:9e:3f:2a:77"]
  device = result.devices["34:5d:9e:3f:2a:77"]
  assert device.vendor == "Sagemcom Broadband SAS"
  assert device.ttl == 63
  assert device.os_guess == "linux/unix/macos"
  assert device.sources == {"arp-table", "arp-sweep", "icmp"}


def test_mac_with_several_ips_keeps_primary_from_best_source():
  result = CleaningEngine(network=NET).merge(
    [
      Observation(ip="192.168.1.50", mac="b0:a7:b9:dc:71:4a", source=Src.ARP_TABLE),
      Observation(ip="192.168.1.20", mac="b0:a7:b9:dc:71:4a", source=Src.ARP_SWEEP),
    ]
  )
  device = result.devices["b0:a7:b9:dc:71:4a"]
  assert device.ip == "192.168.1.20"
  assert device.ips == ["192.168.1.20", "192.168.1.50"]


def test_ip_without_mac_becomes_ip_keyed_device():
  result = CleaningEngine(network=NET).merge([Observation(ip="192.168.1.9", source=Src.TCP)])
  assert list(result.devices) == ["ip:192.168.1.9"]
  assert result.devices["ip:192.168.1.9"].mac is None


 # filtering ->
def test_discards_invalid_and_out_of_network_addresses():
  result = CleaningEngine(network=NET).merge(
    [
      Observation(ip="192.168.1.0", mac="34:5d:9e:3f:2a:77", source=Src.ARP_TABLE),  # network address
      Observation(ip="192.168.1.255", mac="34:5d:9e:3f:2a:77", source=Src.ARP_TABLE),  # broadcast
      Observation(ip="10.0.0.1", mac="34:5d:9e:3f:2a:77", source=Src.ARP_TABLE),  # other network
      Observation(ip="not-an-ip", mac="34:5d:9e:3f:2a:77", source=Src.ARP_TABLE),
      Observation(ip="192.168.1.7", mac="00:00:00:00:00:00", source=Src.ARP_TABLE),  # incomplete entry
      Observation(ip="192.168.1.8", mac="ff:ff:ff:ff:ff:ff", source=Src.ARP_SWEEP),
    ]
  )
  assert result.devices == {}
  assert result.discarded == 6


def test_stale_cache_entries_need_confirmation():
  stale = Observation(ip="192.168.1.30", mac="b0:a7:b9:dc:71:4a", source=Src.ARP_TABLE, fresh=False)
  engine = CleaningEngine(network=NET)

  alone = engine.merge([stale])
  assert alone.devices == {} and alone.discarded == 1

  confirmed = engine.merge([stale, Observation(ip="192.168.1.30", source=Src.TCP)])
  assert list(confirmed.devices) == ["b0:a7:b9:dc:71:4a"]


def test_randomized_mac_is_flagged_not_unknown(vendors):
  result = CleaningEngine(vendors, NET).merge(
    [Observation(ip="192.168.1.139", mac="8e:e7:35:fe:0c:c6", source=Src.ARP_TABLE)]
  )
  device = result.devices["8e:e7:35:fe:0c:c6"]
  assert device.randomized_mac
  assert device.vendor is None
  assert device.display_vendor == "randomized (private mac)"


def test_ip_answered_by_two_macs_is_a_conflict():
  result = CleaningEngine(network=NET).merge(
    [
      Observation(ip="192.168.1.1", mac="34:5d:9e:3f:2a:77", source=Src.ARP_SWEEP),
      Observation(ip="192.168.1.1", mac="b0:a7:b9:dc:71:4a", source=Src.ARP_SWEEP),
      Observation(ip="192.168.1.1", source=Src.ICMP, ttl=64),
    ]
  )
  assert len(result.conflicts) == 1
  assert result.conflicts[0].ip == "192.168.1.1"
  assert result.conflicts[0].macs == ("34:5d:9e:3f:2a:77", "b0:a7:b9:dc:71:4a")
  # the ambiguous icmp reply is not attributed to either mac
  assert all(d.ttl is None for d in result.devices.values())


 # text cleaning ->
def test_clean_hostname():
  assert clean_hostname("Android-2.local.") == "android-2.local"
  assert clean_hostname("1.1.168.192.in-addr.arpa") is None
  assert clean_hostname("192.168.1.1") is None
  assert clean_hostname("bad name with spaces") is None
  assert clean_hostname("") is None


def test_clean_banner():
  assert clean_banner(b"SSH-2.0-OpenSSH_9.6\r\nextra") == "SSH-2.0-OpenSSH_9.6"
  assert clean_banner(b"\x00\x01\x02") is None
  assert clean_banner(b"  220   ftp\tready \x1b[0m") == "220 ftp ready [0m"
  long = clean_banner(b"x" * 500)
  assert long is not None and len(long) == 160 and long.endswith("…")


 # latency statistics ->
def test_latency_statistics():
  latency = Latency(method="icmp", sent=5, samples=[10.0, 12.0, 11.0, 15.0])
  assert latency.received == 4
  assert latency.loss == 20.0
  assert latency.avg == 12.0
  assert latency.min == 10.0
  assert latency.max == 15.0
  assert latency.jitter == round((2 + 1 + 4) / 3, 2)
  assert Latency(method="icmp", sent=3).avg is None
