 # import libraries ->
import pytest


scapy = pytest.importorskip("scapy")

from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.dns import DNS, DNSRR  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402

from beacon.scanners.passive import MAX_QUEUE, PassiveListener, parse_dhcp, sighting_from_packet  # noqa: E402


PHONE = "8e:e7:35:fe:0c:c6"


def dhcp_request(hostname=b"ana-phone", prl=(1, 3, 6, 15, 119, 252)):
  return (
    Ether(src=PHONE, dst="ff:ff:ff:ff:ff:ff")
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / BOOTP(chaddr=bytes.fromhex(PHONE.replace(":", "")) + b"\x00" * 10)
    / DHCP(options=[("message-type", "request"), ("requested_addr", "192.168.1.23"), ("hostname", hostname),
                    ("vendor_class_id", b"android-dhcp-14"), ("param_req_list", list(prl)), "end"])
  )


 # parsers ->
def test_a_dhcp_request_yields_mac_ip_name_and_a_stack_fingerprint():
  sighting = sighting_from_packet(Ether(bytes(dhcp_request())))
  assert (sighting.source, sighting.mac, sighting.ip, sighting.hostname) == ("dhcp", PHONE, "192.168.1.23", "ana-phone")
  assert sighting.vendor_class == "android-dhcp-14" and len(sighting.dhcp_fingerprint) == 16
  other = sighting_from_packet(Ether(bytes(dhcp_request(prl=(1, 3, 6)))))
  assert other.dhcp_fingerprint != sighting.dhcp_fingerprint


def test_hostile_dhcp_hostnames_are_dropped():
  sighting = sighting_from_packet(Ether(bytes(dhcp_request(hostname=b"<script>x</script>"))))
  assert sighting.hostname is None


def test_truncated_dhcp_is_ignored():
  assert parse_dhcp(b"\x01" * 100) is None
  assert parse_dhcp(bytes(dhcp_request()[UDP].payload)[:239]) is None


def test_arp_and_mdns_sightings():
  arp = Ether(src=PHONE) / ARP(op=1, hwsrc=PHONE, psrc="192.168.1.23", pdst="192.168.1.1")
  assert sighting_from_packet(Ether(bytes(arp))).ip == "192.168.1.23"
  probe = Ether(src=PHONE) / ARP(op=1, hwsrc=PHONE, psrc="0.0.0.0", pdst="192.168.1.23")
  assert sighting_from_packet(Ether(bytes(probe))) is None
  mdns = (
    Ether(src=PHONE) / IP(src="192.168.1.23", dst="224.0.0.251") / UDP(sport=5353, dport=5353)
    / DNS(qr=1, aa=1, an=DNSRR(rrname="23.1.168.192.in-addr.arpa", type="PTR", rdata="ana-phone.local"))
  )
  sighting = sighting_from_packet(Ether(bytes(mdns)))
  assert (sighting.source, sighting.hostname, sighting.ip) == ("mdns", "ana-phone", "192.168.1.23")


def test_the_queue_is_bounded():
  listener = PassiveListener(None)
  packet = Ether(bytes(Ether(src=PHONE) / ARP(op=1, hwsrc=PHONE, psrc="192.168.1.23", pdst="192.168.1.1")))
  for _ in range(MAX_QUEUE + 10):
    listener._handle(packet)
  assert listener.sightings.qsize() == MAX_QUEUE and listener.dropped == 10
  assert len(listener.drain(50)) == 50
