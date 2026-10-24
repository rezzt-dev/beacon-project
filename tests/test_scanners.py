 # import libraries ->
import asyncio
import struct

import pytest

from beacon.scanners.arp import parse_arp_a, parse_ip_neigh_json, parse_proc_net_arp
from beacon.scanners.hostname import HostnameResolver
from beacon.scanners.icmp import build_echo_request, checksum, parse_echo_reply
from beacon.scanners.network import _linux_gateways
from beacon.scanners.ports import parse_port_spec, scan_ports, tcp_rtt
from beacon.scanners.protocols.dns import (
  build_query,
  encode_name,
  parse_ptr_response,
  read_name,
  reverse_pointer,
)
from beacon.scanners.protocols.netbios import (
  build_nbstat_query,
  parse_nbstat_response,
  workstation_name,
)


 # arp table parsers ->
def test_parse_ip_neigh_json_marks_freshness():
  output = """[
    {"dst":"192.168.1.1","dev":"wlan0","lladdr":"34:5d:9e:3f:2a:77","state":["REACHABLE"]},
    {"dst":"192.168.1.5","dev":"wlan0","lladdr":"b0:a7:b9:dc:71:4a","state":["STALE"]},
    {"dst":"192.168.1.6","dev":"wlan0","state":["FAILED"]},
    {"dst":"10.0.0.1","dev":"eth0","lladdr":"00:00:0c:00:00:01","state":["REACHABLE"]}
  ]"""
  entries = parse_ip_neigh_json(output, "wlan0")
  assert [(e.ip, e.fresh) for e in entries] == [("192.168.1.1", True), ("192.168.1.5", False)]


def test_parse_proc_net_arp_skips_incomplete():
  text = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.1      0x1         0x2         34:5d:9e:3f:2a:77     *        wlan0\n"
    "192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
  )
  entries = parse_proc_net_arp(text)
  assert [(e.ip, e.mac, e.fresh) for e in entries] == [("192.168.1.1", "34:5d:9e:3f:2a:77", False)]


def test_parse_arp_a_macos_and_windows():
  macos = "? (192.168.1.1) at 34:5d:9e:3f:2a:77 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0 [ethernet]\n"
  windows = "Interface: 192.168.1.5 --- 0x7\n  Internet Address      Physical Address      Type\n  192.168.1.1           34-5d-9e-3f-2a-77     dynamic\n"
  assert [(e.ip, e.mac) for e in parse_arp_a(macos, "en0")] == [("192.168.1.1", "34:5d:9e:3f:2a:77")]
  assert [(e.ip, e.mac) for e in parse_arp_a(windows)] == [("192.168.1.1", "34-5d-9e-3f-2a-77")]


def test_linux_gateway_parser(tmp_path):
  route = tmp_path / "route"
  route.write_text(
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
    "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n"
  )
  assert {k: str(v) for k, v in _linux_gateways(route).items()} == {"wlan0": "192.168.1.1"}


 # icmp ->
def test_icmp_checksum_roundtrip():
  packet = build_echo_request(0x1234, 7)
  assert checksum(packet) == 0  # a packet with a valid checksum sums to zero


def test_parse_echo_reply_with_and_without_ip_header():
  icmp = struct.pack("!BBHHH", 0, 0, 0, 0x1234, 7) + b"payload"
  assert parse_echo_reply(icmp) == (0x1234, 7, None)
  ip_header = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 57, 1]) + bytes(10)
  assert parse_echo_reply(ip_header + icmp) == (0x1234, 7, 57)
  assert parse_echo_reply(struct.pack("!BBHHH", 8, 0, 0, 1, 1)) is None  # a request, not a reply


 # dns / mdns ->
def test_dns_query_and_ptr_response_with_compression():
  name = reverse_pointer("192.168.1.128")
  assert name == "128.1.168.192.in-addr.arpa"
  query = build_query(name, txid=0xBEEF, unicast_response=True)
  assert query[:2] == b"\xbe\xef"
  assert query.endswith(struct.pack("!HH", 12, 0x8001))

  question = encode_name(name) + struct.pack("!HH", 12, 1)
  target = encode_name("android-2.local")
  answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
  response = struct.pack("!HHHHHH", 0xBEEF, 0x8400, 1, 1, 0, 0) + question + answer
  assert parse_ptr_response(response, txid=0xBEEF) == "android-2.local"
  assert parse_ptr_response(response, txid=0x0001) is None


def test_read_name_rejects_pointer_loops():
  packet = struct.pack("!HHHHHH", 0, 0x8000, 0, 0, 0, 0) + b"\xc0\x0c"
  with pytest.raises(ValueError):
    read_name(packet, 12)


def test_resolver_asks_the_router_dns_when_the_system_one_knows_nothing():
  class _Router(asyncio.DatagramProtocol):
    def connection_made(self, transport) -> None:
      self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
      txid = data[:2]
      question = data[12:]
      target = encode_name("SUN2000-1022B6808337")
      answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, len(target)) + target
      self.transport.sendto(txid + struct.pack("!HHHHH", 0x8580, 1, 1, 0, 0) + question + answer, addr)

  async def scenario():
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(_Router, local_addr=("127.0.0.1", 0))
    resolver = HostnameResolver(timeout=0.5, router="127.0.0.1", router_port=transport.get_extra_info("sockname")[1])
    resolver.reverse_dns = _nothing
    resolver.mdns = _nothing
    resolver.netbios = _nothing
    try:
      return await resolver.resolve("192.168.1.133")
    finally:
      transport.close()
      resolver.close()

  async def _nothing(ip):
    return None

  assert asyncio.run(scenario()) == ("sun2000-1022b6808337", "router")


def test_router_dns_is_skipped_without_a_gateway():
  resolver = HostnameResolver(router=None)
  try:
    assert asyncio.run(resolver.router_dns("192.168.1.133")) is None
  finally:
    resolver.close()


 # netbios ->
def test_nbstat_query_and_response():
  query = build_nbstat_query(0x0102)
  assert query[12] == 32 and query[13:15] == b"CK"  # '*' encodes to "CK", nulls to "AA"
  names = [(b"DESKTOP-01", 0x00, 0x0400), (b"WORKGROUP", 0x00, 0x8400), (b"DESKTOP-01", 0x20, 0x0400)]
  rdata = bytes([len(names)]) + b"".join(n.ljust(15) + bytes([s]) + struct.pack("!H", f) for n, s, f in names)
  response = (
    struct.pack("!HHHHHH", 0x0102, 0x8400, 0, 1, 0, 0)
    + query[12:46]
    + struct.pack("!HHIH", 0x21, 1, 0, len(rdata))
    + rdata
  )
  parsed = parse_nbstat_response(response)
  assert len(parsed) == 3
  assert workstation_name(parsed) == "DESKTOP-01"


 # tcp ports ->
def test_parse_port_spec():
  assert parse_port_spec("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
  assert 443 in parse_port_spec("top")
  assert parse_port_spec("web,22")[0] == 22
  assert len(parse_port_spec("all")) == 65535
  for bad in ("0", "70000", "10-5", "", "abc"):
    with pytest.raises(ValueError):
      parse_port_spec(bad)


def test_scan_ports_against_local_server():
  async def scenario():
    async def handler(reader, writer):
      writer.write(b"SSH-2.0-beacon-test\r\n")
      await writer.drain()
      writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
      closed_port = port + 1 if port < 65535 else port - 1
      found = await scan_ports("127.0.0.1", [port, closed_port], timeout=1.0, workers=4)
      rtt_closed = await tcp_rtt("127.0.0.1", closed_port, 1.0)
    return port, found, rtt_closed

  port, found, rtt_closed = asyncio.run(scenario())
  assert [p.port for p in found] == [port]
  assert found[0].banner == "SSH-2.0-beacon-test"
  assert rtt_closed is not None  # a refused connection still proves the host is up
