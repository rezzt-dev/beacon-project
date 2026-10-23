 # import libraries ->
import asyncio
import struct

import pytest

from beacon.scanners.protocols.dns import (
  FLAG_RESPONSE,
  TYPE_PTR,
  DnsParseError,
  encode_name,
  parse_ptr_records,
  parse_ptr_response,
)
from beacon.scanners.services import (
  MAX_SERVICES,
  SERVICE_ENUMERATION,
  clean_services,
  discover_services,
)


 # helpers ->
def ptr_response(targets: list[str], question: str = SERVICE_ENUMERATION, compress: bool = False) -> bytes:
  """a dns response answering `question` with one ptr record per target."""
  header = struct.pack("!HHHHHH", 0, FLAG_RESPONSE, 1, len(targets), 0, 0)
  data = header + encode_name(question) + struct.pack("!HH", TYPE_PTR, 1)
  for target in targets:
    rdata = encode_name(target)
    owner = b"\xc0\x0c" if compress else encode_name(question)
    data += owner + struct.pack("!HHIH", TYPE_PTR, 1, 120, len(rdata)) + rdata
  return data


 # parsing ->
def test_parse_ptr_records_returns_every_target():
  data = ptr_response(["_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local"], compress=True)
  assert parse_ptr_records(data) == ["_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local"]


def test_parse_ptr_response_still_returns_the_first_one():
  assert parse_ptr_response(ptr_response(["a.local", "b.local"])) == "a.local"
  assert parse_ptr_response(ptr_response([])) is None


def test_parse_ptr_records_respects_the_limit_and_ignores_queries():
  assert len(parse_ptr_records(ptr_response([f"_s{i}._tcp.local" for i in range(10)]), limit=3)) == 3
  query = struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0)
  assert parse_ptr_records(query) == []


def test_parse_ptr_records_rejects_truncated_packets():
  with pytest.raises(DnsParseError):
    parse_ptr_records(b"\x00\x01")
  with pytest.raises(DnsParseError):
    parse_ptr_records(ptr_response(["_a._tcp.local"])[:-6])


def test_clean_services_keeps_only_well_formed_service_types():
  names = ["_airplay._tcp.local", "_AIRPLAY._tcp.local.", "_raop._tcp.local", "evil name", "_x" * 40 + "._tcp", "example.com", "_ok._udp.local"]
  assert clean_services(names) == ["_airplay._tcp", "_ok._udp", "_raop._tcp"]


def test_clean_services_caps_the_amount():
  names = [f"_svc{i:03d}._tcp.local" for i in range(100)]
  assert len(clean_services(names)) == MAX_SERVICES


 # discovery against a local mdns responder ->
class _Responder(asyncio.DatagramProtocol):
  def __init__(self, reply: bytes | None) -> None:
    self.reply = reply

  def connection_made(self, transport) -> None:
    self.transport = transport

  def datagram_received(self, data: bytes, addr) -> None:
    if self.reply is not None:
      self.transport.sendto(self.reply, addr)


async def _serve(reply: bytes | None):
  loop = asyncio.get_running_loop()
  transport, _ = await loop.create_datagram_endpoint(lambda: _Responder(reply), local_addr=("127.0.0.1", 0))
  return transport, transport.get_extra_info("sockname")[1]


def test_discover_services_reads_the_announced_types():
  async def scenario():
    transport, port = await _serve(ptr_response(["_airplay._tcp.local", "_raop._tcp.local"]))
    try:
      return await discover_services("127.0.0.1", timeout=1.0, port=port)
    finally:
      transport.close()

  assert asyncio.run(scenario()) == ["_airplay._tcp", "_raop._tcp"]


def test_discover_services_survives_silence_and_garbage():
  async def scenario(reply):
    transport, port = await _serve(reply)
    try:
      return await discover_services("127.0.0.1", timeout=0.2, port=port)
    finally:
      transport.close()

  assert asyncio.run(scenario(None)) == []
  assert asyncio.run(scenario(b"\x01\x02\x03")) == []
