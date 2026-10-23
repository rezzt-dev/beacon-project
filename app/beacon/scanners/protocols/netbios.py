 # import libraries ->
import struct
from dataclasses import dataclass

from beacon.scanners.protocols.dns import DnsParseError, read_name


 # constants ->
TYPE_NBSTAT = 0x21
CLASS_IN = 0x0001
GROUP_NAME_FLAG = 0x8000
WORKSTATION_SUFFIX = 0x00


 # models ->
@dataclass(frozen=True, slots=True)
class NetbiosName:
  name: str
  suffix: int
  flags: int

  @property
  def is_group(self) -> bool:
    return bool(self.flags & GROUP_NAME_FLAG)


 # building ->
def encode_netbios_name(name: str, suffix: int = 0x00) -> bytes:
  """rfc 1001 first-level encoding: every nibble becomes a letter `a`..`p`."""
  raw = name.upper().encode("ascii")[:15].ljust(15, b"\x00" if name == "*" else b" ") + bytes([suffix])
  encoded = bytes(c for b in raw for c in ((b >> 4) + 0x41, (b & 0x0F) + 0x41))
  return bytes([len(encoded)]) + encoded + b"\x00"


def build_nbstat_query(txid: int) -> bytes:
  """node status request for the wildcard name `*`, answered by any windows/samba host."""
  header = struct.pack("!HHHHHH", txid, 0x0000, 1, 0, 0, 0)
  return header + encode_netbios_name("*") + struct.pack("!HH", TYPE_NBSTAT, CLASS_IN)


 # parsing ->
def parse_nbstat_response(data: bytes) -> list[NetbiosName]:
  if len(data) < 12:
    raise DnsParseError("packet shorter than a netbios header")
  _txid, _flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
  if ancount < 1:
    return []
  offset = 12
  for _ in range(qdcount):
    _, offset = read_name(data, offset)
    offset += 4
  _, offset = read_name(data, offset)
  if offset + 11 > len(data):
    raise DnsParseError("truncated nbstat record")
  rtype = struct.unpack("!H", data[offset : offset + 2])[0]
  if rtype != TYPE_NBSTAT:
    return []
  offset += 10
  count = data[offset]
  offset += 1
  names: list[NetbiosName] = []
  for _ in range(count):
    entry = data[offset : offset + 18]
    if len(entry) < 18:
      break
    name = entry[:15].decode("ascii", errors="replace").strip(" \x00")
    names.append(NetbiosName(name=name, suffix=entry[15], flags=struct.unpack("!H", entry[16:18])[0]))
    offset += 18
  return names


def workstation_name(names: list[NetbiosName]) -> str | None:
  return next((n.name for n in names if n.suffix == WORKSTATION_SUFFIX and not n.is_group and n.name), None)
