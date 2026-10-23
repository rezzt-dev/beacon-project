 # import libraries ->
import struct


 # constants ->
TYPE_PTR = 12
CLASS_IN = 1
UNICAST_RESPONSE = 0x8000
FLAG_RESPONSE = 0x8000
FLAG_RECURSION_DESIRED = 0x0100
MAX_POINTER_JUMPS = 32


class DnsParseError(ValueError):
  pass


 # building ->
def reverse_pointer(ip: str) -> str:
  return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def encode_name(name: str) -> bytes:
  encoded = b""
  for label in name.rstrip(".").split("."):
    raw = label.encode("idna") if label else b""
    if not 0 < len(raw) < 64:
      raise ValueError(f"invalid dns label in {name!r}")
    encoded += bytes([len(raw)]) + raw
  return encoded + b"\x00"


def build_query(name: str, qtype: int = TYPE_PTR, txid: int = 0, recursion: bool = False, unicast_response: bool = False) -> bytes:
  flags = FLAG_RECURSION_DESIRED if recursion else 0
  header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
  qclass = CLASS_IN | (UNICAST_RESPONSE if unicast_response else 0)
  return header + encode_name(name) + struct.pack("!HH", qtype, qclass)


 # parsing ->
def read_name(data: bytes, offset: int) -> tuple[str, int]:
  """decode a possibly compressed name; returns the name and the offset after it."""
  labels: list[str] = []
  end: int | None = None
  jumps = 0
  while True:
    if offset >= len(data):
      raise DnsParseError("name runs past the end of the packet")
    length = data[offset]
    if length & 0xC0 == 0xC0:
      if offset + 1 >= len(data):
        raise DnsParseError("truncated compression pointer")
      jumps += 1
      if jumps > MAX_POINTER_JUMPS:
        raise DnsParseError("compression pointer loop")
      if end is None:
        end = offset + 2
      offset = ((length & 0x3F) << 8) | data[offset + 1]
      continue
    if length == 0:
      return ".".join(labels), (end if end is not None else offset + 1)
    offset += 1
    labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
    offset += length


def parse_ptr_response(data: bytes, txid: int | None = None) -> str | None:
  """return the first ptr target found in any section of a response."""
  if len(data) < 12:
    raise DnsParseError("packet shorter than a dns header")
  rx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
  if not flags & FLAG_RESPONSE or (txid is not None and rx_id != txid):
    return None
  offset = 12
  for _ in range(qdcount):
    _, offset = read_name(data, offset)
    offset += 4
  for _ in range(ancount + nscount + arcount):
    _, offset = read_name(data, offset)
    if offset + 10 > len(data):
      raise DnsParseError("truncated resource record")
    rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
    offset += 10
    if rtype == TYPE_PTR:
      target, _ = read_name(data, offset)
      return target
    offset += rdlength
  return None
