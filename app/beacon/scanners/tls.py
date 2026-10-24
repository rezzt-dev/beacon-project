 # import libraries ->
import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import ssl
from datetime import UTC, datetime
from typing import Any

from beacon.core.engine import clean_banner


log = logging.getLogger(__name__)


 # constants ->
TLS_PORTS = frozenset({443, 465, 636, 853, 993, 995, 3389, 5986, 8443, 8883, 9443})
MAX_CERT_BYTES = 64 * 1024
MAX_NAMES = 20
_CN = bytes.fromhex("550403")
_ORG = bytes.fromhex("55040a")
_SAN = bytes.fromhex("551d11")


 # der parsing ->
class DerError(ValueError):
  pass


def _read(data: bytes, offset: int) -> tuple[int, bytes, int]:
  """one tlv: `(tag, value, next offset)`. bounds are checked: certificates come from the network."""
  if offset + 2 > len(data):
    raise DerError("truncated header")
  tag = data[offset]
  length = data[offset + 1]
  offset += 2
  if length & 0x80:
    count = length & 0x7F
    if not 1 <= count <= 4 or offset + count > len(data):
      raise DerError("bad length")
    length = int.from_bytes(data[offset : offset + count], "big")
    offset += count
  if offset + length > len(data):
    raise DerError("truncated value")
  return tag, data[offset : offset + length], offset + length


def _children(data: bytes) -> list[tuple[int, bytes]]:
  items: list[tuple[int, bytes]] = []
  offset = 0
  while offset < len(data):
    tag, value, offset = _read(data, offset)
    items.append((tag, value))
    if len(items) > 512:
      raise DerError("too many elements")
  return items


def _text(tag: int, value: bytes) -> str:
  if tag == 0x1E:  # bmpstring
    return value.decode("utf-16-be", errors="replace")
  return value.decode("utf-8", errors="replace")


def _name(data: bytes) -> dict[str, str]:
  found: dict[str, str] = {}
  for _set_tag, rdn in _children(data):
    for _seq_tag, attribute in _children(rdn):
      parts = _children(attribute)
      if len(parts) == 2 and parts[0][0] == 0x06:
        oid, (tag, value) = parts[0][1], parts[1]
        if oid == _CN:
          found.setdefault("cn", clean_banner(_text(tag, value)) or "")
        elif oid == _ORG:
          found.setdefault("o", clean_banner(_text(tag, value)) or "")
  return found


def _time(tag: int, value: bytes) -> datetime:
  text = value.decode("ascii", errors="replace").rstrip("Z")
  if tag == 0x17:  # utctime: two digit year, 50-99 means 19xx
    year = int(text[:2])
    text = f"{1900 + year if year >= 50 else 2000 + year}{text[2:]}"
  return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def _san(extensions: bytes) -> list[str]:
  names: list[str] = []
  for _tag, extension in _children(extensions):
    parts = _children(extension)
    if not parts or parts[0] != (0x06, _SAN):
      continue
    octets = parts[-1][1]
    _seq, general_names, _ = _read(octets, 0)
    for tag, value in _children(general_names):
      if tag == 0x82:
        names.append(clean_banner(value.decode("ascii", errors="replace")) or "")
      elif tag == 0x87 and len(value) in (4, 16):
        names.append(str(ipaddress.ip_address(value)))
      if len(names) >= MAX_NAMES:
        return names
  return names


def parse_certificate(der: bytes) -> dict[str, Any]:
  """subject, issuer, alternative names and validity of an x.509 certificate. never validates trust."""
  if len(der) > MAX_CERT_BYTES:
    raise DerError("certificate too large")
  _tag, certificate, _ = _read(der, 0)
  _tag, tbs, _ = _read(certificate, 0)
  fields = _children(tbs)
  if fields and fields[0][0] == 0xA0:  # explicit version
    fields = fields[1:]
  if len(fields) < 6:
    raise DerError("incomplete certificate")
  issuer = _name(fields[2][1])
  validity = _children(fields[3][1])
  subject = _name(fields[4][1])
  san: list[str] = []
  for tag, value in fields[6:]:
    if tag == 0xA3:
      _seq, extensions, _ = _read(value, 0)
      san = _san(extensions)
  not_before, not_after = (_time(*validity[0]), _time(*validity[1])) if len(validity) == 2 else (None, None)
  return {
    "subject": subject.get("cn"),
    "subject_org": subject.get("o"),
    "issuer": issuer.get("cn"),
    "issuer_org": issuer.get("o"),
    "names": san,
    "not_before": not_before.isoformat() if not_before else None,
    "not_after": not_after.isoformat() if not_after else None,
    "self_signed": fields[2][1] == fields[4][1],
    "sha256": hashlib.sha256(der).hexdigest(),
  }


 # network ->
async def fetch_certificate(ip: str, port: int, timeout: float = 2.0) -> dict[str, Any] | None:
  """the certificate a tls service presents, as observed. `trusted` is always false: beacon records
  what it saw and never claims a chain is valid (it does not validate it)."""
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  writer = None
  try:
    _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=context), timeout)
    tls = writer.get_extra_info("ssl_object")
    der = tls.getpeercert(binary_form=True) if tls else None
    version = tls.version() if tls else None
  except (TimeoutError, OSError, ssl.SSLError, EOFError):
    return None
  finally:
    if writer is not None:
      writer.close()
      with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 1.0)
  if not der:
    return None
  try:
    details = parse_certificate(der)
  except (DerError, ValueError, IndexError) as exc:
    log.debug("unreadable certificate from %s:%s: %s", ip, port, exc)
    return {"error": "unreadable certificate", "observed_at": datetime.now(UTC).replace(microsecond=0).isoformat()}
  return {**details, "tls_version": version, "trusted": False, "observed_at": datetime.now(UTC).replace(microsecond=0).isoformat()}
