 # import libraries ->
import re


 # constants ->
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_GROUPED = re.compile(r"^[0-9a-f]{1,2}([:-])[0-9a-f]{1,2}(\1[0-9a-f]{1,2}){4}$")
_DOTTED = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$")
BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO = "00:00:00:00:00:00"


 # normalization ->
def normalize_mac(value: str | None) -> str | None:
  """normalize any common mac notation to `aa:bb:cc:dd:ee:ff`, or return none if invalid.

  accepts `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, cisco `aabb.ccdd.eeff`, bare
  `aabbccddeeff` and the zero-stripped form macos prints (`a:b:c:d:e:f`).
  """
  if not value:
    return None
  raw = value.strip().lower()
  if _GROUPED.match(raw):
    raw = "".join(part.zfill(2) for part in re.split(r"[:-]", raw))
  elif _DOTTED.match(raw):
    raw = raw.replace(".", "")
  if not _HEX12.match(raw):
    return None
  return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def mac_to_int(mac: str) -> int:
  return int(mac.replace(":", ""), 16)


def first_octet(mac: str) -> int:
  return int(mac[:2], 16)


 # address classification ->
def is_multicast(mac: str) -> bool:
  """i/g bit: least significant bit of the first octet."""
  return bool(first_octet(mac) & 0x01)


def is_locally_administered(mac: str) -> bool:
  """u/l bit: set on randomized (private) addresses used by modern phones and laptops."""
  return bool(first_octet(mac) & 0x02)


def is_valid_unicast(mac: str | None) -> bool:
  return mac is not None and mac not in (BROADCAST, ZERO) and not is_multicast(mac)


def is_randomized(mac: str) -> bool:
  """a unicast, locally administered address is almost always a randomized mac."""
  return is_valid_unicast(mac) and is_locally_administered(mac)
