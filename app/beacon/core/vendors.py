 # import libraries ->
import logging
import os
import tempfile
import urllib.request
from collections.abc import Iterable
from pathlib import Path

from beacon.config import MANUF_URL, SYSTEM_MANUF_PATHS
from beacon.core.mac import is_randomized, mac_to_int, normalize_mac


log = logging.getLogger(__name__)

MIN_VALID_ENTRIES = 1_000


 # vendor database ->
class VendorDatabase:
  """offline ieee oui lookup backed by the wireshark `manuf` file.

  supports the three ieee assignment sizes: ma-l (/24), ma-m (/28) and ma-s (/36);
  lookups try the longest prefix first.
  """

  def __init__(self, source: Path | None = None) -> None:
    self.source = source
    self._tables: dict[int, dict[int, str]] = {}

  def __len__(self) -> int:
    return sum(len(table) for table in self._tables.values())

  def add(self, prefix: str, vendor: str) -> None:
    hex_part, _, mask = prefix.partition("/")
    digits = hex_part.replace(":", "").replace("-", "").replace(".", "").lower()
    if not digits or len(digits) > 12 or any(c not in "0123456789abcdef" for c in digits):
      return
    bits = int(mask) if mask else len(digits) * 4
    if not 0 < bits <= 48:
      return
    value = int(digits, 16) << (48 - len(digits) * 4)
    self._tables.setdefault(bits, {})[value >> (48 - bits)] = vendor

  def load_lines(self, lines: Iterable[str]) -> "VendorDatabase":
    for line in lines:
      line = line.strip()
      if not line or line.startswith("#"):
        continue
      fields = [f.strip() for f in line.split("\t") if f.strip()]
      if len(fields) < 2:
        continue
      long_name = fields[2] if len(fields) > 2 else fields[1]
      self.add(fields[0], long_name.split("#")[0].strip() or fields[1])
    return self

  @classmethod
  def from_file(cls, path: Path) -> "VendorDatabase":
    with path.open(encoding="utf-8", errors="replace") as handle:
      return cls(source=path).load_lines(handle)

  @classmethod
  def load_default(cls, user_path: Path) -> "VendorDatabase":
    """load the user copy, falling back to a system wireshark install, or an empty db."""
    for candidate in (user_path, *SYSTEM_MANUF_PATHS):
      if candidate.is_file():
        try:
          return cls.from_file(candidate)
        except OSError as exc:
          log.warning("cannot read oui database %s: %s", candidate, exc)
    return cls()

  def lookup(self, mac: str | None) -> str | None:
    normalized = normalize_mac(mac)
    if normalized is None or is_randomized(normalized):
      return None
    value = mac_to_int(normalized)
    for bits in sorted(self._tables, reverse=True):
      vendor = self._tables[bits].get(value >> (48 - bits))
      if vendor:
        return vendor
    return None


 # database download ->
def download_manuf(dest: Path, url: str = MANUF_URL, timeout: float = 30.0) -> int:
  """download and validate a fresh `manuf` file, replacing `dest` atomically."""
  dest.parent.mkdir(parents=True, exist_ok=True)
  request = urllib.request.Request(url, headers={"User-Agent": "beacon-oui-updater"})
  with urllib.request.urlopen(request, timeout=timeout) as response:
    payload = response.read()

  text = payload.decode("utf-8", errors="replace")
  entries = len(VendorDatabase().load_lines(text.splitlines()))
  if entries < MIN_VALID_ENTRIES:
    raise ValueError(f"downloaded file looks invalid ({entries} entries)")

  fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".manuf-")
  try:
    with os.fdopen(fd, "wb") as handle:
      handle.write(payload)
    os.replace(tmp_name, dest)
  except BaseException:
    Path(tmp_name).unlink(missing_ok=True)
    raise
  return entries
