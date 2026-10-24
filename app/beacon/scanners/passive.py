 # import libraries ->
import contextlib
import hashlib
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from beacon.core.engine import clean_hostname
from beacon.core.mac import is_valid_unicast, normalize_mac
from beacon.scanners.protocols.dns import DnsParseError, parse_ptr_records


log = logging.getLogger(__name__)


 # constants ->
# only what identifies a device on the lan: no payloads, no queries of other hosts, no traffic content
BPF_FILTER = "arp or (udp and (port 67 or port 68 or port 5353))"
MAX_QUEUE = 1000
DHCP_MAGIC = b"\x63\x82\x53\x63"


 # sightings ->
@dataclass(frozen=True, slots=True)
class Sighting:
  """one passive observation, already minimized."""

  source: str  # arp, dhcp, mdns
  mac: str
  ip: str | None = None
  hostname: str | None = None
  # hash of the dhcp parameter request list (option 55): a stable trait of the client stack
  dhcp_fingerprint: str | None = None
  vendor_class: str | None = None
  seen_at: float = 0.0

  def to_dict(self) -> dict[str, Any]:
    return {
      "source": self.source, "mac": self.mac, "ip": self.ip, "hostname": self.hostname,
      "dhcp_fingerprint": self.dhcp_fingerprint, "vendor_class": self.vendor_class,
    }


 # parsers (pure, bytes in) ->
def parse_dhcp(payload: bytes) -> dict[str, Any] | None:
  """client hardware address, requested ip, hostname, vendor class and option 55 of a bootp/dhcp message."""
  if len(payload) < 240 or payload[236:240] != DHCP_MAGIC:
    return None
  hlen = payload[2]
  chaddr = payload[28 : 28 + min(hlen, 16)]
  mac = normalize_mac(chaddr[:6].hex()) if hlen >= 6 else None
  yiaddr = ".".join(str(b) for b in payload[16:20])
  options: dict[int, bytes] = {}
  offset = 240
  while offset < len(payload):
    code = payload[offset]
    if code == 255:
      break
    if code == 0:
      offset += 1
      continue
    if offset + 1 >= len(payload):
      break
    length = payload[offset + 1]
    options[code] = payload[offset + 2 : offset + 2 + length]
    offset += 2 + length
  requested = options.get(50)
  hostname = options.get(12)
  vendor = options.get(60)
  prl = options.get(55)
  return {
    "mac": mac,
    "ip": ".".join(str(b) for b in requested) if requested and len(requested) == 4 else (yiaddr if yiaddr != "0.0.0.0" else None),
    "hostname": clean_hostname(hostname.decode("utf-8", errors="replace")) if hostname else None,
    "vendor_class": vendor.decode("ascii", errors="replace")[:64] if vendor else None,
    "fingerprint": hashlib.sha256(bytes(prl)).hexdigest()[:16] if prl else None,
  }


def parse_mdns_names(payload: bytes) -> list[str]:
  """hostnames a device announces about itself in an mdns response (ptr records of reverse names)."""
  try:
    names = parse_ptr_records(payload)
  except DnsParseError:
    return []
  # service instance names (`x._airplay._tcp.local`) are not host names
  return [n for n in (clean_hostname(name) for name in names) if n and n.endswith(".local") and "._" not in n][:4]


def sighting_from_packet(packet: Any) -> Sighting | None:
  """turn a scapy packet into a minimized sighting, or none when it says nothing useful."""
  from scapy.layers.inet import UDP
  from scapy.layers.l2 import ARP, Ether

  now = time.time()
  if packet.haslayer(ARP):
    arp = packet[ARP]
    mac = normalize_mac(arp.hwsrc)
    if mac and is_valid_unicast(mac) and arp.psrc not in ("0.0.0.0", None):
      return Sighting("arp", mac, arp.psrc, seen_at=now)
    return None
  if packet.haslayer(UDP):
    udp = packet[UDP]
    payload = bytes(udp.payload)
    if udp.sport == 68 or udp.dport == 67:
      info = parse_dhcp(payload)
      if info and info["mac"] and is_valid_unicast(info["mac"]):
        return Sighting("dhcp", info["mac"], info["ip"], info["hostname"], info["fingerprint"], info["vendor_class"], now)
    if udp.sport == 5353 and packet.haslayer(Ether):
      mac = normalize_mac(packet[Ether].src)
      names = parse_mdns_names(payload)
      if mac and names and is_valid_unicast(mac):
        source_ip = packet.payload.src if hasattr(packet.payload, "src") else None
        return Sighting("mdns", mac, source_ip, names[0].removesuffix(".local"), seen_at=now)
  return None


 # listener ->
class PassiveListener:
  """an optional sniffer on one interface (needs privileges and scapy). sightings go to a bounded
  queue: when it is full the oldest news are dropped, never the scanner's memory."""

  def __init__(self, interface: str | None, on_sighting: Callable[[Sighting], None] | None = None) -> None:
    self.interface = interface
    self.on_sighting = on_sighting
    self.sightings: queue.Queue[Sighting] = queue.Queue(MAX_QUEUE)
    self.dropped = 0
    self._sniffer = None
    self._lock = threading.Lock()

  def _handle(self, packet: Any) -> None:
    try:
      sighting = sighting_from_packet(packet)
    except Exception:  # a malformed packet must not stop the sniffer
      log.debug("unreadable packet", exc_info=True)
      return
    if sighting is None:
      return
    if self.sightings.full():
      self.dropped += 1
      with contextlib.suppress(queue.Empty):
        self.sightings.get_nowait()
    self.sightings.put_nowait(sighting)
    if self.on_sighting is not None:
      self.on_sighting(sighting)

  def start(self) -> None:
    from scapy.sendrecv import AsyncSniffer

    with self._lock:
      if self._sniffer is not None:
        return
      self._sniffer = AsyncSniffer(iface=self.interface, filter=BPF_FILTER, prn=self._handle, store=False)
      self._sniffer.start()

  def stop(self) -> None:
    with self._lock:
      if self._sniffer is not None:
        try:
          self._sniffer.stop()
        except Exception:  # stopping a sniffer that failed to start
          log.debug("sniffer stop failed", exc_info=True)
        self._sniffer = None

  def drain(self, limit: int = 200) -> list[Sighting]:
    items: list[Sighting] = []
    while len(items) < limit:
      try:
        items.append(self.sightings.get_nowait())
      except queue.Empty:
        break
    return items
