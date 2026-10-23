 # import libraries ->
import asyncio
import json
import logging
import re
import shutil
import subprocess
import sys
from ipaddress import IPv4Network
from pathlib import Path

from beacon.core.models import DiscoverySource, Observation


log = logging.getLogger(__name__)


 # constants ->
PROC_NET_ARP = Path("/proc/net/arp")
ATF_COM = 0x2
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_MAC = r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"
_ARP_A_LINE = re.compile(rf"{_IP}\)?\s+(?:at\s+)?{_MAC}(?:\s+on\s+(\S+))?")


 # active arp sweep (requires raw sockets) ->
async def arp_sweep(network: IPv4Network, interface: str | None, timeout: float = 2.0, retry: int = 1) -> list[Observation]:
  """broadcast an arp who-has for every address with scapy `srp`.

  `srp` blocks until the timeout, so it runs in an executor to keep the event loop free.
  """
  loop = asyncio.get_running_loop()
  return await loop.run_in_executor(None, _arp_sweep_blocking, str(network), interface, timeout, retry)


def _arp_sweep_blocking(network: str, interface: str | None, timeout: float, retry: int) -> list[Observation]:
  from scapy.layers.l2 import ARP, Ether
  from scapy.sendrecv import srp

  answered, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
    iface=interface,
    timeout=timeout,
    retry=retry,
    verbose=False,
  )
  observations: list[Observation] = []
  for sent, received in answered:
    sent_time = getattr(sent, "sent_time", None)
    rtt = (float(received.time) - float(sent_time)) * 1000 if sent_time else None
    observations.append(
      Observation(ip=received[ARP].psrc, mac=received[ARP].hwsrc, source=DiscoverySource.ARP_SWEEP, rtt_ms=rtt)
    )
  return observations


 # passive arp cache (no privileges) ->
def read_arp_table(interface: str | None = None) -> list[Observation]:
  """read the operating system neighbour cache.

  only `reachable` entries are marked fresh; stale or unknown entries must be
  confirmed by another probe before the cleaning engine accepts them.
  """
  if sys.platform.startswith("linux"):
    if shutil.which("ip"):
      try:
        output = _run(["ip", "-j", "-4", "neigh", "show", *(["dev", interface] if interface else [])])
        return parse_ip_neigh_json(output, interface)
      except (OSError, subprocess.SubprocessError, ValueError) as exc:
        log.debug("ip neigh failed, falling back to /proc/net/arp: %s", exc)
    try:
      return parse_proc_net_arp(PROC_NET_ARP.read_text(), interface)
    except OSError as exc:
      log.warning("cannot read %s: %s", PROC_NET_ARP, exc)
      return []
  try:
    return parse_arp_a(_run(["arp", "-a", *(["-n"] if sys.platform == "darwin" else [])]), interface)
  except (OSError, subprocess.SubprocessError) as exc:
    log.warning("cannot read the arp table: %s", exc)
    return []


def _run(command: list[str]) -> str:
  return subprocess.run(command, capture_output=True, text=True, check=True, timeout=10).stdout


 # parsers ->
def parse_ip_neigh_json(output: str, interface: str | None = None) -> list[Observation]:
  observations: list[Observation] = []
  for entry in json.loads(output or "[]"):
    states = set(entry.get("state", []))
    mac = entry.get("lladdr")
    if not mac or states & {"FAILED", "INCOMPLETE", "NOARP"}:
      continue
    if interface and entry.get("dev", interface) != interface:
      continue
    observations.append(
      Observation(ip=entry["dst"], mac=mac, source=DiscoverySource.ARP_TABLE, fresh="REACHABLE" in states)
    )
  return observations


def parse_proc_net_arp(text: str, interface: str | None = None) -> list[Observation]:
  observations: list[Observation] = []
  for line in text.splitlines()[1:]:
    fields = line.split()
    if len(fields) < 6:
      continue
    ip, _hw_type, flags, mac, _mask, device = fields[:6]
    if not int(flags, 16) & ATF_COM or (interface and device != interface):
      continue
    observations.append(Observation(ip=ip, mac=mac, source=DiscoverySource.ARP_TABLE, fresh=False))
  return observations


def parse_arp_a(text: str, interface: str | None = None) -> list[Observation]:
  """parse `arp -a` from macos/bsd (`? (ip) at mac on en0`) and windows (`ip  mac  dynamic`)."""
  observations: list[Observation] = []
  for line in text.splitlines():
    match = _ARP_A_LINE.search(line)
    if not match:
      continue
    ip, mac, device = match.groups()
    if interface and device and device != interface:
      continue
    observations.append(Observation(ip=ip, mac=mac, source=DiscoverySource.ARP_TABLE, fresh=False))
  return observations
