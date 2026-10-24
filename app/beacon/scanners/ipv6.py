 # import libraries ->
import asyncio
import contextlib
import json
import logging
import re
import shutil
import socket
import struct
import subprocess
import sys
from ipaddress import IPv6Address

from beacon.core.mac import is_valid_unicast, normalize_mac


log = logging.getLogger(__name__)


 # constants ->
ALL_NODES = "ff02::1"
_NDP_LINE = re.compile(r"^([0-9a-f:]+)(?:%\S+)?\s+([0-9a-f:]+)\s+(\S+)", re.I)


 # parsing ->
def _usable(address: str) -> str | None:
  try:
    ip = IPv6Address(address.split("%", 1)[0])
  except ValueError:
    return None
  if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
    return None
  return str(ip)


def parse_ip_neigh6_json(output: str) -> list[tuple[str, str]]:
  pairs: list[tuple[str, str]] = []
  for entry in json.loads(output or "[]"):
    states = set(entry.get("state", []))
    mac = normalize_mac(entry.get("lladdr"))
    address = _usable(entry.get("dst", ""))
    if address and mac and is_valid_unicast(mac) and not states & {"FAILED", "INCOMPLETE", "NOARP"}:
      pairs.append((address, mac))
  return pairs


def parse_ndp(output: str) -> list[tuple[str, str]]:
  """`ndp -an` on macos/bsd: `address  linklayer  netif  expire  flags`."""
  pairs: list[tuple[str, str]] = []
  for line in output.splitlines()[1:]:
    match = _NDP_LINE.match(line.strip())
    if not match:
      continue
    address, mac = _usable(match.group(1)), normalize_mac(match.group(2))
    if address and mac and is_valid_unicast(mac):
      pairs.append((address, mac))
  return pairs


 # discovery ->
def neighbours6(interface: str | None = None) -> list[tuple[str, str]]:
  """`(ipv6 address, mac)` pairs the system already knows. no packet is sent and no range is swept."""
  try:
    if sys.platform.startswith("linux") and shutil.which("ip"):
      command = ["ip", "-j", "-6", "neigh", "show", *(["dev", interface] if interface else [])]
      return parse_ip_neigh6_json(subprocess.run(command, capture_output=True, text=True, check=True, timeout=10).stdout)
    if sys.platform == "darwin" and shutil.which("ndp"):
      return parse_ndp(subprocess.run(["ndp", "-an"], capture_output=True, text=True, check=True, timeout=10).stdout)
  except (OSError, subprocess.SubprocessError, ValueError) as exc:
    log.debug("ipv6 neighbour table unavailable: %s", exc)
  return []


async def solicit_all_nodes(interface: str, wait: float = 1.0) -> bool:
  """one icmpv6 echo to the link's all-nodes group so hosts answer and land in the neighbour table.

  uses an unprivileged icmpv6 datagram socket when the system allows it; otherwise nothing is sent.
  """
  try:
    index = socket.if_nametoindex(interface)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
  except (OSError, AttributeError) as exc:
    log.debug("cannot open an icmpv6 socket: %s", exc)
    return False
  with contextlib.closing(sock):
    sock.setblocking(False)
    packet = struct.pack("!BBHHH", 128, 0, 0, 0, 1) + b"beacon-ndp"
    try:
      sock.sendto(packet, (ALL_NODES, 0, 0, index))
    except OSError as exc:
      log.debug("icmpv6 all-nodes echo failed: %s", exc)
      return False
    await asyncio.sleep(wait)
  return True
