 # import libraries ->
import logging
import socket
import sys
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path

import psutil

from beacon.config import MAX_SWEEP_HOSTS
from beacon.core.mac import normalize_mac


log = logging.getLogger(__name__)


 # interface model ->
@dataclass(frozen=True, slots=True)
class InterfaceInfo:
  name: str
  ip: IPv4Address
  network: IPv4Network
  mac: str | None
  is_up: bool = True
  gateway: IPv4Address | None = None

  @property
  def cidr(self) -> str:
    return f"{self.ip}/{self.network.prefixlen}"


 # interface discovery ->
def list_interfaces(include_down: bool = False) -> list[InterfaceInfo]:
  """every non-loopback ipv4 address on the host, one entry per address."""
  stats = psutil.net_if_stats()
  gateways = default_gateways()
  result: list[InterfaceInfo] = []
  for name, addresses in psutil.net_if_addrs().items():
    is_up = stats[name].isup if name in stats else False
    if not is_up and not include_down:
      continue
    mac = next((normalize_mac(a.address) for a in addresses if a.family == psutil.AF_LINK), None)
    for addr in addresses:
      if addr.family != socket.AF_INET or not addr.netmask:
        continue
      iface = IPv4Interface(f"{addr.address}/{addr.netmask}")
      if iface.ip.is_loopback or iface.ip.is_link_local:
        continue
      result.append(
        InterfaceInfo(name=name, ip=iface.ip, network=iface.network, mac=mac, is_up=is_up, gateway=gateways.get(name))
      )
  return result


def primary_local_ip() -> IPv4Address | None:
  """the source address the kernel would use for internet traffic (no packet is sent)."""
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    try:
      sock.connect(("192.0.2.1", 9))
      return IPv4Address(sock.getsockname()[0])
    except OSError:
      return None


def default_interface() -> InterfaceInfo | None:
  interfaces = list_interfaces()
  local_ip = primary_local_ip()
  match = next((i for i in interfaces if i.ip == local_ip), None)
  return match or next((i for i in interfaces if i.network.prefixlen < 32), None)


def find_interface(name: str) -> InterfaceInfo | None:
  candidates = [i for i in list_interfaces() if i.name == name]
  local_ip = primary_local_ip()
  return next((i for i in candidates if i.ip == local_ip), candidates[0] if candidates else None)


 # gateway discovery ->
def default_gateways() -> dict[str, IPv4Address]:
  """map of interface name to its default ipv4 gateway."""
  if sys.platform.startswith("linux"):
    return _linux_gateways(Path("/proc/net/route"))
  try:
    from scapy.config import conf

    iface, _, gateway = conf.route.route("0.0.0.0")
    if gateway and gateway != "0.0.0.0":
      return {str(getattr(iface, "name", iface)): IPv4Address(gateway)}
  except Exception as exc:  # scapy is optional here, any failure just means "unknown"
    log.debug("gateway lookup through scapy failed: %s", exc)
  return {}


def _linux_gateways(route_file: Path) -> dict[str, IPv4Address]:
  gateways: dict[str, IPv4Address] = {}
  try:
    lines = route_file.read_text().splitlines()[1:]
  except OSError:
    return gateways
  for line in lines:
    fields = line.split()
    if len(fields) < 4 or fields[1] != "00000000" or not int(fields[3], 16) & 0x2:
      continue
    gateway = IPv4Address(int(fields[2], 16).to_bytes(4, "little"))
    gateways.setdefault(fields[0], gateway)
  return gateways


 # target resolution ->
class TargetError(ValueError):
  pass


def resolve_target(target: str | None, interface: str | None) -> tuple[InterfaceInfo, IPv4Network]:
  """pick the interface and network to scan from cli arguments and the host configuration."""
  iface = find_interface(interface) if interface else default_interface()
  if iface is None:
    raise TargetError(f"interface {interface!r} not found or has no ipv4 address" if interface else "no active ipv4 interface found")
  if target is None:
    network = iface.network
  else:
    try:
      network = IPv4Network(target, strict=False)
    except ValueError as exc:
      raise TargetError(f"invalid network {target!r}: {exc}") from exc
  if network.num_addresses - 2 > MAX_SWEEP_HOSTS:
    raise TargetError(f"network {network} is too large (max /16)")
  return iface, network


def iter_hosts(network: IPv4Network) -> list[IPv4Address]:
  return [network.network_address] if network.prefixlen == 32 else list(network.hosts())
