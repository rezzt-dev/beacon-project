 # import libraries ->
import asyncio
import logging
import platform
import socket
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Protocol

from beacon.core.diff import detect_changes
from beacon.core.engine import CleaningEngine, apply_ttl, clean_hostname
from beacon.core.events import Event, EventBus, EventType
from beacon.core.identity import IdentityMatch, IdentityResolver
from beacon.core.models import Device, DeviceStatus, DiscoverySource, Observation, ScanMode, utcnow
from beacon.core.presence import (
  MAX_ROUTINE_ABSENCE,
  PROFILE_WEEKS,
  SESSION_GAP,
  build_profile,
  detect_anomalies,
  is_profilable,
)
from beacon.core.report import ScanReport
from beacon.core.vendors import VendorDatabase
from beacon.scanners.arp import arp_sweep, read_arp_table
from beacon.scanners.hostname import HostnameResolver
from beacon.scanners.icmp import IcmpPinger
from beacon.scanners.latency import measure_latency
from beacon.scanners.network import InterfaceInfo, iter_hosts, list_interfaces, resolve_target
from beacon.scanners.ports import scan_ports, tcp_alive
from beacon.scanners.privileges import privileged_mode_available
from beacon.scanners.services import discover_services
from beacon.storage.repository import Repository


log = logging.getLogger(__name__)


 # options ->
@dataclass(slots=True)
class ScanOptions:
  target: str | None = None
  interface: str | None = None
  mode: ScanMode = ScanMode.AUTO
  ports: Sequence[int] = ()
  discovery_timeout: float = 1.5
  port_timeout: float = 1.0
  port_concurrency: int = 512
  host_concurrency: int = 64
  latency_samples: int = 3
  offline_grace: float = 0.0
  resolve_hostnames: bool = True
  grab_banners: bool = True
  identity: bool = True
  presence: bool = True
  presence_gap: float = SESSION_GAP.total_seconds()
  save: bool = True


class ScanError(RuntimeError):
  pass


 # progress reporting ->
class ProgressReporter(Protocol):
  def stage(self, name: str, total: int | None = None) -> None: ...
  def advance(self, amount: int = 1) -> None: ...


class NullProgress:
  def stage(self, name: str, total: int | None = None) -> None:
    log.debug("stage: %s (%s)", name, total)

  def advance(self, amount: int = 1) -> None:
    pass


 # pipeline ->
@dataclass(slots=True)
class ScanPipeline:
  """orchestrates one scan: discover -> clean -> enrich -> diff -> persist -> publish."""

  repository: Repository
  vendors: VendorDatabase
  bus: EventBus = field(default_factory=EventBus)
  progress: ProgressReporter = field(default_factory=NullProgress)

  async def run(self, options: ScanOptions) -> ScanReport:
    started = utcnow()
    iface, network = resolve_target(options.target, options.interface)
    privileged = self._resolve_mode(options.mode)
    report = ScanReport(
      network=str(network),
      mode=ScanMode.PRIVILEGED if privileged else ScanMode.UNPRIVILEGED,
      started_at=started,
      interface=iface.name,
      local_ip=str(iface.ip),
      ports_scanned=bool(options.ports),
    )

    pinger = IcmpPinger.open()
    try:
      observations = await self._discover(network, iface, privileged, pinger, options)
      merged = CleaningEngine(self.vendors, network).merge(observations)
      devices = merged.devices
      for device in devices.values():
        device.is_gateway = iface.gateway is not None and device.ip == str(iface.gateway)
      router = str(iface.gateway) if iface.gateway is not None else None
      await self._enrich(list(devices.values()), options, pinger, router)
    finally:
      if pinger is not None:
        pinger.close()

    previous = self.repository.load_devices()
    report.first_run = not previous
    now = utcnow()
    report.events = detect_changes(
      previous,
      devices,
      merged.conflicts,
      network,
      report.ports_scanned,
      offline_grace=timedelta(seconds=options.offline_grace),
      now=now,
      identity_candidates=self._identity_candidates(previous, devices) if options.identity else None,
    )
    self._carry_history(previous, devices, report.ports_scanned, now)
    if options.presence:
      report.events += self._presence_events(previous, devices, network, now)

    report.devices = sorted(devices.values(), key=lambda d: IPv4Address(d.ip))
    report.conflicts = merged.conflicts
    report.discarded = merged.discarded
    report.finished_at = now
    if options.save:
      report.scan_id = self.repository.save_scan(
        report, presence=options.presence, presence_gap=timedelta(seconds=options.presence_gap)
      )
    self.bus.publish_many(report.events)
    return report

  @staticmethod
  def _resolve_mode(mode: ScanMode) -> bool:
    available = privileged_mode_available()
    if mode == ScanMode.PRIVILEGED and not available:
      raise ScanError("privileged mode needs root/administrator (npcap on windows) and scapy")
    return available if mode == ScanMode.AUTO else mode == ScanMode.PRIVILEGED

  # discovery ->
  async def _discover(
    self,
    network: IPv4Network,
    iface: InterfaceInfo,
    privileged: bool,
    pinger: IcmpPinger | None,
    options: ScanOptions,
  ) -> list[Observation]:
    observations: list[Observation] = []
    # every address of this host is one device, never a separate "unknown" one
    local_ips = [iface.ip, *sorted({i.ip for i in list_interfaces() if i.name == iface.name} - {iface.ip})]
    for ip in local_ips:
      if ip in network:
        observations.append(Observation(ip=str(ip), mac=iface.mac, source=DiscoverySource.LOCAL))

    if privileged:
      self.progress.stage("arp sweep", None)
      observations += await arp_sweep(network, iface.name, options.discovery_timeout)
      return observations

    hosts = [str(h) for h in iter_hosts(network) if h not in local_ips]
    if pinger is not None:
      self.progress.stage("icmp sweep", len(hosts))
      observations += await self._icmp_sweep(hosts, pinger, options)
    else:
      self.progress.stage("arp cache priming", None)
      await self._prime_arp_cache(hosts, options.discovery_timeout)

    table = read_arp_table(iface.name if network.overlaps(iface.network) else None)
    observations += table
    confirmed = {o.ip for o in observations if o.fresh}
    stale = sorted({o.ip for o in table if not o.fresh and o.ip not in confirmed and IPv4Address(o.ip) in network})
    if stale:
      self.progress.stage("confirming cached entries", len(stale))
      observations += await self._tcp_confirm(stale, options)
    return observations

  async def _icmp_sweep(self, hosts: list[str], pinger: IcmpPinger, options: ScanOptions) -> list[Observation]:
    limiter = asyncio.Semaphore(256)

    async def probe(ip: str) -> Observation | None:
      async with limiter:
        reply = await pinger.ping(ip, options.discovery_timeout)
      self.progress.advance()
      if reply is None:
        return None
      return Observation(ip=ip, source=DiscoverySource.ICMP, ttl=reply.ttl, rtt_ms=reply.rtt_ms)

    results = await asyncio.gather(*(probe(ip) for ip in hosts))
    return [r for r in results if r is not None]

  @staticmethod
  async def _prime_arp_cache(hosts: list[str], wait: float) -> None:
    """a udp datagram to the discard port forces the kernel to arp every address.

    datagrams waiting for arp hold send buffer space, so `EAGAIN` backs off briefly.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
      sock.setblocking(False)
      for ip in hosts:
        for _ in range(100):
          try:
            sock.sendto(b"", (ip, 9))
            break
          except BlockingIOError:
            await asyncio.sleep(0.05)
          except OSError:
            break
    await asyncio.sleep(wait)

  async def _tcp_confirm(self, ips: list[str], options: ScanOptions) -> list[Observation]:
    limiter = asyncio.Semaphore(options.host_concurrency)

    async def confirm(ip: str) -> Observation | None:
      async with limiter:
        rtt = await tcp_alive(ip, timeout=options.port_timeout)
      self.progress.advance()
      return Observation(ip=ip, source=DiscoverySource.TCP, rtt_ms=rtt) if rtt is not None else None

    results = await asyncio.gather(*(confirm(ip) for ip in ips))
    return [r for r in results if r is not None]

  # enrichment ->
  async def _enrich(
    self, devices: list[Device], options: ScanOptions, pinger: IcmpPinger | None, router: str | None = None
  ) -> None:
    host_limiter = asyncio.Semaphore(options.host_concurrency)
    port_limiter = asyncio.Semaphore(options.port_concurrency)
    resolver = HostnameResolver(router=router) if options.resolve_hostnames else None
    banner_timeout = 1.5 if options.grab_banners else None
    self.progress.stage("enriching devices", len(devices))

    async def enrich(device: Device) -> None:
      async with host_limiter:
        if device.is_local:
          self._describe_local(device)
        hostname = (
          asyncio.create_task(resolver.resolve(device.ip)) if resolver and not device.hostname else None
        )
        # a randomized mac says nothing about the device, so the services it announces help recognize it later
        services = (
          asyncio.create_task(discover_services(device.ip, options.discovery_timeout))
          if options.identity and device.randomized_mac and not device.is_local
          else None
        )
        if options.ports:
          device.ports = await scan_ports(device.ip, options.ports, options.port_timeout, port_limiter, banner_timeout)
        if options.latency_samples > 0 and not device.is_local:
          tcp_ports = [p.port for p in device.open_ports]
          device.latency, ttl = await measure_latency(
            device.ip, options.latency_samples, options.port_timeout, pinger, tcp_ports
          )
          apply_ttl(device, ttl)
        if hostname is not None:
          device.hostname, device.hostname_source = await hostname
        if services is not None:
          device.services = await services
      self.progress.advance()

    try:
      await asyncio.gather(*(enrich(d) for d in devices))
    finally:
      if resolver is not None:
        resolver.close()

  @staticmethod
  def _describe_local(device: Device) -> None:
    device.hostname = clean_hostname(socket.gethostname())
    device.hostname_source = "local" if device.hostname else None
    device.os_guess = f"{platform.system()} {platform.release()}".strip().lower() or None

  # identity and presence ->
  @staticmethod
  def _identity_candidates(previous: dict[str, Device], devices: dict[str, Device]) -> dict[str, IdentityMatch]:
    """new randomized devices that are probably a known randomized one that vanished in this same scan.

    a known device still present can never be the same one, so only those that are gone are
    candidates. if several newcomers point at the same candidate, nobody is sure: none is linked.
    """
    gone = [d for key, d in previous.items() if key not in devices and d.randomized_mac and not d.is_local]
    newcomers = [d for key, d in devices.items() if key not in previous and d.randomized_mac and not d.is_local]
    resolver = IdentityResolver()
    found = {d.key: match for d in newcomers if (match := resolver.best(d, gone)) is not None}
    taken = [m.candidate_key for m in found.values()]
    return {key: m for key, m in found.items() if taken.count(m.candidate_key) == 1}

  def _presence_events(
    self, previous: dict[str, Device], devices: dict[str, Device], network: IPv4Network, now: datetime
  ) -> list[Event]:
    """unusual-presence for devices that just came back and routine-broken for always-on ones that vanished."""
    arrivals = [d for key, d in devices.items() if key in previous and previous[key].status == DeviceStatus.OFFLINE]
    absent = [
      d
      for key, d in previous.items()
      if key not in devices
      and d.last_seen is not None
      and now - d.last_seen <= MAX_ROUTINE_ABSENCE
      and IPv4Address(d.ip) in network
    ]
    subjects = [d for d in [*arrivals, *absent] if is_profilable(d)]
    if not subjects:
      return []
    sessions = self.repository.sessions_by_identity(subjects, since=now - timedelta(weeks=PROFILE_WEEKS))
    profiles = {d.key: build_profile(sessions[d.key], now) for d in subjects}
    flagged = {
      d.key
      for d in absent
      if d.last_seen and self.repository.has_event_since(d.key, EventType.ROUTINE_BROKEN, d.last_seen)
    }
    return detect_anomalies(profiles, arrivals, absent, now, flagged)

  # history ->
  @staticmethod
  def _carry_history(previous: dict[str, Device], devices: dict[str, Device], ports_scanned: bool, now) -> None:
    """keep identity data (alias, trust, first seen) and anything this scan did not refresh."""
    for key, device in devices.items():
      device.status = DeviceStatus.ONLINE
      device.last_seen = now
      old = previous.get(key)
      if old is None:
        device.first_seen = now
        device.trusted = device.is_local
        continue
      device.first_seen = old.first_seen or now
      device.alias = old.alias
      device.trusted = old.trusted
      device.identity_id = old.identity_id
      if not device.services:
        device.services = old.services
      if not ports_scanned:
        device.ports = old.ports
      if device.hostname is None and old.hostname:
        device.hostname, device.hostname_source = old.hostname, old.hostname_source
