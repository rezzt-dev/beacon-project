 # import libraries ->
import asyncio
import contextlib
import logging
import platform
import socket
import time
from collections.abc import Awaitable, Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Protocol, TypeVar

from beacon.core.diff import detect_changes
from beacon.core.engine import CleaningEngine, apply_ttl, clean_hostname
from beacon.core.events import Event, EventBus, EventType, Severity
from beacon.core.identity import IdentityMatch, IdentityResolver
from beacon.core.models import (
  Device,
  DeviceStatus,
  DiscoverySource,
  Observation,
  PortInfo,
  ScanMode,
  utcnow,
)
from beacon.core.ports import PortSet, merge_ports
from beacon.core.presence import (
  MAX_ROUTINE_ABSENCE,
  PROFILE_WEEKS,
  SESSION_GAP,
  build_profile,
  detect_anomalies,
  is_profilable,
)
from beacon.core.report import ScanIssue, ScanReport, ScanStatus
from beacon.core.vendors import VendorDatabase
from beacon.scanners.arp import arp_sweep, read_arp_table
from beacon.scanners.hostname import HostnameResolver
from beacon.scanners.icmp import IcmpPinger
from beacon.scanners.latency import measure_latency
from beacon.scanners.network import InterfaceInfo, iter_hosts, list_interfaces, resolve_target
from beacon.scanners.ports import scan_host_ports, tcp_alive
from beacon.scanners.privileges import privileged_mode_available
from beacon.scanners.services import discover_services
from beacon.storage.repository import Repository


log = logging.getLogger(__name__)
T = TypeVar("T")
R = TypeVar("R")


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
  sweep_concurrency: int = 256
  latency_samples: int = 3
  offline_grace: float = 0.0
  resolve_hostnames: bool = True
  grab_banners: bool = True
  identity: bool = True
  presence: bool = True
  presence_gap: float = SESSION_GAP.total_seconds()
  save: bool = True
  # addresses or ranges never probed (when the protocol allows it) and always dropped from results
  exclude: Sequence[str] = ()
  trigger: str = "cli"
  profile_id: int | None = None
  network_id: int | None = None
  tls: bool = True
  ipv6: bool = True


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


 # bounded concurrency ->
async def run_pool(items: Iterable[T], worker: Callable[[T], Awaitable[R | None]], concurrency: int) -> list[R]:
  """run `worker` over `items` with at most `concurrency` in flight.

  a fixed set of tasks pulls from one iterator, so a /16 sweep never creates 65k tasks at once
  (a semaphore alone would still allocate them all up front).
  """
  iterator: Iterator[T] = iter(items)
  results: list[R] = []

  async def run() -> None:
    for item in iterator:
      value = await worker(item)
      if value is not None:
        results.append(value)

  await asyncio.gather(*(run() for _ in range(max(1, concurrency))))
  return results


def _excluder(exclude: Sequence[str]) -> Callable[[str], bool]:
  networks = [ip_network(item, strict=False) for item in exclude]
  if not networks:
    return lambda _ip: False

  def excluded(ip: str) -> bool:
    try:
      address = IPv4Address(ip)
    except ValueError:
      return False
    return any(address in n for n in networks)

  return excluded


 # pipeline ->
@dataclass(slots=True)
class ScanPipeline:
  """orchestrates one scan: discover -> clean -> enrich -> diff -> persist -> publish.

  every scan leaves a row in the history with an honest status: complete, partial (some hosts or
  stages failed), failed or cancelled. only what was really measured changes the inventory.
  """

  repository: Repository
  vendors: VendorDatabase
  bus: EventBus = field(default_factory=EventBus)
  progress: ProgressReporter = field(default_factory=NullProgress)
  # called with the saved report (alerts, exports); a failing hook is logged, never fatal
  after_save: list[Callable[[ScanReport], None]] = field(default_factory=list)
  _report: ScanReport | None = field(default=None, init=False, repr=False)
  _current_stage: str | None = field(default=None, init=False, repr=False)
  _stage_started: float = field(default=0.0, init=False, repr=False)
  _clock_start: float = field(default=0.0, init=False, repr=False)

  async def run(self, options: ScanOptions) -> ScanReport:
    started = utcnow()
    self._clock_start = time.monotonic()
    report = ScanReport(network=options.target or "?", mode=options.mode, started_at=started, trigger=options.trigger)
    report.profile_id = options.profile_id
    report.port_spec = PortSet(options.ports)
    self._report = report
    try:
      iface, network = resolve_target(options.target, options.interface)
      privileged = self._resolve_mode(options.mode)
    except Exception as exc:
      self._fail(report, options, ScanStatus.FAILED, exc)
      raise
    report.network = str(network)
    report.target = str(network)
    report.mode = ScanMode.PRIVILEGED if privileged else ScanMode.UNPRIVILEGED
    report.interface = iface.name
    report.local_ip = str(iface.ip)
    if options.save:
      report.network_id = options.network_id
      report.scan_id = self.repository.begin_scan(report)
    try:
      return await self._run(report, options, iface, network, privileged)
    except asyncio.CancelledError:
      self._fail(report, options, ScanStatus.CANCELLED, None)
      raise
    except Exception as exc:
      self._fail(report, options, ScanStatus.FAILED, exc)
      raise
    finally:
      self._report = None

  def _fail(self, report: ScanReport, options: ScanOptions, status: ScanStatus, exc: BaseException | None) -> None:
    """a scan that changed nothing still leaves a trace: a monitoring gap is not an absence of devices."""
    stage = self._current_stage or "setup"
    self._close_stage()
    report.status = status
    if exc is not None:
      report.issues.append(ScanIssue(stage, f"{type(exc).__name__}: {exc}"))
    if not options.save:
      return
    try:
      report.scan_id = self.repository.end_scan(
        report.scan_id,
        status,
        report.issues,
        report.stages,
        network=report.network,
        started_at=report.started_at,
        trigger=report.trigger,
        network_id=report.network_id,
      )
      if status == ScanStatus.FAILED and self._previous_was_valid(report):
        message = f"scan of {report.network} failed: {report.issues[-1].message if report.issues else 'unknown error'}"
        event = Event(EventType.SCAN_FAILED, Severity.WARNING, message, details={"scan_id": report.scan_id})
        self.repository.record_events([event], report.scan_id, report.network_id)
        self.bus.publish(event)
    except Exception:  # recording the failure must never hide the original error
      log.exception("could not record the %s scan", status)

  def _previous_was_valid(self, report: ScanReport) -> bool:
    """only the first failure in a row is an event; a watch loop retrying an absent interface stays quiet."""
    previous = [s for s in self.repository.list_scans(limit=2) if s["id"] != report.scan_id]
    return not previous or previous[0]["status"] in (str(ScanStatus.COMPLETE), str(ScanStatus.PARTIAL))

  async def _run(
    self, report: ScanReport, options: ScanOptions, iface: InterfaceInfo, network: IPv4Network, privileged: bool
  ) -> ScanReport:
    excluded = _excluder(options.exclude)
    pinger = IcmpPinger.open()
    try:
      observations = await self._discover(network, iface, privileged, pinger, options)
      observations = [o for o in observations if not excluded(o.ip)]
      if pinger is not None:
        report.unobserved = set(pinger.unsent)
      merged = CleaningEngine(self.vendors, network).merge(observations)
      report.first_result_after = time.monotonic() - self._clock_start
      gateway = next((d for d in merged.devices.values() if iface.gateway is not None and d.ip == str(iface.gateway)), None)
      if options.network_id is not None:
        report.network_id = options.network_id
      else:
        scope = iface.network if network.subnet_of(iface.network) else network
        report.network_id = self.repository.resolve_network(
          str(scope),
          iface.name,
          str(iface.gateway) if iface.gateway else None,
          gateway.mac if gateway else None,
          create=options.save,
        )
      devices: dict[str, Device] = {}
      for device in merged.devices.values():
        if report.network_id is not None:
          device.network_id = report.network_id
        device.is_gateway = iface.gateway is not None and device.ip == str(iface.gateway)
        devices[device.key] = device
      # a dry run on a network never seen before has no history to compare with
      previous = self.repository.load_devices(report.network_id) if report.network_id is not None else {}
      examined_before = self.repository.port_coverage(devices.keys()) if options.ports else {}
      router = str(iface.gateway) if iface.gateway is not None else None
      await self._enrich(list(devices.values()), options, pinger, router, previous)
    finally:
      if pinger is not None:
        pinger.close()
    if options.ipv6:
      await self._neighbors6(iface, devices)

    report.first_run = not previous
    now = utcnow()
    with self._stage("diff"):
      report.events = detect_changes(
        previous,
        devices,
        merged.conflicts,
        network,
        report.port_spec,
        offline_grace=timedelta(seconds=options.offline_grace),
        now=now,
        identity_candidates=self._identity_candidates(previous, devices) if options.identity else None,
        examined_before={k: v[0] for k, v in examined_before.items()},
        unobserved=report.unobserved,
      )
      self._carry_history(previous, devices, report, now)
      if options.presence:
        gap = timedelta(seconds=options.presence_gap)
        report.events += self._presence_events(previous, devices, network, now, gap, report.network_id)
    if report.issues and report.status == ScanStatus.COMPLETE:
      report.status = ScanStatus.PARTIAL
    if report.unobserved:
      report.status = ScanStatus.PARTIAL
      report.issues.append(
        ScanIssue("discovery", f"{len(report.unobserved)} addresses could not be probed; they are not reported offline")
      )
    if report.status == ScanStatus.PARTIAL and report.issues:
      summary = "; ".join(i.message for i in report.issues[:3])
      report.events.append(
        Event(EventType.SCAN_PARTIAL, Severity.INFO, f"scan of {report.network} was incomplete: {summary}", details={"issues": len(report.issues)})
      )

    report.devices = sorted(devices.values(), key=lambda d: IPv4Address(d.ip))
    report.conflicts = merged.conflicts
    report.discarded = merged.discarded
    self._close_stage()
    report.finished_at = now
    if options.save:
      with self._stage("save"):
        report.scan_id = self.repository.save_scan(
          report, presence=options.presence, presence_gap=timedelta(seconds=options.presence_gap)
        )
      self._close_stage()
      for hook in self.after_save:
        try:
          hook(report)
        except Exception:
          log.exception("after-save hook failed")
    self.bus.publish_many(report.events)
    return report

  # stages ->
  @contextlib.contextmanager
  def _stage(self, name: str, total: int | None = None):
    self._open_stage(name, total)
    yield

  def _open_stage(self, name: str, total: int | None = None) -> None:
    self._close_stage()
    self._current_stage = name
    self._stage_started = time.monotonic()
    self.progress.stage(name, total)
    report = self._report
    if report is not None and report.scan_id is not None:
      with contextlib.suppress(Exception):
        self.repository.heartbeat_scan(report.scan_id, name)

  def _close_stage(self) -> None:
    report = self._report
    if self._current_stage is not None and report is not None:
      elapsed = time.monotonic() - self._stage_started
      report.stages[self._current_stage] = report.stages.get(self._current_stage, 0.0) + elapsed
    self._current_stage = None

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
    excluded = _excluder(options.exclude)
    # every address of this host is one device, never a separate "unknown" one
    local_ips = [iface.ip, *sorted({i.ip for i in list_interfaces() if i.name == iface.name} - {iface.ip})]
    for ip in local_ips:
      if ip in network:
        observations.append(Observation(ip=str(ip), mac=iface.mac, source=DiscoverySource.LOCAL))

    if privileged:
      self._open_stage("arp sweep", None)
      observations += await arp_sweep(network, iface.name, options.discovery_timeout)
      return observations

    hosts = [str(h) for h in iter_hosts(network) if h not in local_ips and not excluded(str(h))]
    if pinger is not None:
      self._open_stage("icmp sweep", len(hosts))
      observations += await self._icmp_sweep(hosts, pinger, options)
    else:
      self._open_stage("arp cache priming", None)
      await self._prime_arp_cache(hosts, options.discovery_timeout)

    table = read_arp_table(iface.name if network.overlaps(iface.network) else None)
    observations += table
    confirmed = {o.ip for o in observations if o.fresh}
    stale = sorted(
      {o.ip for o in table if not o.fresh and o.ip not in confirmed and IPv4Address(o.ip) in network and not excluded(o.ip)}
    )
    if stale:
      self._open_stage("confirming cached entries", len(stale))
      observations += await self._tcp_confirm(stale, options)
    return observations

  async def _icmp_sweep(self, hosts: list[str], pinger: IcmpPinger, options: ScanOptions) -> list[Observation]:
    async def probe(ip: str) -> Observation | None:
      reply = await pinger.ping(ip, options.discovery_timeout)
      self.progress.advance()
      if reply is None:
        return None
      return Observation(ip=ip, source=DiscoverySource.ICMP, ttl=reply.ttl, rtt_ms=reply.rtt_ms)

    return await run_pool(hosts, probe, options.sweep_concurrency)

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
    async def confirm(ip: str) -> Observation | None:
      rtt = await tcp_alive(ip, timeout=options.port_timeout)
      self.progress.advance()
      return Observation(ip=ip, source=DiscoverySource.TCP, rtt_ms=rtt) if rtt is not None else None

    return await run_pool(ips, confirm, options.host_concurrency)

  # enrichment ->
  async def _enrich(
    self,
    devices: list[Device],
    options: ScanOptions,
    pinger: IcmpPinger | None,
    router: str | None = None,
    previous: dict[str, Device] | None = None,
  ) -> None:
    previous = previous or {}
    report = self._report
    port_limiter = asyncio.Semaphore(options.port_concurrency)
    resolver = HostnameResolver(router=router) if options.resolve_hostnames else None
    banner_timeout = 1.5 if options.grab_banners else None
    self._open_stage("enriching devices", len(devices))

    async def enrich(device: Device) -> None:
      try:
        await self._enrich_one(device, options, pinger, resolver, port_limiter, banner_timeout, previous.get(device.key))
      except asyncio.CancelledError:
        raise
      except Exception as exc:  # one broken host must not sink the scan
        log.debug("enrichment of %s failed", device.ip, exc_info=True)
        if report is not None:
          report.issues.append(ScanIssue("enrich", f"{type(exc).__name__}: {exc}", device.ip))
      finally:
        self.progress.advance()

    try:
      await run_pool(devices, enrich, options.host_concurrency)
    finally:
      if resolver is not None:
        resolver.close()

  async def _enrich_one(
    self,
    device: Device,
    options: ScanOptions,
    pinger: IcmpPinger | None,
    resolver: HostnameResolver | None,
    port_limiter: asyncio.Semaphore,
    banner_timeout: float | None,
    old: Device | None,
  ) -> None:
    report = self._report
    if device.is_local:
      self._describe_local(device)
    hostname = asyncio.create_task(resolver.resolve(device.ip)) if resolver and not device.hostname else None
    # a randomized mac says nothing about the device, so the services it announces help recognize it later
    services = (
      asyncio.create_task(discover_services(device.ip, options.discovery_timeout))
      if options.identity and device.randomized_mac and not device.is_local
      else None
    )
    try:
      if options.ports:
        known = [p.port for p in old.ports] if old else []
        try:
          result = await scan_host_ports(
            device.ip, options.ports, options.port_timeout, port_limiter, banner_timeout, track=known
          )
        except (OSError, RuntimeError) as exc:
          if report is not None:
            report.issues.append(ScanIssue("ports", f"{type(exc).__name__}: {exc}", device.ip))
          device.ports = []
        else:
          device.ports = result.ports
          if report is not None:
            report.port_counts[device.key] = dict(result.counts)
          if options.tls:
            await self._tls(device, options)
      if options.latency_samples > 0 and not device.is_local:
        tcp_ports = [p.port for p in device.open_ports]
        device.latency, ttl = await measure_latency(device.ip, options.latency_samples, options.port_timeout, pinger, tcp_ports)
        apply_ttl(device, ttl)
      if hostname is not None:
        device.hostname, device.hostname_source = await hostname
      if services is not None:
        device.services = await services
    finally:
      for task in (hostname, services):
        if task is not None and not task.done():
          task.cancel()

  async def _tls(self, device: Device, options: ScanOptions) -> None:
    """certificate details of open tls ports; best effort, bounded in time and size."""
    from beacon.scanners.tls import TLS_PORTS, fetch_certificate

    for port in device.open_ports:
      if port.port in TLS_PORTS or port.protocol_observed == "tls":
        port.tls = await fetch_certificate(device.ip, port.port, timeout=options.port_timeout + 1.0)

  async def _neighbors6(self, iface: InterfaceInfo, devices: dict[str, Device]) -> None:
    """ipv6 addresses from the neighbour table, attached by mac. a /64 is never enumerated."""
    from beacon.scanners.ipv6 import neighbours6, solicit_all_nodes

    try:
      self._open_stage("ipv6 neighbours", None)
      await solicit_all_nodes(iface.name)
      table = await asyncio.to_thread(neighbours6, iface.name)
    except Exception:  # ipv6 is optional: no tool, no permission, no address
      log.debug("ipv6 neighbour discovery failed", exc_info=True)
      return
    by_mac: dict[str, list[str]] = {}
    for address, mac in table:
      by_mac.setdefault(mac, []).append(address)
    for device in devices.values():
      if device.mac and device.mac in by_mac:
        device.ips6 = sorted(set(by_mac[device.mac]))

  @staticmethod
  def _describe_local(device: Device) -> None:
    device.hostname = clean_hostname(socket.gethostname())
    device.hostname_source = "local" if device.hostname else None
    device.os_guess = f"{platform.system()} {platform.release()}".strip().lower() or None

  # identity and presence ->
  def _identity_candidates(self, previous: dict[str, Device], devices: dict[str, Device]) -> dict[str, IdentityMatch]:
    """new randomized devices that are probably a known randomized one that vanished in this same scan.

    a known device still present can never be the same one, so only those that are gone are
    candidates. if several newcomers point at the same candidate, nobody is sure: none is linked.
    """
    gone = [d for key, d in previous.items() if key not in devices and d.randomized_mac and not d.is_local]
    newcomers = [d for key, d in devices.items() if key not in previous and d.randomized_mac and not d.is_local]
    if not gone or not newcomers:
      return {}
    rejected = self.repository.rejected_pairs()
    resolver = IdentityResolver()
    found = {
      d.key: match
      for d in newcomers
      if (match := resolver.best(d, [g for g in gone if (d.key, g.key) not in rejected])) is not None
    }
    taken = [m.candidate_key for m in found.values()]
    return {key: m for key, m in found.items() if taken.count(m.candidate_key) == 1}

  def _presence_events(
    self,
    previous: dict[str, Device],
    devices: dict[str, Device],
    network: IPv4Network,
    now: datetime,
    gap: timedelta = SESSION_GAP,
    network_id: int | None = None,
  ) -> list[Event]:
    """unusual-presence for devices that just came back and routine-broken for always-on ones that vanished.

    profiles only count the hours beacon was really watching (completed scans no more than `gap` apart).
    """
    arrivals = [d for key, d in devices.items() if key in previous and previous[key].status == DeviceStatus.OFFLINE]
    absent = [
      d
      for key, d in previous.items()
      if key not in devices
      and d.last_seen is not None
      and now - d.last_seen <= MAX_ROUTINE_ABSENCE
      and IPv4Address(d.ip) in network
      and d.ip not in (self._report.unobserved if self._report else ())
    ]
    subjects = [d for d in [*arrivals, *absent] if is_profilable(d)]
    if not subjects:
      return []
    since = now - timedelta(weeks=PROFILE_WEEKS)
    sessions = self.repository.sessions_by_identity(subjects, since=since)
    observed = self.repository.observation_windows(since, gap, network_id) or None
    profiles = {d.key: build_profile(sessions[d.key], now, observed=observed) for d in subjects}
    flagged = {
      d.key
      for d in absent
      if d.last_seen and self.repository.has_event_since(d.key, EventType.ROUTINE_BROKEN, d.last_seen)
    }
    return detect_anomalies(profiles, arrivals, absent, now, flagged)

  # history ->
  @staticmethod
  def _carry_history(previous: dict[str, Device], devices: dict[str, Device], report: ScanReport, now: datetime) -> None:
    """keep identity data (alias, trust, first seen, notes) and anything this scan did not measure.

    ports are merged, not replaced: only the ports in `report.port_spec` were measured, and a
    host whose port scan failed keeps what was known about it.
    """
    failed_ports = {i.host for i in report.issues if i.stage == "ports"}
    for key, device in devices.items():
      device.status = DeviceStatus.ONLINE
      device.last_seen = now
      old = previous.get(key)
      results: dict[int, PortInfo] = {p.port: p for p in device.ports}
      examined = report.port_spec if device.ip not in failed_ports else PortSet()
      device.ports = merge_ports(old.ports if old else [], results, examined, now)
      if old is None:
        device.first_seen = now
        device.trusted = device.is_local
        continue
      device.first_seen = old.first_seen or now
      device.alias = old.alias
      device.trusted = old.trusted
      device.identity_id = old.identity_id
      device.category, device.tags, device.notes = old.category, old.tags, old.notes
      device.owner, device.essential, device.version = old.owner, old.essential, old.version
      if not device.services:
        device.services = old.services
      if not device.ips6:
        device.ips6 = old.ips6
      if device.hostname is None and old.hostname:
        device.hostname, device.hostname_source = old.hostname, old.hostname_source
