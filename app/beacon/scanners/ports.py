 # import libraries ->
import asyncio
import contextlib
import errno
import socket
import time
from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field

from beacon.core.engine import clean_banner
from beacon.core.exposure import observed_protocol
from beacon.core.models import PortInfo, PortState
from beacon.core.ports import PortSet


 # constants ->
TOP_PORTS: tuple[int, ...] = (
  7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
  144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
  873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1883, 1900,
  2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
  5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080,
  8081, 8123, 8443, 8888, 9090, 9100, 9999, 10000, 27017, 32400, 32768, 49152, 49153, 49154,
  62078,
)
PORT_PRESETS: dict[str, tuple[int, ...]] = {
  "top": TOP_PORTS,
  "top100": TOP_PORTS,
  "web": (80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9090),
  "admin": (22, 23, 135, 139, 445, 3389, 5800, 5900, 5985, 5986),
  "iot": (80, 443, 554, 1883, 1900, 5353, 8008, 8009, 8080, 8123, 8883, 9100, 49152, 62078),
  "all": tuple(range(1, 65536)),
}
HTTP_PORTS = frozenset({80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8888, 9090, 32400})
LIVENESS_PORTS: tuple[int, ...] = (80, 443, 22, 445, 139, 62078, 8080)
KNOWN_SERVICES: dict[int, str] = {
  1883: "mqtt",
  3000: "http-alt",
  5000: "upnp/http",
  5357: "wsdapi",
  8008: "http-alt",
  8009: "ajp/cast",
  8123: "home-assistant",
  8883: "mqtt-tls",
  9100: "jetdirect",
  32400: "plex",
  49152: "upnp",
  62078: "iphone-sync",
}


 # port specs ->
def parse_port_spec(spec: str) -> list[int]:
  """parse `top`, `web`, `all`, `22,80,443` or `1-1024` (combinable with commas)."""
  ports: set[int] = set()
  for token in (t.strip().lower() for t in spec.split(",")):
    if not token:
      continue
    if token in PORT_PRESETS:
      ports.update(PORT_PRESETS[token])
    elif "-" in token:
      start_text, _, end_text = token.partition("-")
      start, end = int(start_text), int(end_text)
      if not 1 <= start <= end <= 65535:
        raise ValueError(f"invalid port range {token!r}")
      ports.update(range(start, end + 1))
    else:
      port = int(token)
      if not 1 <= port <= 65535:
        raise ValueError(f"invalid port {token!r}")
      ports.add(port)
  if not ports:
    raise ValueError("empty port specification")
  return sorted(ports)


def service_name(port: int) -> str | None:
  if port in KNOWN_SERVICES:
    return KNOWN_SERVICES[port]
  try:
    return socket.getservbyport(port, "tcp")
  except OSError:
    return None


 # tcp connect primitives ->
async def _close(writer: asyncio.StreamWriter) -> None:
  writer.close()
  with contextlib.suppress(Exception):
    await asyncio.wait_for(writer.wait_closed(), 1.0)


async def tcp_rtt(ip: str, port: int, timeout: float) -> float | None:
  """round trip of a tcp handshake; a refused connection (rst) also proves the host is up."""
  started = time.perf_counter()
  try:
    _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
  except ConnectionRefusedError:
    return (time.perf_counter() - started) * 1000
  except (TimeoutError, OSError):
    return None
  elapsed = (time.perf_counter() - started) * 1000
  await _close(writer)
  return elapsed


async def tcp_alive(ip: str, ports: Sequence[int] = LIVENESS_PORTS, timeout: float = 1.0) -> float | None:
  """first successful rtt among `ports`, probed concurrently."""
  pending = {asyncio.create_task(tcp_rtt(ip, port, timeout)) for port in ports}
  try:
    while pending:
      done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
      for task in done:
        if (rtt := task.result()) is not None:
          return rtt
    return None
  finally:
    for task in pending:
      task.cancel()


 # banner grabbing ->
def _summarize_http(data: bytes) -> str:
  lines = data.decode("latin-1", errors="replace").splitlines()
  status = lines[0].strip() if lines else ""
  server = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("server:")), None)
  return f"{status} | server: {server}" if server else status


async def read_banner(
  reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str, port: int, timeout: float
) -> tuple[str | None, str | None]:
  """`(banner, observed protocol)` from the first bytes a service sends (or answers to a http get)."""
  data = b""
  with contextlib.suppress(TimeoutError, OSError):
    data = await asyncio.wait_for(reader.read(512), timeout)
  if not data and port in HTTP_PORTS:
    with contextlib.suppress(TimeoutError, OSError):
      writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: beacon\r\n\r\n".encode())
      await writer.drain()
      data = await asyncio.wait_for(reader.read(1024), timeout)
  protocol = observed_protocol(data)
  if data.startswith(b"HTTP/"):
    return clean_banner(_summarize_http(data)), protocol
  if protocol in ("telnet", "tls"):
    return None, protocol  # negotiation bytes, not text
  return clean_banner(data), protocol


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str, port: int, timeout: float) -> str | None:
  return (await read_banner(reader, writer, ip, port, timeout))[0]


 # port scanning ->
# errors that come from the path or the local stack, not from the port: they prove nothing about it
_LOCAL_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENOBUFS, errno.EMFILE, errno.ENFILE, errno.EADDRNOTAVAIL}


async def probe_port(ip: str, port: int, timeout: float, banner_timeout: float | None = None) -> PortInfo:
  """one tcp connect: open, closed (refused), filtered (silence) or error (the probe itself failed)."""
  started = time.perf_counter()
  try:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
  except ConnectionRefusedError:
    return PortInfo(port=port, state=PortState.CLOSED)
  except TimeoutError:
    return PortInfo(port=port, state=PortState.FILTERED)
  except OSError as exc:
    state = PortState.ERROR if exc.errno in _LOCAL_ERRNOS else PortState.FILTERED
    return PortInfo(port=port, state=state)
  rtt = (time.perf_counter() - started) * 1000
  banner = protocol = None
  try:
    if banner_timeout:
      banner, protocol = await read_banner(reader, writer, ip, port, banner_timeout)
  finally:
    await _close(writer)
  return PortInfo(
    port=port, state=PortState.OPEN, service=service_name(port), banner=banner, rtt_ms=rtt, protocol_observed=protocol
  )


@dataclass(slots=True)
class PortScanResult:
  """what one host scan measured: every open port, every tracked port whatever its state, and totals."""

  examined: PortSet
  ports: list[PortInfo] = field(default_factory=list)
  counts: Counter[str] = field(default_factory=Counter)

  @property
  def open(self) -> list[PortInfo]:
    return [p for p in self.ports if p.state == PortState.OPEN]


async def scan_host_ports(
  ip: str,
  ports: Iterable[int],
  timeout: float = 1.0,
  semaphore: asyncio.Semaphore | None = None,
  banner_timeout: float | None = 1.5,
  workers: int = 256,
  track: Collection[int] = (),
) -> PortScanResult:
  """concurrent tcp connect scan of one host.

  open ports are always reported; closed, filtered and failed probes only for ports in `track`
  (the ports already known for this host), so a scan of 65535 ports keeps memory flat while a
  known port that closed is still noticed. a fixed pool of workers pulls ports from a shared
  iterator and the optional semaphore caps sockets across every host scanned at the same time.
  """
  port_list = list(ports)
  result = PortScanResult(examined=PortSet(port_list))
  queue = iter(port_list)
  tracked = set(track)
  limiter = semaphore or asyncio.Semaphore(workers)

  async def worker() -> None:
    for port in queue:
      async with limiter:
        probe = await probe_port(ip, port, timeout, banner_timeout)
      result.counts[str(probe.state)] += 1
      if probe.state == PortState.OPEN or port in tracked:
        result.ports.append(probe)

  await asyncio.gather(*(worker() for _ in range(max(1, min(workers, len(port_list))))))
  result.ports.sort(key=lambda p: p.port)
  return result


async def scan_ports(
  ip: str,
  ports: Iterable[int],
  timeout: float = 1.0,
  semaphore: asyncio.Semaphore | None = None,
  banner_timeout: float | None = 1.5,
  workers: int = 256,
) -> list[PortInfo]:
  """concurrent tcp connect scan of one host; returns only open ports."""
  return (await scan_host_ports(ip, ports, timeout, semaphore, banner_timeout, workers)).open
