 # import libraries ->
import asyncio
import contextlib
import socket
import time
from collections.abc import Iterable, Sequence

from beacon.core.engine import clean_banner
from beacon.core.models import PortInfo, PortState


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


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str, port: int, timeout: float) -> str | None:
  data = b""
  with contextlib.suppress(TimeoutError, OSError):
    data = await asyncio.wait_for(reader.read(512), timeout)
  if not data and port in HTTP_PORTS:
    with contextlib.suppress(TimeoutError, OSError):
      writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: beacon\r\n\r\n".encode())
      await writer.drain()
      data = await asyncio.wait_for(reader.read(1024), timeout)
  if data.startswith(b"HTTP/"):
    return clean_banner(_summarize_http(data))
  return clean_banner(data)


 # port scanning ->
async def probe_port(ip: str, port: int, timeout: float, banner_timeout: float | None = None) -> PortInfo:
  started = time.perf_counter()
  try:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
  except ConnectionRefusedError:
    return PortInfo(port=port, state=PortState.CLOSED)
  except (TimeoutError, OSError):
    return PortInfo(port=port, state=PortState.FILTERED)
  rtt = (time.perf_counter() - started) * 1000
  try:
    banner = await grab_banner(reader, writer, ip, port, banner_timeout) if banner_timeout else None
  finally:
    await _close(writer)
  return PortInfo(port=port, state=PortState.OPEN, service=service_name(port), banner=banner, rtt_ms=rtt)


async def scan_ports(
  ip: str,
  ports: Iterable[int],
  timeout: float = 1.0,
  semaphore: asyncio.Semaphore | None = None,
  banner_timeout: float | None = 1.5,
  workers: int = 256,
) -> list[PortInfo]:
  """concurrent tcp connect scan of one host; returns only open ports.

  a fixed pool of workers pulls ports from a shared iterator, so memory stays
  flat even for `all` (65535 ports). the optional semaphore caps sockets
  across every host scanned at the same time.
  """
  queue = iter(ports)
  found: list[PortInfo] = []
  limiter = semaphore or asyncio.Semaphore(workers)

  async def worker() -> None:
    for port in queue:
      async with limiter:
        result = await probe_port(ip, port, timeout, banner_timeout)
      if result.state == PortState.OPEN:
        found.append(result)

  await asyncio.gather(*(worker() for _ in range(workers)))
  return sorted(found, key=lambda p: p.port)
