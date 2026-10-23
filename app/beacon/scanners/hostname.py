 # import libraries ->
import asyncio
import logging
import random
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from beacon.core.engine import clean_hostname
from beacon.scanners.protocols.dns import (
  DnsParseError,
  build_query,
  parse_ptr_response,
  reverse_pointer,
)
from beacon.scanners.protocols.netbios import (
  build_nbstat_query,
  parse_nbstat_response,
  workstation_name,
)


log = logging.getLogger(__name__)


 # constants ->
MDNS_PORT = 5353
NETBIOS_NS_PORT = 137


 # udp request helper ->
class _FirstDatagram(asyncio.DatagramProtocol):
  def __init__(self, future: asyncio.Future[bytes]) -> None:
    self.future = future

  def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
    if not self.future.done():
      self.future.set_result(data)

  def error_received(self, exc: Exception) -> None:
    if not self.future.done():
      self.future.set_exception(exc)


async def udp_request(ip: str, port: int, payload: bytes, timeout: float = 1.0, retries: int = 1) -> bytes | None:
  """send one datagram and wait for the first reply from the same `(ip, port)`."""
  loop = asyncio.get_running_loop()
  future: asyncio.Future[bytes] = loop.create_future()
  try:
    transport, _ = await loop.create_datagram_endpoint(lambda: _FirstDatagram(future), remote_addr=(ip, port))
  except OSError:
    return None
  try:
    for _ in range(retries + 1):
      transport.sendto(payload)
      try:
        return await asyncio.wait_for(asyncio.shield(future), timeout)
      except TimeoutError:
        continue
      except OSError:
        return None
    return None
  finally:
    transport.close()


 # resolver ->
class HostnameResolver:
  """resolve a friendly name per host: reverse dns, then mdns, then netbios.

  the three lookups run concurrently and the first valid answer by priority wins.
  reverse dns uses blocking libc calls, so it gets a dedicated thread pool.
  """

  def __init__(self, timeout: float = 1.5, workers: int = 32) -> None:
    self.timeout = timeout
    self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="beacon-dns")

  def close(self) -> None:
    self._executor.shutdown(wait=False, cancel_futures=True)

  async def resolve(self, ip: str) -> tuple[str | None, str | None]:
    lookups = (("dns", self.reverse_dns(ip)), ("mdns", self.mdns(ip)), ("netbios", self.netbios(ip)))
    results = await asyncio.gather(*(coro for _, coro in lookups), return_exceptions=True)
    for (source, _), result in zip(lookups, results, strict=True):
      if isinstance(result, BaseException):
        log.debug("%s lookup for %s failed: %s", source, ip, result)
        continue
      if name := clean_hostname(result, ip):
        return name, source
    return None, None

  async def reverse_dns(self, ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
      name, _aliases, _addrs = await asyncio.wait_for(
        loop.run_in_executor(self._executor, socket.gethostbyaddr, ip), self.timeout
      )
    except (TimeoutError, OSError):
      return None
    return name

  async def mdns(self, ip: str) -> str | None:
    txid = random.randrange(1, 0x10000)
    query = build_query(reverse_pointer(ip), txid=txid, unicast_response=True)
    reply = await udp_request(ip, MDNS_PORT, query, self.timeout, retries=0)
    if reply is None:
      return None
    try:
      return parse_ptr_response(reply)
    except DnsParseError:
      return None

  async def netbios(self, ip: str) -> str | None:
    reply = await udp_request(ip, NETBIOS_NS_PORT, build_nbstat_query(random.randrange(1, 0x10000)), self.timeout, retries=0)
    if reply is None:
      return None
    try:
      return workstation_name(parse_nbstat_response(reply))
    except DnsParseError:
      return None
