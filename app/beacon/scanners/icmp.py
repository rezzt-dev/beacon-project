 # import libraries ->
import asyncio
import contextlib
import logging
import os
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass


log = logging.getLogger(__name__)


 # constants ->
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
PAYLOAD = b"beacon-probe"
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12 if sys.platform.startswith("linux") else None)
SOCKET_POOL = 4
SEND_WINDOW = 6.0


 # packet building and parsing ->
def checksum(data: bytes) -> int:
  """rfc 1071 internet checksum."""
  if len(data) % 2:
    data += b"\x00"
  total = sum(struct.unpack(f"!{len(data) // 2}H", data))
  total = (total >> 16) + (total & 0xFFFF)
  total += total >> 16
  return ~total & 0xFFFF


def build_echo_request(ident: int, seq: int, payload: bytes = PAYLOAD) -> bytes:
  header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
  return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum(header + payload), ident, seq) + payload


def parse_echo_reply(data: bytes) -> tuple[int, int, int | None] | None:
  """return `(ident, seq, ttl)` for an echo reply; the ip header is optional (raw vs dgram)."""
  ttl = None
  if len(data) >= 20 and data[0] >> 4 == 4:
    header_length = (data[0] & 0x0F) * 4
    ttl = data[8]
    data = data[header_length:]
  if len(data) < 8:
    return None
  kind, _code, _checksum, ident, seq = struct.unpack("!BBHHH", data[:8])
  if kind != ICMP_ECHO_REPLY:
    return None
  return ident, seq, ttl


 # pinger ->
@dataclass(frozen=True, slots=True)
class PingReply:
  rtt_ms: float
  ttl: int | None


class IcmpPinger:
  """asyncio icmp echo client multiplexing every in-flight probe over a small socket pool.

  prefers unprivileged `SOCK_DGRAM` icmp sockets (linux `ping_group_range`, macos)
  and falls back to `SOCK_RAW` when running as root. replies are matched by
  `(source ip, sequence)`.

  echo requests to addresses that never answer arp stay queued in the kernel for
  ~3s and keep consuming the socket send buffer (~220 packets each), so sends
  that hit `EAGAIN` are retried within `SEND_WINDOW` and the pool spreads load.
  """

  def __init__(self, sockets: list[socket.socket], mode: str) -> None:
    self._sockets = sockets
    self.mode = mode
    self._ident = os.getpid() & 0xFFFF
    self._seq = random.randrange(0x10000)
    self._waiters: dict[tuple[str, int], asyncio.Future[tuple[float, int | None]]] = {}
    self._loop: asyncio.AbstractEventLoop | None = None

  @classmethod
  def open(cls, pool_size: int = SOCKET_POOL) -> "IcmpPinger | None":
    if sys.platform == "win32":
      return None
    for mode, kind in (("dgram", socket.SOCK_DGRAM), ("raw", socket.SOCK_RAW)):
      sockets: list[socket.socket] = []
      for _ in range(pool_size if mode == "dgram" else 1):
        try:
          sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except OSError:
          break
        sock.setblocking(False)
        if mode == "dgram" and IP_RECVTTL is not None:
          with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
        sockets.append(sock)
      if sockets:
        log.debug("icmp pinger using %d %s socket(s)", len(sockets), mode)
        return cls(sockets, mode)
    return None

  async def __aenter__(self) -> "IcmpPinger":
    self._start()
    return self

  async def __aexit__(self, *_exc: object) -> None:
    self.close()

  def _start(self) -> None:
    if self._loop is None:
      self._loop = asyncio.get_running_loop()
      for sock in self._sockets:
        self._loop.add_reader(sock.fileno(), self._on_readable, sock)

  def close(self) -> None:
    if self._loop is not None:
      for sock in self._sockets:
        self._loop.remove_reader(sock.fileno())
      self._loop = None
    for waiter in self._waiters.values():
      waiter.cancel()
    self._waiters.clear()
    for sock in self._sockets:
      sock.close()

  def _next_seq(self) -> int:
    self._seq = (self._seq + 1) & 0xFFFF
    return self._seq

  def _on_readable(self, sock: socket.socket) -> None:
    while True:
      try:
        data, ancdata, _flags, addr = sock.recvmsg(2048, socket.CMSG_SPACE(4))
      except (BlockingIOError, InterruptedError):
        return
      except OSError as exc:  # queued errors such as ehostunreach after failed arp
        log.debug("icmp receive error: %s", exc)
        continue
      received_at = time.perf_counter()
      parsed = parse_echo_reply(data)
      if parsed is None:
        continue
      ident, seq, ttl = parsed
      if self.mode == "raw" and ident != self._ident:
        continue
      for level, kind, cdata in ancdata:
        if level == socket.IPPROTO_IP and kind in (socket.IP_TTL, IP_RECVTTL) and cdata:
          ttl = cdata[0] if len(cdata) == 1 else int.from_bytes(cdata[:4], sys.byteorder)
      waiter = self._waiters.pop((addr[0], seq), None)
      if waiter is not None and not waiter.done():
        waiter.set_result((received_at, ttl))

  async def _send(self, sock: socket.socket, packet: bytes, ip: str) -> bool:
    assert self._loop is not None
    deadline = self._loop.time() + SEND_WINDOW
    while True:
      try:
        sock.sendto(packet, (ip, 0))
        return True
      except BlockingIOError:
        if self._loop.time() >= deadline:
          return False
        await asyncio.sleep(0.05)
      except OSError:
        return False

  async def ping(self, ip: str, timeout: float = 1.0) -> PingReply | None:
    """send one echo request; the reply timeout starts once the packet left the socket."""
    self._start()
    assert self._loop is not None
    seq = self._next_seq()
    key = (ip, seq)
    waiter = self._loop.create_future()
    self._waiters[key] = waiter
    sock = self._sockets[seq % len(self._sockets)]
    try:
      if not await self._send(sock, build_echo_request(self._ident, seq), ip):
        return None
      started = time.perf_counter()
      received_at, ttl = await asyncio.wait_for(waiter, timeout)
    except (TimeoutError, OSError):
      return None
    finally:
      self._waiters.pop(key, None)
    return PingReply(rtt_ms=max(0.0, received_at - started) * 1000, ttl=ttl)
