 # import libraries ->
import asyncio
from collections.abc import Sequence

from beacon.core.models import Latency
from beacon.scanners.icmp import IcmpPinger
from beacon.scanners.ports import tcp_rtt


 # constants ->
FALLBACK_TCP_PORTS: tuple[int, ...] = (80, 443, 22)


 # latency measurement ->
async def measure_latency(
  ip: str,
  samples: int = 4,
  timeout: float = 1.0,
  pinger: IcmpPinger | None = None,
  tcp_ports: Sequence[int] = (),
  interval: float = 0.2,
) -> tuple[Latency, int | None]:
  """sample the rtt of a host and return `(latency, ttl)`.

  icmp echo is tried first; hosts that drop icmp (windows firewall, many phones)
  fall back to tcp handshake timing on a known open port or a common one.
  """
  if pinger is not None:
    rtts: list[float] = []
    ttl: int | None = None
    for attempt in range(samples):
      reply = await pinger.ping(ip, timeout)
      if reply is not None:
        rtts.append(reply.rtt_ms)
        ttl = ttl or reply.ttl
      if attempt < samples - 1:
        await asyncio.sleep(interval)
    if rtts:
      return Latency(method="icmp", sent=samples, samples=rtts), ttl

  candidates = list(dict.fromkeys([*tcp_ports, *FALLBACK_TCP_PORTS]))
  for port in candidates[:4]:
    first = await tcp_rtt(ip, port, timeout)
    if first is None:
      continue
    rtts = [first]
    for _ in range(samples - 1):
      await asyncio.sleep(interval)
      if (rtt := await tcp_rtt(ip, port, timeout)) is not None:
        rtts.append(rtt)
    return Latency(method=f"tcp/{port}", sent=samples, samples=rtts), None

  return Latency(method="icmp" if pinger else "tcp", sent=samples), None
