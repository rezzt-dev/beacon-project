 # import libraries ->
import random
import re

from beacon.scanners.hostname import MDNS_PORT, udp_request
from beacon.scanners.protocols.dns import DnsParseError, build_query, parse_ptr_records


 # constants ->
SERVICE_ENUMERATION = "_services._dns-sd._udp.local"
MAX_SERVICES = 32
_SERVICE_TYPE = re.compile(r"^_[a-z0-9][a-z0-9-]{0,30}\._(?:tcp|udp)$")


 # parsing ->
def clean_services(names: list[str]) -> list[str]:
  """keep well-formed service types (`_airplay._tcp`), deduplicated, sorted and capped: replies are untrusted."""
  found = set()
  for name in names:
    service = name.strip().rstrip(".").lower().removesuffix(".local")
    if _SERVICE_TYPE.match(service):
      found.add(service)
  return sorted(found)[:MAX_SERVICES]


 # discovery ->
async def discover_services(ip: str, timeout: float = 1.5, port: int = MDNS_PORT) -> list[str]:
  """service types a host announces over mdns, by unicast query so no multicast access is needed.

  silence is normal (mdns blocked, client isolation, a device that does not speak it) and
  returns an empty list: the fingerprint just loses this trait.
  """
  query = build_query(SERVICE_ENUMERATION, txid=random.randrange(1, 0x10000), unicast_response=True)
  reply = await udp_request(ip, port, query, timeout, retries=0)
  if reply is None:
    return []
  try:
    return clean_services(parse_ptr_records(reply))
  except DnsParseError:
    return []
