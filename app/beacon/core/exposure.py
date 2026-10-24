 # import libraries ->
from dataclasses import dataclass
from enum import StrEnum

from beacon.core.models import PortInfo


 # enums ->
class Exposure(StrEnum):
  """what an open port exposes, independently of whether the transport is encrypted."""

  REMOTE_ADMIN = "remote-admin"
  FILE_SHARING = "file-sharing"
  DATABASE = "database"
  WEB = "web"
  MEDIA = "media"
  MESSAGING = "messaging"
  PRINTING = "printing"
  OTHER = "other"


class Basis(StrEnum):
  """how beacon knows something: measured on the wire, inferred from a convention, or context."""

  OBSERVED = "observed"
  INFERRED = "inferred"
  CONTEXT = "context"
  HISTORY = "history"


 # catalog ->
@dataclass(frozen=True, slots=True)
class ServiceProfile:
  service: str
  exposure: Exposure
  # true: the protocol always encrypts (ssh, tls); false: it is plaintext; none: depends on configuration
  encrypted: bool | None


# a port number is a convention, not a proof: these profiles describe what usually listens there
PORT_PROFILES: dict[int, ServiceProfile] = {
  21: ServiceProfile("ftp", Exposure.FILE_SHARING, False),
  22: ServiceProfile("ssh", Exposure.REMOTE_ADMIN, True),
  23: ServiceProfile("telnet", Exposure.REMOTE_ADMIN, False),
  80: ServiceProfile("http", Exposure.WEB, False),
  139: ServiceProfile("netbios-ssn", Exposure.FILE_SHARING, False),
  443: ServiceProfile("https", Exposure.WEB, True),
  445: ServiceProfile("smb", Exposure.FILE_SHARING, None),
  548: ServiceProfile("afp", Exposure.FILE_SHARING, None),
  554: ServiceProfile("rtsp", Exposure.MEDIA, False),
  631: ServiceProfile("ipp", Exposure.PRINTING, None),
  1433: ServiceProfile("mssql", Exposure.DATABASE, None),
  1883: ServiceProfile("mqtt", Exposure.MESSAGING, False),
  2049: ServiceProfile("nfs", Exposure.FILE_SHARING, False),
  3306: ServiceProfile("mysql", Exposure.DATABASE, None),
  3389: ServiceProfile("rdp", Exposure.REMOTE_ADMIN, True),
  5432: ServiceProfile("postgresql", Exposure.DATABASE, None),
  5800: ServiceProfile("vnc-http", Exposure.REMOTE_ADMIN, False),
  5900: ServiceProfile("vnc", Exposure.REMOTE_ADMIN, None),
  5985: ServiceProfile("winrm", Exposure.REMOTE_ADMIN, False),
  5986: ServiceProfile("winrm-https", Exposure.REMOTE_ADMIN, True),
  6379: ServiceProfile("redis", Exposure.DATABASE, False),
  8080: ServiceProfile("http-alt", Exposure.WEB, False),
  8443: ServiceProfile("https-alt", Exposure.WEB, True),
  8883: ServiceProfile("mqtt-tls", Exposure.MESSAGING, True),
  9100: ServiceProfile("jetdirect", Exposure.PRINTING, False),
  9200: ServiceProfile("elasticsearch", Exposure.DATABASE, False),
  27017: ServiceProfile("mongodb", Exposure.DATABASE, None),
}
# what a banner proves: protocol -> (exposure, encrypted)
OBSERVED_PROFILES: dict[str, ServiceProfile] = {
  "ssh": ServiceProfile("ssh", Exposure.REMOTE_ADMIN, True),
  "telnet": ServiceProfile("telnet", Exposure.REMOTE_ADMIN, False),
  "ftp": ServiceProfile("ftp", Exposure.FILE_SHARING, False),
  "http": ServiceProfile("http", Exposure.WEB, False),
  "tls": ServiceProfile("tls", Exposure.OTHER, True),
  "vnc": ServiceProfile("vnc", Exposure.REMOTE_ADMIN, None),
  "smtp": ServiceProfile("smtp", Exposure.MESSAGING, False),
  "pop3": ServiceProfile("pop3", Exposure.MESSAGING, False),
  "imap": ServiceProfile("imap", Exposure.MESSAGING, False),
  "rtsp": ServiceProfile("rtsp", Exposure.MEDIA, False),
  "redis": ServiceProfile("redis", Exposure.DATABASE, False),
  "mysql": ServiceProfile("mysql", Exposure.DATABASE, None),
}


 # banner analysis ->
def observed_protocol(raw: bytes | None) -> str | None:
  """the protocol a service announced in its first bytes, or none. reads untrusted data, never executes it."""
  if not raw:
    return None
  head = raw[:64]
  if head[:1] == b"\xff" and len(head) > 2 and head[1] in (0xFB, 0xFC, 0xFD, 0xFE):
    return "telnet"  # iac will/wont/do/dont negotiation
  if head[:1] == b"\x16" and head[1:2] == b"\x03":
    return "tls"
  text = head.decode("latin-1", errors="replace").lower()
  if text.startswith("ssh-"):
    return "ssh"
  if text.startswith("http/"):
    return "http"
  if text.startswith("rtsp/"):
    return "rtsp"
  if text.startswith("rfb "):
    return "vnc"
  if text.startswith("+ok"):
    return "pop3"
  if text.startswith("* ok"):
    return "imap"
  if text.startswith("-err") or text.startswith("-noauth") or text.startswith("-denied"):
    return "redis"
  if text.startswith("220"):
    if "ftp" in text:
      return "ftp"
    if "smtp" in text or "mail" in text:
      return "smtp"
    return None
  if len(head) > 5 and head[4:5] == b"\x0a" and b"mysql" in raw[:128].lower():
    return "mysql"
  return None


def profile_for(port: PortInfo) -> tuple[ServiceProfile | None, Basis]:
  """the observed protocol wins over the port-number convention, and says so."""
  if port.protocol_observed and port.protocol_observed in OBSERVED_PROFILES:
    return OBSERVED_PROFILES[port.protocol_observed], Basis.OBSERVED
  profile = PORT_PROFILES.get(port.port)
  if port.tls:
    # a completed tls handshake proves the transport is encrypted; what runs inside is still a convention
    if profile is None:
      return ServiceProfile("tls", Exposure.OTHER, True), Basis.OBSERVED
    return ServiceProfile(profile.service, profile.exposure, True), Basis.OBSERVED
  return profile, Basis.INFERRED


def describe(port: PortInfo) -> str:
  """`ssh on 22 (banner)` or `22, usually ssh (inferred from the port number)`."""
  profile, basis = profile_for(port)
  if profile is None:
    return f"{port.port}/{port.protocol}"
  if basis == Basis.OBSERVED:
    return f"{profile.service} on {port.port} (seen in the banner)"
  return f"{port.port}/{port.protocol}, usually {profile.service} (inferred from the port number)"


def is_sensitive(port: PortInfo) -> bool:
  """worth highlighting: administration, file sharing, databases or a plaintext protocol."""
  profile, _ = profile_for(port)
  if profile is None:
    return False
  return profile.exposure in (Exposure.REMOTE_ADMIN, Exposure.FILE_SHARING, Exposure.DATABASE) or profile.encrypted is False
