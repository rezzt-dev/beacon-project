 # import libraries ->
import random
from datetime import datetime, timedelta
from pathlib import Path

from beacon.core.events import Event, EventType, Severity
from beacon.core.models import Device, Latency, PortInfo, PortState, ScanMode, utcnow
from beacon.core.ports import PortSet
from beacon.core.report import ScanReport
from beacon.storage import Database, Repository


 # constants ->
# simulated data lives under a documentation-only range and test macs, so it can never be mistaken
# for (or merged with) a real network: 198.18.0.0/15 is reserved for benchmarking (rfc 2544)
DEMO_NETWORK = "198.18.0.0/16"
DEMO_MARK = "simulated"
VENDORS = ["Sagemcom Broadband", "TP-Link Systems", "Apple", "Samsung Electronics", "Raspberry Pi Trading", "Hikvision", "HP Inc.", "Sonos", None]
NAMES = ["router", "laptop", "phone", "tv", "printer", "camera", "nas", "speaker", "thermostat", "tablet", "console", "doorbell"]
PORT_SETS = [(), (80, 443), (22,), (22, 80, 443), (23, 80), (445, 139), (554, 80), (9100, 631), (3389,), (8080,), (5432,)]
SPEC = PortSet([21, 22, 23, 80, 139, 443, 445, 554, 631, 3389, 5432, 8080, 9100])


def _mac(index: int) -> str:
  # locally administered unicast prefix 02:: marks them as not real hardware
  return f"02:be:ac:{(index >> 16) & 0xFF:02x}:{(index >> 8) & 0xFF:02x}:{index & 0xFF:02x}"


def _ip(index: int) -> str:
  return f"198.18.{(index + 2) // 254}.{(index + 2) % 254 + 1}"


 # generator ->
def populate(path: Path, devices: int = 50, events: int = 0, days: int = 14, seed: int = 7, now: datetime | None = None) -> dict[str, int]:
  """fill a new database with a deterministic simulated network. refuses a database that has data."""
  rng = random.Random(seed)
  now = (now or utcnow()).replace(microsecond=0)
  db = Database(path)
  repo = Repository(db)
  if repo.stats()["total"]:
    db.close()
    raise ValueError(f"{path} already has devices: demo data only goes into a new database")
  repo.set_setting("demo", {"mark": DEMO_MARK, "devices": devices, "seed": seed}, actor="demo")
  start = now - timedelta(days=days)
  inventory: list[Device] = []
  for index in range(devices):
    ports = rng.choice(PORT_SETS) if index else (80, 443, 53)
    device = Device(
      ip=_ip(index),
      mac=_mac(index),
      ips=[_ip(index)],
      hostname=f"{rng.choice(NAMES)}-{index}.demo" if rng.random() < 0.7 else None,
      hostname_source="router",
      vendor=rng.choice(VENDORS),
      ttl=rng.choice([64, 128, 255]),
      ports=[PortInfo(p, PortState.OPEN, service=None, checked_at=start, open_seen_at=start, first_seen=start) for p in ports],
      is_gateway=index == 0,
      first_seen=start + timedelta(hours=rng.randint(0, days * 12)),
      last_seen=now,
    )
    device.latency = Latency("icmp", 3, [round(rng.uniform(0.5, 40), 2) for _ in range(rng.randint(1, 3))])
    inventory.append(device)
  # one scan per hour over the period, with presence and latency history
  report = None
  hours = days * 24
  for step in range(hours + 1):
    moment = start + timedelta(hours=step)
    present = [d for d in inventory if d.first_seen <= moment and (d.is_gateway or rng.random() < 0.8)]
    for device in present:
      device.last_seen = moment
      device.latency = Latency("icmp", 3, [round(rng.uniform(0.5, 40), 2) for _ in range(rng.choice([0, 2, 3, 3, 3]))])
    report = ScanReport(DEMO_NETWORK, ScanMode.UNPRIVILEGED, moment, finished_at=moment, interface="demo0", devices=present, port_spec=SPEC if step % 24 == 0 else PortSet())
    report.trigger = "demo"
    repo.save_scan(report, presence_gap=timedelta(hours=2))
  repo.conn.execute("UPDATE devices SET status = 'offline' WHERE last_seen < ?", ((now - timedelta(hours=1)).isoformat(),))
  repo.conn.execute("UPDATE devices SET trusted = 1 WHERE rowid % 3 != 0 OR is_gateway = 1")
  repo.conn.commit()
  # events: the realistic mix the views have to cope with
  kinds = [
    (EventType.NEW_DEVICE, Severity.ALERT), (EventType.DEVICE_OFFLINE, Severity.INFO), (EventType.DEVICE_ONLINE, Severity.WARNING),
    (EventType.IP_CHANGED, Severity.INFO), (EventType.PORT_OPENED, Severity.WARNING), (EventType.PORT_CLOSED, Severity.INFO),
  ]
  batch: list[Event] = []
  for _ in range(events):
    kind, severity = rng.choice(kinds)
    device = rng.choice(inventory)
    details = {"port": rng.choice([22, 80, 443, 8080])} if kind in (EventType.PORT_OPENED, EventType.PORT_CLOSED) else {}
    batch.append(
      Event(kind, severity, f"[{DEMO_MARK}] {kind} on {device.ip}", device_key=device.key, ip=device.ip, mac=device.mac,
            details=details, timestamp=start + timedelta(seconds=rng.randint(0, days * 86400)))
    )
    if len(batch) >= 5000:
      repo.record_events(batch, network_id=1)
      batch = []
  if batch:
    repo.record_events(batch, network_id=1)
  repo.conn.execute("UPDATE events SET acked_at = timestamp WHERE id % 4 != 0")
  repo.conn.commit()
  stats = repo.table_sizes()
  db.close()
  return {"devices": devices, "events": stats["events"], "scans": stats["scans"], "measurements": stats["measurements"], "sessions": stats["sessions"]}
