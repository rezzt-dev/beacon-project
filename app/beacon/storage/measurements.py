 # import libraries ->
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from beacon.core.models import Device
from beacon.storage.base import Store, ts


 # measurement store ->
class MeasurementStore(Store):
  def _record_measurements(self, scan_id: int, devices: Iterable[Device], at: datetime) -> None:
    """one row per device that was actually measured in this scan; no row is ever invented."""
    rows = [
      (
        scan_id,
        d.key,
        ts(at),
        d.latency.method,
        d.latency.sent,
        d.latency.received,
        d.latency.avg,
        d.latency.min,
        d.latency.max,
        d.latency.jitter,
        len(d.open_ports),
      )
      for d in devices
      if d.latency is not None and d.latency.sent > 0 and not d.is_local and getattr(d.latency, "fresh", True)
    ]
    self.conn.executemany(
      """INSERT INTO measurements (scan_id, device_key, at, method, sent, received, rtt_avg, rtt_min, rtt_max, jitter, open_ports)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
      rows,
    )

  def measurement_series(
    self, key: str, since: datetime, until: datetime | None = None, bucket: timedelta | None = None
  ) -> list[dict[str, Any]]:
    """raw samples, or one aggregate per `bucket` (mean of averages, worst max, summed packets).

    buckets without a measurement are simply absent: the caller must not draw them as zero.
    """
    query = "SELECT at, method, sent, received, rtt_avg, rtt_min, rtt_max, jitter FROM measurements WHERE device_key = ? AND at >= ?"
    params: list[Any] = [key, ts(since)]
    if until is not None:
      query += " AND at < ?"
      params.append(ts(until))
    rows = [dict(r) for r in self.conn.execute(query + " ORDER BY at", params)]
    for row in rows:
      row["loss"] = round(100 * (row["sent"] - row["received"]) / row["sent"], 1) if row["sent"] else None
    if bucket is None:
      return rows
    grouped: dict[datetime, list[dict[str, Any]]] = {}
    width = bucket.total_seconds()
    for row in rows:
      moment = datetime.fromisoformat(row["at"])
      start = datetime.fromtimestamp(moment.timestamp() // width * width, tz=moment.tzinfo)
      grouped.setdefault(start, []).append(row)
    series = []
    for start, items in sorted(grouped.items()):
      sent = sum(i["sent"] for i in items)
      received = sum(i["received"] for i in items)
      averages = [i["rtt_avg"] for i in items if i["rtt_avg"] is not None]
      jitters = [i["jitter"] for i in items if i["jitter"] is not None]
      maxima = [i["rtt_max"] for i in items if i["rtt_max"] is not None]
      minima = [i["rtt_min"] for i in items if i["rtt_min"] is not None]
      series.append(
        {
          "at": start.isoformat(),
          "samples": len(items),
          "sent": sent,
          "received": received,
          "loss": round(100 * (sent - received) / sent, 1) if sent else None,
          "rtt_avg": round(sum(averages) / len(averages), 2) if averages else None,
          "rtt_min": min(minima) if minima else None,
          "rtt_max": max(maxima) if maxima else None,
          "jitter": round(sum(jitters) / len(jitters), 2) if jitters else None,
        }
      )
    return series
