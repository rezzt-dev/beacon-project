 # import libraries ->
import json
from typing import Any

from beacon.core.identity import IdentityMatch, fingerprint, score, suggest_links
from beacon.core.models import Device, utcnow
from beacon.storage.base import NotFoundError, Store, placeholders, ts


 # identity store ->
class IdentityStore(Store):
  def link_devices(self, new_key: str, old_key: str, actor: str = "cli") -> int:
    """put two macs under one identity, copy the alias to the one without it and review the new one.

    trust is never copied: a hostname is easy to spoof, so trusting the new mac is a separate decision.
    """
    if new_key == old_key:
      raise ValueError("a device cannot be linked to itself")
    with self.conn:
      rows = {
        row["key"]: row
        for row in self.conn.execute(
          "SELECT key, identity_id, alias, hostname, network_id FROM devices WHERE key IN (?, ?)", (new_key, old_key)
        )
      }
      if len(rows) != 2:
        raise ValueError("both devices must exist in the inventory")
      existing = sorted({r["identity_id"] for r in rows.values() if r["identity_id"] is not None})
      if existing:
        identity_id = existing[0]
        self.conn.execute(
          f"UPDATE devices SET identity_id = ? WHERE identity_id IN ({placeholders(existing)})",
          (identity_id, *existing),
        )
      else:
        old = rows[old_key]
        label = old["alias"] or old["hostname"] or old_key
        cursor = self.conn.execute("INSERT INTO identities (label, created_at) VALUES (?, ?)", (label, ts(utcnow())))
        identity_id = int(cursor.lastrowid or 0)
      self.conn.execute("UPDATE devices SET identity_id = ? WHERE key IN (?, ?)", (identity_id, new_key, old_key))
      if rows[new_key]["alias"] is None and rows[old_key]["alias"]:
        self.conn.execute("UPDATE devices SET alias = ? WHERE key = ?", (rows[old_key]["alias"], new_key))
      self.conn.execute("DELETE FROM identity_rejections WHERE new_key = ? AND candidate_key = ?", (new_key, old_key))
      self._ack(new_key, actor)
      self._prune_identities()
      evidence = self._evidence(new_key, old_key)
      self._audit(actor, "link", "identity", str(identity_id), new=new_key, old=old_key, evidence=evidence)
      for key in (new_key, old_key):
        self.conn.execute("UPDATE devices SET version = version + 1 WHERE key = ?", (key,))
      self._change("identity.linked", "identity", str(identity_id), rows[new_key]["network_id"], new=new_key, old=old_key)
    return identity_id

  def unlink_device(self, key: str, actor: str = "cli") -> bool:
    """take a device out of its identity; an identity left with a single mac is dissolved."""
    with self.conn:
      row = self.conn.execute("SELECT identity_id, network_id FROM devices WHERE key = ?", (key,)).fetchone()
      changed = self.conn.execute(
        "UPDATE devices SET identity_id = NULL, version = version + 1 WHERE key = ? AND identity_id IS NOT NULL", (key,)
      ).rowcount > 0
      self._prune_identities()
      if changed and row is not None:
        self._audit(actor, "unlink", "identity", str(row["identity_id"]), device=key)
        self._change("identity.unlinked", "identity", str(row["identity_id"]), row["network_id"], device=key)
    return changed

  def reject_candidate(self, new_key: str, candidate_key: str, actor: str = "cli") -> None:
    """remember that these two macs are not the same device, so the pair is never proposed again."""
    with self.conn:
      found = self.conn.execute("SELECT COUNT(*) FROM devices WHERE key IN (?, ?)", (new_key, candidate_key)).fetchone()[0]
      if found != 2:
        raise NotFoundError("both devices must exist in the inventory")
      self.conn.execute(
        "INSERT OR REPLACE INTO identity_rejections (new_key, candidate_key, rejected_at) VALUES (?, ?, ?)",
        (new_key, candidate_key, ts(utcnow())),
      )
      self._ack(new_key, actor)
      self._audit(actor, "reject", "identity-candidate", new_key, candidate=candidate_key)
      self._change("identity.rejected", "device", new_key, None, candidate=candidate_key)

  def rejected_pairs(self) -> set[tuple[str, str]]:
    return {(r["new_key"], r["candidate_key"]) for r in self.conn.execute("SELECT * FROM identity_rejections")}

  def _prune_identities(self) -> None:
    self.conn.execute(
      """UPDATE devices SET identity_id = NULL WHERE identity_id IN
           (SELECT identity_id FROM devices WHERE identity_id IS NOT NULL GROUP BY identity_id HAVING COUNT(*) < 2)"""
    )
    self.conn.execute("DELETE FROM identities WHERE id NOT IN (SELECT identity_id FROM devices WHERE identity_id IS NOT NULL)")

  def identity_members(self, device: Device) -> list[Device]:
    """the other macs that belong to the same physical device, oldest first."""
    if device.identity_id is None:
      return []
    keys = [r["key"] for r in self.conn.execute("SELECT key FROM devices WHERE identity_id = ? AND key != ?", (device.identity_id, device.key))]
    members = list(self.get_devices(keys).values())
    return sorted(members, key=lambda d: d.first_seen or utcnow())

  def list_identities(self) -> list[dict[str, Any]]:
    identities = {r["id"]: {**dict(r), "members": []} for r in self.conn.execute("SELECT * FROM identities ORDER BY id")}
    for row in self.conn.execute("SELECT key, identity_id FROM devices WHERE identity_id IS NOT NULL ORDER BY first_seen"):
      if row["identity_id"] in identities:
        identities[row["identity_id"]]["members"].append(row["key"])
    return list(identities.values())

  def identity_history(self, identity_id: int | None = None, device_key: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """the audit trail of links, unlinks and rejections, with the evidence each decision was based on."""
    query = "SELECT * FROM audit WHERE entity IN ('identity', 'identity-candidate')"
    params: list[Any] = []
    if identity_id is not None:
      query += " AND entity = 'identity' AND entity_id = ?"
      params.append(str(identity_id))
    if device_key is not None:
      query += " AND (entity_id = ? OR details LIKE ?)"
      params += [device_key, f'%"{device_key}"%']
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [{**dict(r), "details": json.loads(r["details"])} for r in self.conn.execute(query, params)]

  def list_candidates(self, network_id: int | None = None) -> list[IdentityMatch]:
    """possible links between stored randomized macs of one network, strongest first; rejected pairs are left out."""
    rejected = self.rejected_pairs()
    devices = [d for d in self.load_devices(network_id).values() if d.randomized_mac]
    by_network: dict[int, list[Device]] = {}
    for device in devices:
      by_network.setdefault(device.network_id, []).append(device)
    found = [m for group in by_network.values() for m in suggest_links(group)]
    return [m for m in found if (m.new_key, m.candidate_key) not in rejected]

  def _evidence(self, new_key: str, old_key: str) -> list[str]:
    devices = self.get_devices([new_key, old_key])
    if len(devices) != 2:
      return []
    return list(score(fingerprint(devices[new_key]), fingerprint(devices[old_key]))[1])
