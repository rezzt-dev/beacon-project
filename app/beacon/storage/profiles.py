 # import libraries ->
import json
from typing import Any

from beacon.core.models import utcnow
from beacon.storage.base import ConflictError, NotFoundError, Store, ts


 # profile store ->
PROFILE_COLUMNS = ("name", "network_id", "target", "interface", "exclude", "ports", "options", "interval_seconds", "enabled")
_JSON = {"exclude", "options"}


def _row(row) -> dict[str, Any]:
  data = dict(row)
  for key in _JSON:
    data[key] = json.loads(data[key])
  data["enabled"] = bool(data["enabled"])
  return data


class ProfileStore(Store):
  def list_profiles(self) -> list[dict[str, Any]]:
    return [_row(r) for r in self.conn.execute("SELECT * FROM profiles ORDER BY name")]

  def get_profile(self, profile_id: int) -> dict[str, Any] | None:
    row = self.conn.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
    return _row(row) if row else None

  def get_profile_by_name(self, name: str) -> dict[str, Any] | None:
    row = self.conn.execute("SELECT * FROM profiles WHERE name = ?", (name,)).fetchone()
    return _row(row) if row else None

  def create_profile(self, values: dict[str, Any], actor: str = "cli") -> dict[str, Any]:
    now = ts(utcnow())
    data = {k: values.get(k) for k in PROFILE_COLUMNS}
    data["exclude"] = json.dumps(data["exclude"] or [])
    data["options"] = json.dumps(data["options"] or {})
    data["enabled"] = int(data["enabled"] if data["enabled"] is not None else True)
    with self.conn:
      if self.conn.execute("SELECT 1 FROM profiles WHERE name = ?", (data["name"],)).fetchone():
        raise ValueError(f"a profile named {data['name']!r} already exists")
      cursor = self.conn.execute(
        f"INSERT INTO profiles ({', '.join(PROFILE_COLUMNS)}, created_at, updated_at) VALUES ({', '.join('?' * (len(PROFILE_COLUMNS) + 2))})",
        (*[data[k] for k in PROFILE_COLUMNS], now, now),
      )
      profile_id = int(cursor.lastrowid or 0)
      self._audit(actor, "create", "profile", str(profile_id), name=data["name"])
      self._change("profile.created", "profile", str(profile_id), data["network_id"])
    profile = self.get_profile(profile_id)
    assert profile is not None
    return profile

  def update_profile(self, profile_id: int, values: dict[str, Any], expected_version: int | None, actor: str = "cli") -> dict[str, Any]:
    with self.conn:
      row = self.conn.execute("SELECT version, name FROM profiles WHERE id = ?", (profile_id,)).fetchone()
      if row is None:
        raise NotFoundError(f"profile {profile_id} not found")
      if expected_version is not None and row["version"] != expected_version:
        raise ConflictError("profile", str(profile_id), row["version"])
      renamed = "name" in values and values["name"] != row["name"]
      if renamed and self.conn.execute("SELECT 1 FROM profiles WHERE name = ? AND id != ?", (values["name"], profile_id)).fetchone():
        raise ValueError(f"a profile named {values['name']!r} already exists")
      fields = {k: v for k, v in values.items() if k in PROFILE_COLUMNS}
      for key in _JSON & fields.keys():
        fields[key] = json.dumps(fields[key])
      if "enabled" in fields:
        fields["enabled"] = int(fields["enabled"])
      if fields:
        assignments = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(
          f"UPDATE profiles SET {assignments}, version = version + 1, updated_at = ? WHERE id = ?",
          (*fields.values(), ts(utcnow()), profile_id),
        )
        self._audit(actor, "edit", "profile", str(profile_id), fields=sorted(fields))
        self._change("profile.updated", "profile", str(profile_id), None)
    profile = self.get_profile(profile_id)
    assert profile is not None
    return profile

  def delete_profile(self, profile_id: int, actor: str = "cli") -> bool:
    with self.conn:
      deleted = self.conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,)).rowcount > 0
      if deleted:
        self._audit(actor, "delete", "profile", str(profile_id))
        self._change("profile.deleted", "profile", str(profile_id), None)
    return deleted
