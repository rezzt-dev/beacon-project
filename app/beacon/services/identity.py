 # import libraries ->
from typing import Any

from beacon.core.identity import AMBIGUITY_MARGIN, POSSIBLE_THRESHOLD, PROBABLE_THRESHOLD
from beacon.services.serialize import device_summary
from beacon.storage import NotFoundError, Repository


 # views ->
def overview(repo: Repository, network_id: int | None = None) -> dict[str, Any]:
  """identities, link candidates with their evidence, and how sure each one is.

  a candidate is ambiguous when another candidate for the same newer mac scores almost as high:
  beacon then never suggests linking, it shows both.
  """
  matches = repo.list_candidates(network_id)
  keys = {k for m in matches for k in (m.new_key, m.candidate_key)}
  identities = repo.list_identities()
  keys |= {k for i in identities for k in i["members"]}
  devices = repo.get_devices(keys)
  candidates = []
  for match in matches:
    if match.new_key not in devices or match.candidate_key not in devices:
      continue
    rivals = [m.score for m in matches if m.new_key == match.new_key and m.candidate_key != match.candidate_key]
    ambiguous = any(abs(match.score - rival) < AMBIGUITY_MARGIN for rival in rivals)
    candidates.append(
      {
        "new": device_summary(devices[match.new_key]),
        "candidate": device_summary(devices[match.candidate_key]),
        "score": match.score,
        "level": str(match.level),
        "evidence": list(match.evidence),
        "ambiguous": ambiguous,
      }
    )
  return {
    "identities": [
      {**i, "members": [device_summary(devices[k]) for k in i["members"] if k in devices]} for i in identities
    ],
    "candidates": candidates,
    "thresholds": {"probable": PROBABLE_THRESHOLD, "possible": POSSIBLE_THRESHOLD, "ambiguity_margin": AMBIGUITY_MARGIN},
    "rejections": [{"new": n, "candidate": c} for n, c in sorted(repo.rejected_pairs())],
    "history": repo.identity_history(limit=50),
  }


 # actions ->
def link(repo: Repository, new_key: str, old_key: str, actor: str, trust: bool = False) -> dict[str, Any]:
  """confirm two macs are one device. trust is only granted when explicitly asked for, never inherited."""
  devices = repo.get_devices([new_key, old_key])
  if len(devices) != 2:
    raise NotFoundError("both devices must exist in the inventory")
  if devices[new_key].network_id != devices[old_key].network_id:
    raise ValueError("devices of different networks cannot be linked")
  identity_id = repo.link_devices(new_key, old_key, actor)
  if trust:
    repo.set_trusted(new_key, True, actor)
  return {"identity_id": identity_id, "trusted": trust}
