 # import libraries ->
import os
import sys
from dataclasses import dataclass
from pathlib import Path


 # constants ->
APP_NAME = "beacon"
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
SYSTEM_MANUF_PATHS = (
  Path("/usr/share/wireshark/manuf"),
  Path("/usr/local/share/wireshark/manuf"),
  Path("/opt/homebrew/share/wireshark/manuf"),
)
MAX_SWEEP_HOSTS = 65_534


 # data directory resolution ->
def default_data_dir() -> Path:
  """return the per-user data directory, honouring `BEACON_HOME` first."""
  if override := os.environ.get("BEACON_HOME"):
    return Path(override).expanduser()
  if sys.platform == "win32":
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
  elif sys.platform == "darwin":
    base = Path.home() / "Library" / "Application Support"
  else:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
  return base / APP_NAME


 # settings ->
@dataclass(frozen=True, slots=True)
class Settings:
  data_dir: Path
  db_path: Path
  oui_path: Path

  @classmethod
  def load(cls, db_path: Path | None = None) -> "Settings":
    data_dir = default_data_dir()
    env_db = os.environ.get("BEACON_DB")
    return cls(
      data_dir=data_dir,
      db_path=db_path or (Path(env_db).expanduser() if env_db else data_dir / "beacon.db"),
      oui_path=data_dir / "manuf",
    )

  def ensure_dirs(self) -> None:
    self.data_dir.mkdir(parents=True, exist_ok=True)
    self.db_path.parent.mkdir(parents=True, exist_ok=True)
