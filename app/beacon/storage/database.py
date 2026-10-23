 # import libraries ->
import sqlite3
from pathlib import Path


 # schema ->
# each entry migrates the schema from version `index` to `index + 1`
MIGRATIONS: tuple[str, ...] = (
  """
  CREATE TABLE devices (
    key             TEXT PRIMARY KEY,
    mac             TEXT,
    ip              TEXT NOT NULL,
    ips             TEXT NOT NULL DEFAULT '[]',
    hostname        TEXT,
    hostname_source TEXT,
    vendor          TEXT,
    randomized_mac  INTEGER NOT NULL DEFAULT 0,
    ttl             INTEGER,
    os_guess        TEXT,
    alias           TEXT,
    trusted         INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'online',
    is_local        INTEGER NOT NULL DEFAULT 0,
    is_gateway      INTEGER NOT NULL DEFAULT 0,
    latency         TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
  );
  CREATE INDEX idx_devices_ip ON devices (ip);

  CREATE TABLE ports (
    device_key TEXT NOT NULL REFERENCES devices (key) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    protocol   TEXT NOT NULL DEFAULT 'tcp',
    service    TEXT,
    banner     TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (device_key, port, protocol)
  );

  CREATE TABLE scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT NOT NULL,
    network       TEXT NOT NULL,
    interface     TEXT,
    mode          TEXT NOT NULL,
    ports_scanned INTEGER NOT NULL DEFAULT 0,
    device_count  INTEGER NOT NULL DEFAULT 0,
    event_count   INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans (id) ON DELETE SET NULL,
    timestamp  TEXT NOT NULL,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    device_key TEXT,
    ip         TEXT,
    mac        TEXT,
    message    TEXT NOT NULL,
    details    TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX idx_events_device ON events (device_key);
  CREATE INDEX idx_events_timestamp ON events (timestamp);
  """,
  # v2: events can be acknowledged once the user has reviewed them
  """
  ALTER TABLE events ADD COLUMN acked_at TEXT;
  CREATE INDEX idx_events_pending ON events (severity) WHERE acked_at IS NULL;
  """,
  # v3: identities group the macs of one physical device (randomized private addresses)
  """
  ALTER TABLE devices ADD COLUMN services TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE devices ADD COLUMN identity_id INTEGER;
  CREATE TABLE identities (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX idx_devices_identity ON devices (identity_id);
  """,
  # v4: presence sessions, one row per continuous stay of a device on the network
  """
  CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_key TEXT NOT NULL REFERENCES devices (key) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    last_seen  TEXT NOT NULL
  );
  CREATE INDEX idx_sessions_device ON sessions (device_key, started_at);
  CREATE INDEX idx_sessions_open ON sessions (device_key) WHERE ended_at IS NULL;
  """,
)
SCHEMA_VERSION = len(MIGRATIONS)


 # database ->
class Database:
  """owns the sqlite connection and keeps the schema migrated (`PRAGMA user_version`)."""

  def __init__(self, path: Path | str) -> None:
    self.path = path
    self._conn: sqlite3.Connection | None = None

  @property
  def conn(self) -> sqlite3.Connection:
    if self._conn is None:
      if isinstance(self.path, Path):
        self.path.parent.mkdir(parents=True, exist_ok=True)
      conn = sqlite3.connect(self.path)
      conn.row_factory = sqlite3.Row
      conn.execute("PRAGMA foreign_keys = ON")
      if str(self.path) != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
      self._migrate(conn)
      self._conn = conn
    return self._conn

  @staticmethod
  def _migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
      raise RuntimeError(f"database schema v{version} is newer than this beacon build (v{SCHEMA_VERSION})")
    for index in range(version, SCHEMA_VERSION):
      # schema change and version bump commit together or not at all
      conn.executescript(f"BEGIN;\n{MIGRATIONS[index]}\nPRAGMA user_version = {index + 1};\nCOMMIT;")

  def close(self) -> None:
    if self._conn is not None:
      self._conn.close()
      self._conn = None

  def __enter__(self) -> "Database":
    return self

  def __exit__(self, *_exc: object) -> None:
    self.close()
