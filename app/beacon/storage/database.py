 # import libraries ->
import contextlib
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


log = logging.getLogger(__name__)


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
  # v5: network scope, port states and coverage, scan lifecycle, inventory metadata, change feed,
  # audit trail, scan leases and settings. the first network keeps the historical (unscoped) keys,
  # so no device key, port, session or event reference has to be rewritten.
  """
  CREATE TABLE networks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT,
    cidr         TEXT NOT NULL,
    interface    TEXT,
    gateway_ip   TEXT,
    gateway_mac  TEXT,
    created_at   TEXT NOT NULL,
    last_scan_at TEXT
  );
  INSERT INTO networks (id, cidr, interface, gateway_ip, gateway_mac, created_at, last_scan_at)
    SELECT 1, network, interface,
           (SELECT ip FROM devices WHERE is_gateway = 1 ORDER BY last_seen DESC LIMIT 1),
           (SELECT mac FROM devices WHERE is_gateway = 1 ORDER BY last_seen DESC LIMIT 1),
           (SELECT MIN(started_at) FROM scans), finished_at
    FROM scans ORDER BY id DESC LIMIT 1;

  ALTER TABLE devices ADD COLUMN network_id INTEGER NOT NULL DEFAULT 1;
  ALTER TABLE devices ADD COLUMN ips6 TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE devices ADD COLUMN category TEXT;
  ALTER TABLE devices ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE devices ADD COLUMN notes TEXT;
  ALTER TABLE devices ADD COLUMN owner TEXT;
  ALTER TABLE devices ADD COLUMN essential INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE devices ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE devices ADD COLUMN snoozed_until TEXT;
  ALTER TABLE devices ADD COLUMN updated_at TEXT;
  CREATE INDEX idx_devices_network ON devices (network_id, status);
  CREATE INDEX idx_devices_mac ON devices (mac);

  ALTER TABLE ports ADD COLUMN state TEXT NOT NULL DEFAULT 'open';
  ALTER TABLE ports ADD COLUMN last_probe TEXT;
  ALTER TABLE ports ADD COLUMN checked_at TEXT;
  ALTER TABLE ports ADD COLUMN open_seen_at TEXT;
  ALTER TABLE ports ADD COLUMN protocol_observed TEXT;
  ALTER TABLE ports ADD COLUMN tls TEXT;
  UPDATE ports SET last_probe = 'open', checked_at = last_seen, open_seen_at = last_seen;
  CREATE INDEX idx_ports_state ON ports (state, port);

  CREATE TABLE scans_v5 (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'complete',
    network         TEXT,
    network_id      INTEGER REFERENCES networks (id),
    target          TEXT,
    interface       TEXT,
    mode            TEXT,
    trigger         TEXT NOT NULL DEFAULT 'cli',
    profile_id      INTEGER,
    ports_scanned   INTEGER NOT NULL DEFAULT 0,
    port_spec       TEXT,
    device_count    INTEGER NOT NULL DEFAULT 0,
    event_count     INTEGER NOT NULL DEFAULT 0,
    stages          TEXT NOT NULL DEFAULT '{}',
    issues          TEXT NOT NULL DEFAULT '[]',
    unobserved      INTEGER NOT NULL DEFAULT 0,
    first_result_ms INTEGER,
    rules_version   TEXT,
    pid             INTEGER,
    heartbeat_at    TEXT
  );
  INSERT INTO scans_v5 (id, started_at, finished_at, status, network, network_id, target, interface, mode,
                        ports_scanned, device_count, event_count)
    SELECT id, started_at, finished_at, 'complete', network, 1, network, interface, mode,
           ports_scanned, device_count, event_count
    FROM scans;
  DROP TABLE scans;
  ALTER TABLE scans_v5 RENAME TO scans;
  CREATE INDEX idx_scans_network ON scans (network_id, status, id);

  -- which ports each scan examined on each device; spec NULL is a legacy scan whose port set was not kept
  CREATE TABLE port_coverage (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER REFERENCES scans (id) ON DELETE CASCADE,
    device_key     TEXT NOT NULL REFERENCES devices (key) ON DELETE CASCADE,
    protocol       TEXT NOT NULL DEFAULT 'tcp',
    spec           TEXT,
    checked_at     TEXT NOT NULL,
    open_count     INTEGER,
    closed_count   INTEGER,
    filtered_count INTEGER,
    error_count    INTEGER
  );
  CREATE INDEX idx_coverage_device ON port_coverage (device_key, checked_at);
  INSERT INTO port_coverage (device_key, spec, checked_at)
    SELECT d.key, NULL, MAX(s.finished_at)
    FROM devices d JOIN scans s ON s.ports_scanned = 1 AND s.finished_at >= d.first_seen AND s.finished_at <= d.last_seen
    GROUP BY d.key;

  ALTER TABLE events ADD COLUMN network_id INTEGER;
  UPDATE events SET network_id = 1;
  CREATE INDEX idx_events_network ON events (network_id, id);
  CREATE INDEX idx_events_type ON events (type, timestamp);

  CREATE TABLE identity_rejections (
    new_key       TEXT NOT NULL,
    candidate_key TEXT NOT NULL,
    rejected_at   TEXT NOT NULL,
    PRIMARY KEY (new_key, candidate_key)
  );

  -- monotonic feed of everything that changed, read by live clients to resume after a disconnection
  CREATE TABLE changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    entity     TEXT,
    entity_id  TEXT,
    network_id INTEGER,
    data       TEXT NOT NULL DEFAULT '{}'
  );

  CREATE TABLE audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    entity    TEXT NOT NULL,
    entity_id TEXT,
    details   TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX idx_audit_entity ON audit (entity, entity_id);

  -- one scanning owner per network scope, across processes (cli, watch, live, service)
  CREATE TABLE leases (
    scope        TEXT PRIMARY KEY,
    owner        TEXT NOT NULL,
    kind         TEXT NOT NULL,
    pid          INTEGER,
    acquired_at  TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL
  );

  CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  -- one row per device and scan: the real history behind latency and loss charts (milliseconds, utc)
  CREATE TABLE measurements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans (id) ON DELETE SET NULL,
    device_key TEXT NOT NULL REFERENCES devices (key) ON DELETE CASCADE,
    at         TEXT NOT NULL,
    method     TEXT,
    sent       INTEGER NOT NULL DEFAULT 0,
    received   INTEGER NOT NULL DEFAULT 0,
    rtt_avg    REAL,
    rtt_min    REAL,
    rtt_max    REAL,
    jitter     REAL,
    open_ports INTEGER
  );
  CREATE INDEX idx_measurements_device ON measurements (device_key, at);

  CREATE TABLE profiles (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    network_id       INTEGER REFERENCES networks (id) ON DELETE SET NULL,
    target           TEXT,
    interface        TEXT,
    exclude          TEXT NOT NULL DEFAULT '[]',
    ports            TEXT,
    options          TEXT NOT NULL DEFAULT '{}',
    interval_seconds INTEGER,
    enabled          INTEGER NOT NULL DEFAULT 1,
    version          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
  );

  CREATE TABLE alert_policies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    network_id       INTEGER,
    event_types      TEXT NOT NULL DEFAULT '[]',
    min_severity     TEXT NOT NULL DEFAULT 'warning',
    device_filter    TEXT NOT NULL DEFAULT '{}',
    min_risk         INTEGER,
    window_seconds   INTEGER NOT NULL DEFAULT 0,
    threshold        INTEGER NOT NULL DEFAULT 1,
    cooldown_seconds INTEGER NOT NULL DEFAULT 900,
    channels         TEXT NOT NULL DEFAULT '[]',
    version          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    last_fired_at    TEXT
  );

  -- silences and maintenance windows: alerts matching them are recorded but not delivered
  CREATE TABLE silences (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    reason      TEXT,
    network_id  INTEGER,
    device_key  TEXT,
    event_types TEXT NOT NULL DEFAULT '[]',
    starts_at   TEXT NOT NULL,
    ends_at     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    created_by  TEXT
  );

  CREATE TABLE channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    config     TEXT NOT NULL DEFAULT '{}',
    secret     TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT NOT NULL UNIQUE,
    policy_id       INTEGER,
    channel_id      INTEGER,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_error      TEXT,
    payload         TEXT NOT NULL
  );
  CREATE INDEX idx_deliveries_pending ON deliveries (status, next_attempt_at);
  """,
)
SCHEMA_VERSION = len(MIGRATIONS)
# how many automatic pre-migration backups are kept next to the database
KEEP_BACKUPS = 3
BUSY_TIMEOUT_MS = 5000


 # database ->
class Database:
  """owns the sqlite connection and keeps the schema migrated (`PRAGMA user_version`)."""

  def __init__(self, path: Path | str, backup_before_migrate: bool = True) -> None:
    self.path = path
    self.backup_before_migrate = backup_before_migrate
    self._conn: sqlite3.Connection | None = None
    self.last_backup: Path | None = None

  @property
  def is_memory(self) -> bool:
    return str(self.path) == ":memory:"

  @property
  def conn(self) -> sqlite3.Connection:
    """the connection of this object. sqlite connections must not cross threads: each thread opens its own `Database`."""
    if self._conn is None:
      if isinstance(self.path, Path):
        self.path.parent.mkdir(parents=True, exist_ok=True)
      conn = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1000)
      conn.row_factory = sqlite3.Row
      conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
      if not self.is_memory:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
      self._migrate(conn)
      conn.execute("PRAGMA foreign_keys = ON")
      self._conn = conn
    return self._conn

  def _migrate(self, conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
      raise RuntimeError(f"database schema v{version} is newer than this beacon build (v{SCHEMA_VERSION})")
    if version == SCHEMA_VERSION:
      return
    if version > 0 and not self.is_memory and self.backup_before_migrate:
      self.last_backup = self._backup_before(conn, version)
    # some migrations rebuild tables: foreign keys are checked once at the end instead of cascading
    conn.execute("PRAGMA foreign_keys = OFF")
    for index in range(version, SCHEMA_VERSION):
      # schema change and version bump commit together or not at all
      conn.executescript(f"BEGIN;\n{MIGRATIONS[index]}\nPRAGMA user_version = {index + 1};\nCOMMIT;")
    broken = conn.execute("PRAGMA foreign_key_check").fetchall()
    if broken:
      log.warning("database has %d dangling references after migrating", len(broken))

  def _backup_before(self, conn: sqlite3.Connection, version: int) -> Path:
    """a consistent copy (sqlite backup api, wal included) taken before a structural change."""
    path = Path(self.path)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = path.with_name(f"{path.name}.v{version}-{stamp}.bak")
    backup_to(conn, target)
    old = sorted(path.parent.glob(f"{path.name}.v*-*.bak"))
    for stale in old[:-KEEP_BACKUPS]:
      stale.unlink(missing_ok=True)
    log.info("backed up schema v%d to %s before migrating", version, target)
    return target

  def backup(self, target: Path) -> Path:
    return backup_to(self.conn, target)

  def close(self) -> None:
    if self._conn is not None:
      self._conn.close()
      self._conn = None

  def __enter__(self) -> "Database":
    return self

  def __exit__(self, *_exc: object) -> None:
    self.close()


 # backup and restore ->
def backup_to(conn: sqlite3.Connection, target: Path) -> Path:
  """copy a live database with the sqlite backup api: safe while other processes write (wal aware)."""
  target.parent.mkdir(parents=True, exist_ok=True)
  partial = target.with_name(target.name + ".partial")
  partial.unlink(missing_ok=True)
  with sqlite3.connect(partial) as dest:
    conn.backup(dest)
  dest.close()
  partial.replace(target)
  with contextlib.suppress(OSError):  # not every filesystem keeps unix permissions
    target.chmod(0o600)
  return target


def verify(path: Path) -> list[str]:
  """`PRAGMA integrity_check` and foreign key check of a database file; an empty list means healthy."""
  conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
  try:
    problems = [row[0] for row in conn.execute("PRAGMA integrity_check") if row[0] != "ok"]
    problems += [f"dangling reference in {row[0]} (row {row[1]})" for row in conn.execute("PRAGMA foreign_key_check")]
    return problems
  finally:
    conn.close()


def restore_from(backup: Path, target: Path) -> Path:
  """replace `target` with a verified backup; the replaced file is kept as `<name>.before-restore`."""
  problems = verify(backup)
  if problems:
    raise RuntimeError(f"backup {backup} failed verification: {problems[0]}")
  if target.exists():
    previous = target.with_name(target.name + ".before-restore")
    with sqlite3.connect(target) as live:
      backup_to(live, previous)
    live.close()
  source = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
  try:
    for suffix in ("-wal", "-shm"):
      target.with_name(target.name + suffix).unlink(missing_ok=True)
    return backup_to(source, target)
  finally:
    source.close()
