"""
SentinelCore — storage/db.py
SQLite handler + normalized event schema.

Every event ingested into SentinelCore, regardless of source, is stored
as a NormalizedEvent before hitting the DB. This keeps the correlation
engine source-agnostic.
"""

import sqlite3
import json
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── DB path ──────────────────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent.parent / "logs" / "sentinelcore.db"


# ── Normalized Event Schema ───────────────────────────────────────────────────
@dataclass
class NormalizedEvent:
    """
    Universal event schema. All parsers must produce this.

    Fields
    ------
    timestamp   : ISO-8601 string (e.g. "2026-06-30T14:23:01")
    source      : origin system  ("auth_log", "syslog", "apache", "netwatch", "homeguard")
    event_type  : category       ("auth_failure", "port_scan", "unknown_device", ...)
    severity    : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    src_ip      : source IP (if applicable)
    dst_ip      : destination IP (if applicable)
    user        : username involved (if applicable)
    message     : human-readable summary
    raw         : original log line / JSON (stored as string)
    extra       : dict with source-specific fields (stored as JSON string)
    """
    timestamp:  str
    source:     str
    event_type: str
    severity:   str
    message:    str
    src_ip:     Optional[str] = None
    dst_ip:     Optional[str] = None
    user:       Optional[str] = None
    raw:        Optional[str] = None
    extra:      dict          = field(default_factory=dict)

    # severity ordering for comparisons
    _SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def severity_level(self) -> int:
        return self._SEVERITY_ORDER.get(self.severity, 0)


# ── DB Manager ────────────────────────────────────────────────────────────────
class Database:
    """Handles all SQLite operations for SentinelCore."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row          # dict-like rows
        conn.execute("PRAGMA journal_mode=WAL") # safe concurrent writes
        return conn

    def _init_schema(self):
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    source      TEXT    NOT NULL,
                    event_type  TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    user        TEXT,
                    message     TEXT    NOT NULL,
                    raw         TEXT,
                    extra       TEXT    DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at  TEXT    NOT NULL,
                    rule_name   TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    description TEXT    NOT NULL,
                    event_ids   TEXT    NOT NULL,   -- JSON list of event IDs
                    src_ip      TEXT,
                    user        TEXT,
                    acknowledged INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS reputation (
                    ip          TEXT    PRIMARY KEY,
                    score       INTEGER DEFAULT 0,
                    alert_count INTEGER DEFAULT 0,
                    last_seen   TEXT,
                    first_seen  TEXT,
                    tags        TEXT    DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS geo_cache (
                    ip          TEXT    PRIMARY KEY,
                    country     TEXT,
                    country_code TEXT,
                    city        TEXT,
                    org         TEXT,
                    is_private  INTEGER DEFAULT 0,
                    cached_at   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events(src_ip);
                CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
                CREATE INDEX IF NOT EXISTS idx_reputation_score  ON reputation(score DESC);
            """)

    # ── Events ────────────────────────────────────────────────────────────────

    def insert_event(self, event: NormalizedEvent) -> int:
        """Insert a NormalizedEvent. Returns its row ID."""
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO events
                   (timestamp, source, event_type, severity, src_ip, dst_ip,
                    user, message, raw, extra)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.timestamp, event.source, event.event_type,
                    event.severity, event.src_ip, event.dst_ip,
                    event.user, event.message, event.raw,
                    json.dumps(event.extra),
                ),
            )
            return cur.lastrowid

    def insert_events(self, events: list[NormalizedEvent]) -> list[int]:
        """Bulk insert. Returns list of row IDs."""
        return [self.insert_event(e) for e in events]

    def get_events(
        self,
        since: Optional[str] = None,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict]:
        """Flexible event query with optional filters."""
        clauses, params = [], []
        if since:
            clauses.append("timestamp >= ?"); params.append(since)
        if source:
            clauses.append("source = ?"); params.append(source)
        if event_type:
            clauses.append("event_type = ?"); params.append(event_type)
        if src_ip:
            clauses.append("src_ip = ?"); params.append(src_ip)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def count_events(self, src_ip: str, event_type: str, since: str) -> int:
        """Count events matching IP + type in a time window. Used by correlation."""
        with self._connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) FROM events
                   WHERE src_ip = ? AND event_type = ? AND timestamp >= ?""",
                (src_ip, event_type, since),
            ).fetchone()
        return row[0]

    # ── Alerts ────────────────────────────────────────────────────────────────

    def insert_alert(
        self,
        rule_name: str,
        severity: str,
        description: str,
        event_ids: list[int],
        src_ip: Optional[str] = None,
        user: Optional[str] = None,
    ) -> int:
        """Record a correlation alert. Returns its row ID."""
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO alerts
                   (created_at, rule_name, severity, description, event_ids, src_ip, user)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    datetime.now().isoformat(timespec="seconds"),
                    rule_name, severity, description,
                    json.dumps(event_ids), src_ip, user,
                ),
            )
            return cur.lastrowid

    def get_alerts(self, limit: int = 100, unacked_only: bool = False) -> list[dict]:
        """Retrieve alerts, newest first."""
        where = "WHERE acknowledged = 0" if unacked_only else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int):
        """Mark an alert as acknowledged."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
            )

    # ── Stats (for dashboard) ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Summary counts for the dashboard."""
        with self._connect() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            unacked      = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
            ).fetchone()[0]
            by_severity  = conn.execute(
                "SELECT severity, COUNT(*) as n FROM alerts GROUP BY severity"
            ).fetchall()
            by_source    = conn.execute(
                "SELECT source, COUNT(*) as n FROM events GROUP BY source"
            ).fetchall()

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "unacknowledged_alerts": unacked,
            "alerts_by_severity": {r["severity"]: r["n"] for r in by_severity},
            "events_by_source":   {r["source"]:   r["n"] for r in by_source},
        }

    # ── Reputation ────────────────────────────────────────────────────────────

    def update_reputation(self, ip: str, score_delta: int, tag: str = None):
        """Update IP reputation score. Creates record if missing."""
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT score, alert_count, tags, first_seen FROM reputation WHERE ip = ?", (ip,)
            ).fetchone()
            if existing:
                tags = json.loads(existing["tags"])
                if tag and tag not in tags:
                    tags.append(tag)
                new_score = max(0, min(100, existing["score"] + score_delta))
                conn.execute(
                    """UPDATE reputation
                       SET score=?, alert_count=alert_count+1, last_seen=?, tags=?
                       WHERE ip=?""",
                    (new_score, now, json.dumps(tags), ip)
                )
            else:
                tags = [tag] if tag else []
                conn.execute(
                    """INSERT INTO reputation (ip, score, alert_count, last_seen, first_seen, tags)
                       VALUES (?,?,1,?,?,?)""",
                    (ip, max(0, min(100, score_delta)), now, now, json.dumps(tags))
                )

    def get_reputation(self, ip: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM reputation WHERE ip = ?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    def get_top_offenders(self, limit: int = 10) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM reputation ORDER BY score DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Geo cache ─────────────────────────────────────────────────────────────

    def get_geo(self, ip: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM geo_cache WHERE ip = ?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    def set_geo(self, ip: str, data: dict):
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO geo_cache
                   (ip, country, country_code, city, org, is_private, cached_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (ip, data.get("country"), data.get("country_code"),
                 data.get("city"), data.get("org"),
                 1 if data.get("is_private") else 0, now)
            )
