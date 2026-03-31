"""
SENTINEL — SQLite Storage Layer
================================
Persistent event storage with temporal indexing
for efficient window queries and full-text search.
"""

import sqlite3
import pandas as pd
import os
from datetime import datetime


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    line_number     INTEGER,
    timestamp_str   TEXT,
    parsed_time     TEXT,
    event_type      TEXT,
    ip_address      TEXT,
    username        TEXT,
    process         TEXT,
    host            TEXT,
    message         TEXT,
    raw_line        TEXT,
    -- enrichment columns
    geo_country     TEXT DEFAULT '',
    geo_city        TEXT DEFAULT '',
    geo_lat         REAL DEFAULT 0.0,
    geo_lon         REAL DEFAULT 0.0,
    ip_reputation   REAL DEFAULT 0.5,
    asn             TEXT DEFAULT '',
    mitre_technique TEXT DEFAULT '',
    mitre_tactic    TEXT DEFAULT '',
    -- AI/ML columns
    anomaly_score   REAL DEFAULT 0.0,
    cluster_id      INTEGER DEFAULT -1,
    hmm_state       TEXT DEFAULT '',
    risk_score      REAL DEFAULT 0.0,
    severity_level  TEXT DEFAULT 'LOW',
    -- forensic columns
    session_id      TEXT DEFAULT '',
    attack_chain_id TEXT DEFAULT '',
    tamper_flag     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_time     ON events(parsed_time);
CREATE INDEX IF NOT EXISTS idx_ip       ON events(ip_address);
CREATE INDEX IF NOT EXISTS idx_event    ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_user     ON events(username);
CREATE INDEX IF NOT EXISTS idx_severity ON events(severity_level);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_time    TEXT,
    log_file    TEXT,
    total_events INTEGER,
    suspects    INTEGER,
    critical    INTEGER,
    config_json TEXT
);
"""


class SentinelDB:
    """SQLite database for SENTINEL event storage and querying."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "sentinel_data.db")
        self.db_path = os.path.abspath(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cursor = self.conn.cursor()
        cursor.executescript(DB_SCHEMA)
        self.conn.commit()

    def store_events(self, df: pd.DataFrame) -> int:
        """Store parsed events DataFrame into database. Returns count stored."""
        cursor = self.conn.cursor()
        count = 0
        for _, row in df.iterrows():
            cursor.execute("""
                INSERT INTO events (
                    line_number, timestamp_str, parsed_time, event_type,
                    ip_address, username, process, host, message, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                row.get("Line_Number", 0),
                row.get("Timestamp", ""),
                str(row.get("Parsed_Time", "")),
                row.get("Event", "OTHER"),
                row.get("IP_Address", "Internal"),
                row.get("Username", "unknown"),
                row.get("Process", ""),
                row.get("Host", ""),
                row.get("Message", ""),
                row.get("Raw_Line", ""),
            ))
            count += 1
        self.conn.commit()
        return count

    def update_enrichment(self, event_id: int, **fields):
        """Update enrichment/AI fields for an event."""
        allowed = {
            "geo_country", "geo_city", "geo_lat", "geo_lon",
            "ip_reputation", "asn", "mitre_technique", "mitre_tactic",
            "anomaly_score", "cluster_id", "hmm_state",
            "risk_score", "severity_level",
            "session_id", "attack_chain_id", "tamper_flag"
        }
        fields = {k: v for k, v in fields.items() if k in allowed}
        if not fields:
            return
        setters = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [event_id]
        self.conn.execute(
            f"UPDATE events SET {setters} WHERE id = ?", values
        )
        self.conn.commit()

    def bulk_update_by_ip(self, ip: str, **fields):
        """Update enrichment fields for all events from a given IP."""
        allowed = {
            "geo_country", "geo_city", "geo_lat", "geo_lon",
            "ip_reputation", "asn", "mitre_technique", "mitre_tactic",
            "anomaly_score", "cluster_id", "hmm_state",
            "risk_score", "severity_level", "attack_chain_id"
        }
        fields = {k: v for k, v in fields.items() if k in allowed}
        if not fields:
            return
        setters = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [ip]
        self.conn.execute(
            f"UPDATE events SET {setters} WHERE ip_address = ?", values
        )
        self.conn.commit()

    def get_all_events(self) -> pd.DataFrame:
        """Get all events as DataFrame."""
        return pd.read_sql("SELECT * FROM events ORDER BY parsed_time", self.conn)

    def get_events_by_ip(self, ip: str) -> pd.DataFrame:
        return pd.read_sql(
            "SELECT * FROM events WHERE ip_address = ? ORDER BY parsed_time",
            self.conn, params=(ip,)
        )

    def get_unique_ips(self) -> list:
        cursor = self.conn.execute(
            "SELECT DISTINCT ip_address FROM events WHERE ip_address != 'Internal'"
        )
        return [r[0] for r in cursor.fetchall()]

    def get_event_counts(self) -> dict:
        """Get summary counts for KPI display."""
        cursor = self.conn.cursor()
        total = cursor.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        failed = cursor.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'FAILED_LOGIN'"
        ).fetchone()[0]
        success = cursor.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'SUCCESSFUL_LOGIN'"
        ).fetchone()[0]
        critical = cursor.execute(
            "SELECT COUNT(DISTINCT ip_address) FROM events WHERE severity_level = 'CRITICAL'"
        ).fetchone()[0]
        ips = cursor.execute(
            "SELECT COUNT(DISTINCT ip_address) FROM events WHERE ip_address != 'Internal'"
        ).fetchone()[0]
        return {
            "total": total, "failed": failed, "success": success,
            "critical": critical, "unique_ips": ips
        }

    def log_analysis_run(self, log_file: str, total: int, suspects: int,
                         critical: int, config: str = ""):
        self.conn.execute("""
            INSERT INTO analysis_runs (run_time, log_file, total_events,
                                       suspects, critical, config_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), log_file, total, suspects, critical, config))
        self.conn.commit()

    def clear_events(self):
        """Clear all events for a fresh analysis."""
        self.conn.execute("DELETE FROM events")
        self.conn.commit()

    def close(self):
        self.conn.close()
