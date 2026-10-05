import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


class EventDatabase:
    def __init__(self, db_path="data/ebpf_intelligence.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self):
        with self.connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    uid INTEGER NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    message TEXT,
                    alert_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def save_events(self, events):
        now = datetime.now(timezone.utc).isoformat()

        with self.connect() as conn:
            conn.executemany("""
                INSERT INTO events (
                    event_type, pid, uid, timestamp_ns,
                    process_name, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, [
                (
                    event.event_type.value,
                    event.pid,
                    event.uid,
                    event.timestamp_ns,
                    event.process_name,
                    now,
                )
                for event in events
            ])

    def save_alerts(self, alerts):
        now = datetime.now(timezone.utc).isoformat()

        with self.connect() as conn:
            conn.executemany("""
                INSERT INTO alerts (
                    alert_type, severity, pid, process_name,
                    message, alert_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    alert.get("type", "UNKNOWN"),
                    alert.get("severity", "UNKNOWN"),
                    alert.get("pid"),
                    alert.get("process_name"),
                    alert.get("message", ""),
                    json.dumps(alert),
                    now,
                )
                for alert in alerts
            ])

    def get_recent_events(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT * FROM events
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def get_recent_alerts(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT * FROM alerts
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def get_summary(self):
        with self.connect() as conn:
            event_count = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            alert_count = conn.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

            return {
                "total_events": event_count,
                "total_alerts": alert_count,
                "database": str(self.db_path.resolve()),
            }
