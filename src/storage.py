"""
storage.py
Thin SQLite persistence layer for parsed events and generated alerts.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "siem.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(
        """
        DROP TABLE IF EXISTS events;
        DROP TABLE IF EXISTS alerts;

        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            detail TEXT,
            raw TEXT
        );

        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            ip TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        );

        CREATE INDEX idx_events_ip ON events(ip);
        CREATE INDEX idx_alerts_ip ON alerts(ip);
        """
    )
    conn.commit()
    conn.close()


def save_events(events):
    conn = get_connection()
    conn.executemany(
        "INSERT INTO events (timestamp, source, ip, event_type, detail, raw) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [(e["timestamp"].isoformat(), e["source"], e["ip"], e["event_type"],
          e["detail"], e["raw"]) for e in events],
    )
    conn.commit()
    conn.close()


def save_alerts(alerts):
    conn = get_connection()
    conn.executemany(
        "INSERT INTO alerts (type, ip, timestamp, severity, message) "
        "VALUES (?, ?, ?, ?, ?)",
        [(a["type"], a["ip"], a["timestamp"].isoformat(), a["severity"], a["message"])
         for a in alerts],
    )
    conn.commit()
    conn.close()
