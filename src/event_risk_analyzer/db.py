"""SQLite storage layer.

Kept deliberately dependency-light (stdlib `sqlite3`, no ORM) so the whole
service runs locally with nothing but `pip install -r requirements.txt`.
A short-lived connection is opened per call; SQLite handles that fine at the
throughput this service is meant for (a single application's event stream).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from event_risk_analyzer.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    id          TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    category    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    actor_id    TEXT,
    actor_ip    TEXT,
    resource    TEXT,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raw_events_actor_time
    ON raw_events (actor_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_raw_events_category_time
    ON raw_events (category, occurred_at);

CREATE TABLE IF NOT EXISTS scored_events (
    id          TEXT PRIMARY KEY,
    event_id    TEXT NOT NULL REFERENCES raw_events(id),
    score       INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    reasons     TEXT NOT NULL,
    scored_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scored_events_severity_time
    ON scored_events (severity, scored_at);

CREATE TABLE IF NOT EXISTS subscribers (
    id           TEXT PRIMARY KEY,
    url          TEXT NOT NULL,
    min_severity TEXT NOT NULL,
    secret       TEXT,
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deliveries (
    id               TEXT PRIMARY KEY,
    subscriber_id    TEXT NOT NULL REFERENCES subscribers(id),
    scored_event_id  TEXT NOT NULL REFERENCES scored_events(id),
    status           TEXT NOT NULL,
    http_status      INTEGER,
    attempted_at     TEXT NOT NULL,
    error            TEXT
);
"""


def init_db(db_path: str | None = None) -> None:
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    # check_same_thread=False: each request gets its own dedicated connection
    # (never shared across requests), but FastAPI's threadpool can resume a
    # paused sync-generator dependency's cleanup code on a different worker
    # thread than the one that opened it — sqlite3's default same-thread
    # check would reject that close() call even though it's still safe here.
    conn = sqlite3.connect(db_path or settings.db_path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets the background webhook-dispatch writer and request-handling
    # writers proceed concurrently instead of blocking each other on every
    # write — without it, a slow subscriber webhook can stall unrelated
    # event ingestion with "database is locked".
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


@contextmanager
def get_db(db_path: str | None = None) -> Iterator[sqlite3.Connection]:
    conn = _connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
