from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

import pytest

from event_risk_analyzer.config import settings
from event_risk_analyzer.db import get_db, init_db
from event_risk_analyzer.normalize import normalize
from event_risk_analyzer.schemas import Actor, EventIn


@pytest.fixture
def temp_db(tmp_path):
    """Point the shared `settings.db_path` at a throwaway file for this test.

    `Settings` is a frozen dataclass by design (config shouldn't mutate at
    runtime in production) so we go around `frozen=True` with
    `object.__setattr__` purely for test isolation, then restore it.
    """
    original = settings.db_path
    db_path = str(tmp_path / "test.db")
    object.__setattr__(settings, "db_path", db_path)
    init_db(db_path)
    yield db_path
    object.__setattr__(settings, "db_path", original)


@pytest.fixture
def conn(temp_db):
    with get_db(temp_db) as connection:
        yield connection


@pytest.fixture
def insert_event(conn: sqlite3.Connection):
    """Build + normalize + insert a raw event, returning the stored row dict."""

    def _insert(
        event_type: str,
        category: Optional[str] = None,
        actor_id: Optional[str] = None,
        actor_ip: Optional[str] = None,
        resource: Optional[str] = None,
        occurred_at: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
        geo: Optional[dict] = None,
    ) -> dict:
        actor = None
        if actor_id or actor_ip or geo:
            actor = Actor(id=actor_id, ip=actor_ip, geo=geo)
        event = EventIn(
            event_type=event_type,
            category=category,
            occurred_at=occurred_at or datetime.now(timezone.utc),
            actor=actor,
            resource=resource,
            metadata=metadata or {},
        )
        raw = normalize(event)
        conn.execute(
            """
            INSERT INTO raw_events
                (id, received_at, occurred_at, category, event_type, actor_id, actor_ip, resource, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw["id"], raw["received_at"], raw["occurred_at"], raw["category"],
                raw["event_type"], raw["actor_id"], raw["actor_ip"], raw["resource"], raw["payload"],
            ),
        )
        conn.commit()
        return raw

    return _insert
