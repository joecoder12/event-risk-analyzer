"""FastAPI application: ingestion, scoring trigger, feed, and subscribers."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from event_risk_analyzer.auth import require_api_key
from event_risk_analyzer.db import get_db, init_db
from event_risk_analyzer.distribution import (
    create_subscriber,
    delete_subscriber,
    dispatch_webhooks,
    list_subscribers,
    query_feed,
)
from event_risk_analyzer.normalize import normalize
from event_risk_analyzer.schemas import EventIn, ScoredEventOut, SubscriberIn, SubscriberOut
from event_risk_analyzer.scoring import score_event


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="RiskLens — Event Security Risk Analyzer",
    description="Ingests application events, scores them for security risk, "
    "and distributes flagged events via a feed API and signed webhooks.",
    version="0.1.0",
    lifespan=lifespan,
)


def get_conn() -> Iterator[sqlite3.Connection]:
    with get_db() as conn:
        yield conn


async def _dispatch_task(scored_event_id: str, severity: str, feed_item: dict) -> None:
    with get_db() as conn:
        await dispatch_webhooks(conn, scored_event_id, severity, feed_item)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    # The service has no UI of its own; send visitors to the interactive docs.
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/events", response_model=ScoredEventOut, status_code=201)
def ingest_event(
    event: EventIn,
    background_tasks: BackgroundTasks,
    conn: sqlite3.Connection = Depends(get_conn),
    _: str = Depends(require_api_key),
) -> ScoredEventOut:
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

    score, severity, reasons = score_event(conn, raw)

    scored_id = str(uuid.uuid4())
    scored_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO scored_events (id, event_id, score, severity, reasons, scored_at) VALUES (?, ?, ?, ?, ?, ?)",
        (scored_id, raw["id"], score, severity, json.dumps(reasons), scored_at),
    )

    # Commit explicitly, here, before scheduling the background webhook
    # dispatch. FastAPI runs BackgroundTasks *inside* this request's
    # dependency-exit-stack scope, so the `Depends(get_conn)` connection
    # would otherwise stay open (uncommitted) for the entire dispatch —
    # and dispatch opens its *own* connection to log deliveries, which then
    # blocks on this one's still-held write lock. Committing early breaks
    # that deadlock by releasing the lock before dispatch ever starts.
    conn.commit()

    result = ScoredEventOut(
        id=scored_id,
        event_id=raw["id"],
        occurred_at=raw["occurred_at"],
        category=raw["category"],
        event_type=raw["event_type"],
        actor_id=raw["actor_id"],
        actor_ip=raw["actor_ip"],
        resource=raw["resource"],
        score=score,
        severity=severity,
        reasons=reasons,
        scored_at=scored_at,
    )

    background_tasks.add_task(_dispatch_task, scored_id, severity, json.loads(result.model_dump_json()))
    return result


@app.get("/events", response_model=list[ScoredEventOut])
def list_events(
    since: Optional[str] = None,
    category: Optional[str] = None,
    min_severity: Optional[str] = None,
    limit: int = 100,
    conn: sqlite3.Connection = Depends(get_conn),
    _: str = Depends(require_api_key),
) -> list[ScoredEventOut]:
    rows = query_feed(conn, since=since, min_severity=min_severity, category=category, limit=limit)
    return [ScoredEventOut(**row) for row in rows]


@app.get("/feed", response_model=list[ScoredEventOut])
def feed(
    since: Optional[str] = None,
    category: Optional[str] = None,
    min_severity: str = "medium",
    limit: int = 100,
    conn: sqlite3.Connection = Depends(get_conn),
    _: str = Depends(require_api_key),
) -> list[ScoredEventOut]:
    """The distribution-facing feed — defaults to medium-and-above only."""
    rows = query_feed(conn, since=since, min_severity=min_severity, category=category, limit=limit)
    return [ScoredEventOut(**row) for row in rows]


@app.post("/subscribers", response_model=SubscriberOut, status_code=201)
def add_subscriber(
    sub: SubscriberIn,
    conn: sqlite3.Connection = Depends(get_conn),
    _: str = Depends(require_api_key),
) -> SubscriberOut:
    created = create_subscriber(conn, str(sub.url), sub.min_severity, sub.secret)
    return SubscriberOut(**created)


@app.get("/subscribers", response_model=list[SubscriberOut])
def get_subscribers(
    conn: sqlite3.Connection = Depends(get_conn),
    _: str = Depends(require_api_key),
) -> list[SubscriberOut]:
    return [SubscriberOut(**s) for s in list_subscribers(conn)]


@app.delete("/subscribers/{subscriber_id}", status_code=204)
def remove_subscriber(
    subscriber_id: str,
    conn: sqlite3.Connection = Depends(get_conn),
    _: str = Depends(require_api_key),
) -> None:
    if not delete_subscriber(conn, subscriber_id):
        raise HTTPException(status_code=404, detail="subscriber not found")
