"""Distribution: the /feed query API and outbound signed webhooks.

Subscribers register a URL and a minimum severity. Whenever a scored event
meets or exceeds a subscriber's threshold, we POST it to their URL with an
`X-RiskLens-Signature` header (HMAC-SHA256 over the raw JSON body) so the
receiving side can verify the payload actually came from this service and
wasn't tampered with in transit — every delivery attempt, success or
failure, is logged for audit purposes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from event_risk_analyzer.config import settings
from event_risk_analyzer.scoring import meets_severity
from event_risk_analyzer.schemas import Severity


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------ feed query --

def query_feed(
    conn: sqlite3.Connection,
    since: Optional[str] = None,
    min_severity: Optional[Severity] = None,
    category: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    clauses = ["1 = 1"]
    params: list[Any] = []

    if since:
        clauses.append("s.scored_at >= ?")
        params.append(since)
    if category:
        clauses.append("r.category = ?")
        params.append(category)

    sql = f"""
        SELECT s.id, s.event_id, r.occurred_at, r.category, r.event_type,
               r.actor_id, r.actor_ip, r.resource, s.score, s.severity,
               s.reasons, s.scored_at
        FROM scored_events s
        JOIN raw_events r ON r.id = s.event_id
        WHERE {' AND '.join(clauses)}
        ORDER BY s.scored_at DESC
        LIMIT ?
    """
    params.append(limit)
    rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
    for row in rows:
        row["reasons"] = json.loads(row["reasons"])

    if min_severity:
        rows = [r for r in rows if meets_severity(r["severity"], min_severity)]
    return rows


# ---------------------------------------------------------- subscribers --

def create_subscriber(conn: sqlite3.Connection, url: str, min_severity: str, secret: Optional[str]) -> dict:
    sub_id = str(uuid.uuid4())
    created_at = _now()
    conn.execute(
        "INSERT INTO subscribers (id, url, min_severity, secret, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
        (sub_id, url, min_severity, secret, created_at),
    )
    return {"id": sub_id, "url": url, "min_severity": min_severity, "active": True, "created_at": created_at}


def list_subscribers(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, url, min_severity, active, created_at FROM subscribers ORDER BY created_at DESC"
    ).fetchall()
    return [dict(row) | {"active": bool(row["active"])} for row in rows]


def delete_subscriber(conn: sqlite3.Connection, subscriber_id: str) -> bool:
    cur = conn.execute("DELETE FROM subscribers WHERE id = ?", (subscriber_id,))
    return cur.rowcount > 0


def _active_subscribers(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM subscribers WHERE active = 1").fetchall()


# ------------------------------------------------------------- delivery --

def sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _log_delivery(
    conn: sqlite3.Connection,
    subscriber_id: str,
    scored_event_id: str,
    status_: str,
    http_status: Optional[int],
    error: Optional[str],
) -> None:
    conn.execute(
        """
        INSERT INTO deliveries (id, subscriber_id, scored_event_id, status, http_status, attempted_at, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), subscriber_id, scored_event_id, status_, http_status, _now(), error),
    )


async def dispatch_webhooks(
    conn: sqlite3.Connection,
    scored_event_id: str,
    severity: Severity,
    feed_item: dict[str, Any],
) -> None:
    """Fan the just-scored event out to every subscriber whose threshold it meets.

    Deliberately does the network calls and the DB writes in two separate
    passes. Interleaving a write transaction with `await client.post(...)`
    would hold a SQLite write lock open for the duration of each outbound
    HTTP call, which is exactly the kind of thing that stalls unrelated
    event ingestion under load — see the WAL/busy_timeout note in db.py.
    """
    subscribers = [s for s in _active_subscribers(conn) if meets_severity(severity, s["min_severity"])]
    if not subscribers:
        return

    body = json.dumps(feed_item, default=str).encode("utf-8")
    results: list[tuple[str, str, Optional[int], Optional[str]]] = []

    async with httpx.AsyncClient(timeout=settings.webhook_timeout_seconds) as client:
        for sub in subscribers:
            secret = sub["secret"] or settings.webhook_secret
            signature = sign_payload(secret, body)
            headers = {
                "Content-Type": "application/json",
                "X-RiskLens-Signature": signature,
                "X-RiskLens-Event-Id": scored_event_id,
            }
            try:
                resp = await client.post(sub["url"], content=body, headers=headers)
                status_ = "delivered" if resp.status_code < 300 else "failed"
                results.append((sub["id"], status_, resp.status_code, None))
            except httpx.HTTPError as exc:
                results.append((sub["id"], "failed", None, str(exc)))

    for subscriber_id, status_, http_status, error in results:
        _log_delivery(conn, subscriber_id, scored_event_id, status_, http_status, error)
    conn.commit()
