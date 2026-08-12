"""Pydantic request/response schemas."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator

Category = Literal["auth", "activity", "infra"]
Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_ORDER: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Geo(BaseModel):
    lat: float
    lon: float
    country: Optional[str] = None


class Actor(BaseModel):
    id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    geo: Optional[Geo] = None


class EventIn(BaseModel):
    """The event payload an application POSTs to /events.

    Only `event_type` is required. Everything else is optional so this can
    ingest events from almost any application without a custom adapter —
    `category` is inferred from `event_type` when omitted (see normalize.py).
    """

    event_type: str = Field(..., min_length=1, max_length=128)
    category: Optional[Category] = None
    occurred_at: Optional[datetime] = None
    actor: Optional[Actor] = None
    resource: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def _ensure_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class ScoredEventOut(BaseModel):
    id: str
    event_id: str
    occurred_at: datetime
    category: Category
    event_type: str
    actor_id: Optional[str] = None
    actor_ip: Optional[str] = None
    resource: Optional[str] = None
    score: int
    severity: Severity
    reasons: list[str]
    scored_at: datetime


class SubscriberIn(BaseModel):
    url: HttpUrl
    min_severity: Severity = "high"
    secret: Optional[str] = Field(
        default=None,
        description="Per-subscriber HMAC secret. Falls back to the server's "
        "global RISKLENS_WEBHOOK_SECRET if omitted.",
    )


class SubscriberOut(BaseModel):
    id: str
    url: str
    min_severity: Severity
    active: bool
    created_at: datetime
