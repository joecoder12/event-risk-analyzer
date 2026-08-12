"""Turns an arbitrary incoming EventIn into the normalized record we store.

The analyzer is source-agnostic by design: any application can POST an event
with nothing but an `event_type`. When the caller doesn't tell us the
category, we infer it from the event_type string so auth/activity/infra
scoring rules still apply.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from event_risk_analyzer.schemas import Category, EventIn

_AUTH_KEYWORDS = (
    "login", "logout", "signin", "signout", "auth", "mfa", "2fa",
    "password", "session", "sso", "token_issued", "credential",
)
_INFRA_KEYWORDS = (
    "config", "deploy", "security_group", "firewall", "network_acl",
    "admin_account", "service_account", "logging", "audit", "iam_policy",
    "infra", "server", "instance", "bucket_policy", "role_created",
)


def infer_category(event_type: str) -> Category:
    lowered = event_type.lower()
    if any(k in lowered for k in _AUTH_KEYWORDS):
        return "auth"
    if any(k in lowered for k in _INFRA_KEYWORDS):
        return "infra"
    return "activity"


def normalize(event: EventIn) -> dict[str, Any]:
    """Return a flat dict matching the raw_events table columns."""
    now = datetime.now(timezone.utc)
    category = event.category or infer_category(event.event_type)
    occurred_at = event.occurred_at or now

    actor_id = event.actor.id if event.actor else None
    actor_ip = event.actor.ip if event.actor else None

    payload = event.model_dump(mode="json")

    return {
        "id": str(uuid.uuid4()),
        "received_at": now.isoformat(),
        "occurred_at": occurred_at.isoformat(),
        "category": category,
        "event_type": event.event_type,
        "actor_id": actor_id,
        "actor_ip": actor_ip,
        "resource": event.resource,
        "payload": json.dumps(payload),
    }
