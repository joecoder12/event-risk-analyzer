"""API key authentication for the analyzer's own endpoints.

A tool that scores everyone else's access events should not itself accept
unauthenticated writes — every route that ingests or reads event data
requires `X-API-Key`, compared with a constant-time check.
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from event_risk_analyzer.config import settings


def require_api_key(x_api_key: str = Header(default="")) -> str:
    for candidate in settings.api_keys:
        if hmac.compare_digest(x_api_key, candidate):
            return x_api_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid X-API-Key",
    )
