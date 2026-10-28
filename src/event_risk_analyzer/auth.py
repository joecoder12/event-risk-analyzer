"""API key authentication for the analyzer's own endpoints.

A tool that scores everyone else's access events should not itself accept
unauthenticated writes — every route that ingests or reads event data
requires `X-API-Key`, compared with a constant-time check.
"""
from __future__ import annotations

import hmac

from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from event_risk_analyzer.config import settings

# Declared as a security scheme (not a plain header) so the /docs page shows a
# single "Authorize" button instead of a key field on every endpoint.
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(x_api_key: Optional[str] = Security(_api_key_header)) -> str:
    x_api_key = x_api_key or ""
    for candidate in settings.api_keys:
        if hmac.compare_digest(x_api_key, candidate):
            return x_api_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid X-API-Key",
    )
