"""Runtime configuration, loaded from environment variables.

Everything here has a sane local-dev default so the service runs out of the
box with `event-risk-analyzer serve`, but every value that matters for
security (API keys, webhook secret) should be overridden via the environment
before this is exposed beyond localhost.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass(frozen=True)
class Settings:
    # Storage
    db_path: str = os.environ.get("RISKLENS_DB_PATH", "risklens.db")

    # Auth — callers must send `X-API-Key` matching one of these.
    api_keys: list[str] = field(
        default_factory=lambda: _split_csv(
            os.environ.get("RISKLENS_API_KEYS", "dev-local-key")
        )
    )

    # Outbound webhook signing secret (HMAC-SHA256 over the raw request body).
    webhook_secret: str = os.environ.get("RISKLENS_WEBHOOK_SECRET", "dev-webhook-secret")
    webhook_timeout_seconds: float = float(os.environ.get("RISKLENS_WEBHOOK_TIMEOUT", "5"))

    # Severity thresholds (0-100 risk score -> bucket)
    threshold_low: int = int(os.environ.get("RISKLENS_THRESHOLD_LOW", "25"))
    threshold_medium: int = int(os.environ.get("RISKLENS_THRESHOLD_MEDIUM", "50"))
    threshold_high: int = int(os.environ.get("RISKLENS_THRESHOLD_HIGH", "75"))
    threshold_critical: int = int(os.environ.get("RISKLENS_THRESHOLD_CRITICAL", "90"))

    # Business-hours window used by off-hours heuristics (UTC, 24h clock, Mon-Fri).
    business_hours_start: int = int(os.environ.get("RISKLENS_BUSINESS_HOURS_START", "9"))
    business_hours_end: int = int(os.environ.get("RISKLENS_BUSINESS_HOURS_END", "19"))

    # Patterns that mark a resource as sensitive when no explicit
    # metadata.sensitive flag is provided by the caller.
    sensitive_resource_patterns: list[str] = field(
        default_factory=lambda: _split_csv(
            os.environ.get(
                "RISKLENS_SENSITIVE_PATTERNS",
                "prod-db,customers,payroll,secrets,/admin,billing",
            )
        )
    )

    # Rule tuning
    auth_fail_burst_count: int = int(os.environ.get("RISKLENS_AUTH_FAIL_BURST_COUNT", "5"))
    auth_fail_burst_window_minutes: int = int(
        os.environ.get("RISKLENS_AUTH_FAIL_BURST_WINDOW_MIN", "10")
    )
    new_ip_lookback_days: int = int(os.environ.get("RISKLENS_NEW_IP_LOOKBACK_DAYS", "30"))
    bulk_export_record_threshold: int = int(
        os.environ.get("RISKLENS_BULK_EXPORT_THRESHOLD", "1000")
    )
    activity_rate_window_minutes: int = int(
        os.environ.get("RISKLENS_ACTIVITY_RATE_WINDOW_MIN", "60")
    )
    activity_rate_baseline_days: int = int(
        os.environ.get("RISKLENS_ACTIVITY_RATE_BASELINE_DAYS", "7")
    )
    activity_rate_zscore_threshold: float = float(
        os.environ.get("RISKLENS_ACTIVITY_RATE_ZSCORE", "3.0")
    )
    # Max plausible travel speed used by the impossible-travel heuristic, in km/h.
    # ~1100 km/h comfortably covers commercial air travel; faster than that
    # between two consecutive logins is flagged.
    impossible_travel_max_kmh: float = float(
        os.environ.get("RISKLENS_IMPOSSIBLE_TRAVEL_MAX_KMH", "1100")
    )


settings = Settings()
