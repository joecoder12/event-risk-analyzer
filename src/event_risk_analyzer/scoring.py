"""Deterministic, explainable risk-scoring engine.

Every rule is a small, independently-testable function that looks at the
event just stored (plus, where needed, that actor's recent history in
SQLite) and returns either nothing or `(points, reason)`. Points from every
rule that fires are summed and capped at 100 — an event can trigger several
rules at once, and the final score is fully explainable by walking the
`reasons` list back to the rule that produced each line.

This is intentionally rule-based rather than ML-based: the goal is a score
a SOC analyst (or an interviewer) can audit line by line, not a black box.
"""
from __future__ import annotations

import json
import math
import sqlite3
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from event_risk_analyzer.config import settings
from event_risk_analyzer.schemas import SEVERITY_ORDER, Severity

Rule = Callable[[sqlite3.Connection, dict], Optional[tuple[int, str]]]


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _payload(raw: dict) -> dict[str, Any]:
    return json.loads(raw["payload"])


def _is_off_hours(dt: datetime) -> bool:
    dt = dt.astimezone(timezone.utc)
    if dt.weekday() >= 5:  # Saturday/Sunday
        return True
    return not (settings.business_hours_start <= dt.hour < settings.business_hours_end)


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _matches_any(text: str, keywords: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(k in lowered for k in keywords)


def _is_sensitive_resource(raw: dict, payload: dict) -> bool:
    if payload.get("metadata", {}).get("sensitive") is True:
        return True
    resource = (raw.get("resource") or "").lower()
    return any(p.lower() in resource for p in settings.sensitive_resource_patterns)


# ---------------------------------------------------------------- AUTH ----

def rule_auth_fail_burst(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "auth" or "fail" not in raw["event_type"].lower():
        return None
    if not (raw["actor_id"] or raw["actor_ip"]):
        return None
    since = _parse_dt(raw["occurred_at"]) - timedelta(minutes=settings.auth_fail_burst_window_minutes)
    cur = conn.execute(
        """
        SELECT COUNT(*) AS n FROM raw_events
        WHERE category = 'auth' AND event_type LIKE '%fail%'
          AND occurred_at >= ? AND occurred_at <= ?
          AND ((actor_id IS NOT NULL AND actor_id = ?) OR (actor_ip IS NOT NULL AND actor_ip = ?))
        """,
        (since.isoformat(), raw["occurred_at"], raw["actor_id"], raw["actor_ip"]),
    )
    n = cur.fetchone()["n"]
    if n >= settings.auth_fail_burst_count:
        return 40, f"auth_fail_burst: {n} failed logins within {settings.auth_fail_burst_window_minutes} min"
    return None


def rule_auth_new_ip(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "auth" or "fail" in raw["event_type"].lower():
        return None
    if not (raw["actor_id"] and raw["actor_ip"]):
        return None
    since = _parse_dt(raw["occurred_at"]) - timedelta(days=settings.new_ip_lookback_days)
    cur = conn.execute(
        """
        SELECT DISTINCT actor_ip FROM raw_events
        WHERE category = 'auth' AND actor_id = ? AND id != ?
          AND occurred_at >= ? AND occurred_at < ?
        """,
        (raw["actor_id"], raw["id"], since.isoformat(), raw["occurred_at"]),
    )
    known_ips = {row["actor_ip"] for row in cur.fetchall() if row["actor_ip"]}
    if not known_ips:
        return None  # no history yet — not enough signal to call this "new"
    if raw["actor_ip"] not in known_ips:
        return 20, f"new_ip_login: {raw['actor_ip']} not seen for this actor in {settings.new_ip_lookback_days}d"
    return None


def rule_auth_impossible_travel(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "auth" or "fail" in raw["event_type"].lower():
        return None
    payload = _payload(raw)
    geo = (payload.get("actor") or {}).get("geo")
    if not geo:
        return None
    cur = conn.execute(
        """
        SELECT payload, occurred_at FROM raw_events
        WHERE category = 'auth' AND actor_id = ? AND id != ?
          AND event_type NOT LIKE '%fail%' AND occurred_at < ?
        ORDER BY occurred_at DESC LIMIT 1
        """,
        (raw["actor_id"], raw["id"], raw["occurred_at"]),
    )
    prev = cur.fetchone()
    if not prev:
        return None
    prev_payload = json.loads(prev["payload"])
    prev_geo = (prev_payload.get("actor") or {}).get("geo")
    if not prev_geo:
        return None

    dist_km = _haversine_km(prev_geo["lat"], prev_geo["lon"], geo["lat"], geo["lon"])
    hours = max((_parse_dt(raw["occurred_at"]) - _parse_dt(prev["occurred_at"])).total_seconds() / 3600, 1e-6)
    speed_kmh = dist_km / hours
    if speed_kmh > settings.impossible_travel_max_kmh and dist_km > 100:
        return 50, (
            f"impossible_travel: {dist_km:.0f}km in {hours:.2f}h "
            f"(~{speed_kmh:.0f} km/h, max plausible {settings.impossible_travel_max_kmh:.0f} km/h)"
        )
    return None


_PRIV_ESCALATION_KEYWORDS = ("role_changed", "permission_granted", "privilege", "elevated", "admin_granted")


def rule_auth_priv_escalation(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "auth":
        return None
    if _matches_any(raw["event_type"], _PRIV_ESCALATION_KEYWORDS):
        return 35, f"privilege_escalation: event_type={raw['event_type']!r}"
    return None


def rule_auth_off_hours_admin(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "auth" or "fail" in raw["event_type"].lower():
        return None
    payload = _payload(raw)
    role = str((payload.get("metadata") or {}).get("role", "")).lower()
    resource = (raw.get("resource") or "").lower()
    is_admin = role in ("admin", "administrator", "superuser", "owner") or "admin" in resource
    if not is_admin:
        return None
    if _is_off_hours(_parse_dt(raw["occurred_at"])):
        return 15, "off_hours_admin_login: admin login outside configured business hours"
    return None


# ------------------------------------------------------------ ACTIVITY ----

def rule_activity_bulk_export(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "activity" or not _matches_any(raw["event_type"], ("export", "download", "bulk")):
        return None
    payload = _payload(raw)
    count = (payload.get("metadata") or {}).get("record_count")
    if not isinstance(count, (int, float)):
        return None
    threshold = settings.bulk_export_record_threshold
    if count >= threshold * 5:
        return 45, f"bulk_data_access: {int(count)} records exported (>=5x threshold of {threshold})"
    if count >= threshold:
        return 30, f"bulk_data_access: {int(count)} records exported (>= threshold of {threshold})"
    return None


def rule_activity_sensitive_resource(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    payload = _payload(raw)
    if _is_sensitive_resource(raw, payload):
        return 20, f"sensitive_resource_access: resource={raw.get('resource')!r}"
    return None


def rule_activity_rate_anomaly(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "activity" or not raw["actor_id"]:
        return None

    now = _parse_dt(raw["occurred_at"])
    window_start = now - timedelta(minutes=settings.activity_rate_window_minutes)
    baseline_start = now - timedelta(days=settings.activity_rate_baseline_days)

    cur = conn.execute(
        """
        SELECT COUNT(*) AS n FROM raw_events
        WHERE category = 'activity' AND actor_id = ?
          AND occurred_at >= ? AND occurred_at <= ?
        """,
        (raw["actor_id"], window_start.isoformat(), raw["occurred_at"]),
    )
    current_count = cur.fetchone()["n"]

    cur = conn.execute(
        """
        SELECT occurred_at FROM raw_events
        WHERE category = 'activity' AND actor_id = ?
          AND occurred_at >= ? AND occurred_at < ?
        """,
        (raw["actor_id"], baseline_start.isoformat(), window_start.isoformat()),
    )
    rows = [r["occurred_at"] for r in cur.fetchall()]
    if len(rows) < 3:
        return None  # not enough history to establish a baseline

    bucket_minutes = settings.activity_rate_window_minutes
    buckets: dict[str, int] = {}
    for ts in rows:
        dt = _parse_dt(ts)
        bucket_key = dt.strftime("%Y-%m-%d %H") + str(dt.minute // max(bucket_minutes, 1))
        buckets[bucket_key] = buckets.get(bucket_key, 0) + 1
    counts = list(buckets.values())
    if len(counts) < 3:
        return None

    mean = statistics.mean(counts)
    stdev = statistics.pstdev(counts) or 1.0
    z = (current_count - mean) / stdev
    if z >= settings.activity_rate_zscore_threshold:
        return 25, f"activity_rate_anomaly: {current_count} events vs baseline mean {mean:.1f} (z={z:.1f})"
    return None


def rule_activity_off_hours_novel(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "activity" or not raw["actor_id"]:
        return None
    if not _is_off_hours(_parse_dt(raw["occurred_at"])):
        return None
    baseline_start = _parse_dt(raw["occurred_at"]) - timedelta(days=settings.activity_rate_baseline_days)
    cur = conn.execute(
        """
        SELECT occurred_at FROM raw_events
        WHERE category = 'activity' AND actor_id = ? AND id != ?
          AND occurred_at >= ? AND occurred_at < ?
        """,
        (raw["actor_id"], raw["id"], baseline_start.isoformat(), raw["occurred_at"]),
    )
    prior_off_hours = sum(1 for r in cur.fetchall() if _is_off_hours(_parse_dt(r["occurred_at"])))
    if prior_off_hours == 0:
        return 10, "off_hours_activity: first off-hours activity observed for this actor"
    return None


# --------------------------------------------------------------- INFRA ----

def rule_infra_secgroup_change(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "infra":
        return None
    if _matches_any(raw["event_type"], ("security_group", "firewall_rule", "network_acl", "bucket_policy")):
        return 40, f"network_control_change: event_type={raw['event_type']!r}"
    return None


def rule_infra_new_privileged_account(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "infra":
        return None
    if _matches_any(raw["event_type"], ("admin_account_created", "service_account_created", "role_created")):
        return 35, f"new_privileged_account: event_type={raw['event_type']!r}"
    return None


def rule_infra_change_outside_window(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "infra" or not _matches_any(raw["event_type"], ("config_change", "config_changed")):
        return None
    if _is_off_hours(_parse_dt(raw["occurred_at"])):
        return 30, "unauthorized_change_window: config change outside the declared change window"
    return None


def rule_infra_logging_tampering(conn: sqlite3.Connection, raw: dict) -> Optional[tuple[int, str]]:
    if raw["category"] != "infra":
        return None
    if _matches_any(raw["event_type"], ("logging_disabled", "audit_disabled", "log_deletion", "logs_cleared")):
        return 60, f"logging_tampering: event_type={raw['event_type']!r} — likely anti-forensic action"
    return None


ALL_RULES: tuple[Rule, ...] = (
    rule_auth_fail_burst,
    rule_auth_new_ip,
    rule_auth_impossible_travel,
    rule_auth_priv_escalation,
    rule_auth_off_hours_admin,
    rule_activity_bulk_export,
    rule_activity_sensitive_resource,
    rule_activity_rate_anomaly,
    rule_activity_off_hours_novel,
    rule_infra_secgroup_change,
    rule_infra_new_privileged_account,
    rule_infra_change_outside_window,
    rule_infra_logging_tampering,
)


def severity_for(score: int) -> Severity:
    if score >= settings.threshold_critical:
        return "critical"
    if score >= settings.threshold_high:
        return "high"
    if score >= settings.threshold_medium:
        return "medium"
    if score >= settings.threshold_low:
        return "low"
    return "info"


def score_event(conn: sqlite3.Connection, raw: dict) -> tuple[int, Severity, list[str]]:
    """Run every applicable rule against `raw` and return (score, severity, reasons)."""
    total = 0
    reasons: list[str] = []
    for rule in ALL_RULES:
        result = rule(conn, raw)
        if result is None:
            continue
        points, reason = result
        total += points
        reasons.append(reason)
    total = min(total, 100)
    return total, severity_for(total), reasons


def meets_severity(actual: Severity, minimum: Severity) -> bool:
    return SEVERITY_ORDER[actual] >= SEVERITY_ORDER[minimum]
