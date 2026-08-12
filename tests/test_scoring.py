from datetime import datetime, timedelta, timezone

from event_risk_analyzer.scoring import score_event, severity_for


def test_severity_buckets():
    assert severity_for(10) == "info"
    assert severity_for(30) == "low"
    assert severity_for(60) == "medium"
    assert severity_for(80) == "high"
    assert severity_for(95) == "critical"


def test_auth_fail_burst_triggers_at_threshold(insert_event, conn):
    now = datetime.now(timezone.utc)
    raw = None
    for _ in range(5):
        raw = insert_event("login_failed", actor_id="u1", actor_ip="1.1.1.1", occurred_at=now)
    score, severity, reasons = score_event(conn, raw)
    assert score >= 40
    assert any("auth_fail_burst" in r for r in reasons)


def test_auth_fail_burst_not_triggered_below_threshold(insert_event, conn):
    now = datetime.now(timezone.utc)
    raw = None
    for _ in range(3):
        raw = insert_event("login_failed", actor_id="u1", actor_ip="1.1.1.1", occurred_at=now)
    _score, _severity, reasons = score_event(conn, raw)
    assert not any("auth_fail_burst" in r for r in reasons)


def test_auth_new_ip_not_flagged_without_history(insert_event, conn):
    raw = insert_event("login_success", actor_id="u2", actor_ip="9.9.9.9")
    _score, _severity, reasons = score_event(conn, raw)
    assert not any("new_ip_login" in r for r in reasons)


def test_auth_new_ip_flagged_once_history_exists(insert_event, conn):
    now = datetime.now(timezone.utc)
    insert_event("login_success", actor_id="u2", actor_ip="9.9.9.9", occurred_at=now)
    raw = insert_event(
        "login_success", actor_id="u2", actor_ip="8.8.8.8", occurred_at=now + timedelta(hours=1)
    )
    _score, _severity, reasons = score_event(conn, raw)
    assert any("new_ip_login" in r for r in reasons)


def test_auth_impossible_travel_flagged(insert_event, conn):
    now = datetime.now(timezone.utc)
    new_york = {"lat": 40.7128, "lon": -74.0060, "country": "US"}
    singapore = {"lat": 1.3521, "lon": 103.8198, "country": "SG"}
    insert_event("login_success", actor_id="u3", actor_ip="1.2.3.4", occurred_at=now, geo=new_york)
    raw = insert_event(
        "login_success", actor_id="u3", actor_ip="5.6.7.8",
        occurred_at=now + timedelta(hours=1), geo=singapore,
    )
    _score, _severity, reasons = score_event(conn, raw)
    assert any("impossible_travel" in r for r in reasons)


def test_auth_plausible_travel_not_flagged(insert_event, conn):
    now = datetime.now(timezone.utc)
    boston = {"lat": 42.3601, "lon": -71.0589}
    new_york = {"lat": 40.7128, "lon": -74.0060}
    insert_event("login_success", actor_id="u4", actor_ip="1.2.3.4", occurred_at=now, geo=boston)
    raw = insert_event(
        "login_success", actor_id="u4", actor_ip="1.2.3.4",
        occurred_at=now + timedelta(hours=5), geo=new_york,
    )
    _score, _severity, reasons = score_event(conn, raw)
    assert not any("impossible_travel" in r for r in reasons)


def test_infra_logging_disabled_is_flagged_critical_signal(insert_event, conn):
    raw = insert_event("logging_disabled", category="infra")
    score, severity, reasons = score_event(conn, raw)
    assert score == 60
    assert severity == "medium"  # single-rule score; combined with other signals it crosses "high"/"critical"
    assert any("logging_tampering" in r for r in reasons)


def test_bulk_export_scales_with_volume(insert_event, conn):
    raw_small = insert_event("data_export", category="activity", metadata={"record_count": 1500})
    score_small, _, reasons_small = score_event(conn, raw_small)
    assert any("bulk_data_access" in r for r in reasons_small)
    assert score_small == 30

    raw_large = insert_event("data_export", category="activity", metadata={"record_count": 8000})
    score_large, _, reasons_large = score_event(conn, raw_large)
    assert score_large == 45


def test_sensitive_resource_pattern_match(insert_event, conn):
    raw = insert_event("record_viewed", category="activity", resource="prod-db/customers/1234")
    _score, _severity, reasons = score_event(conn, raw)
    assert any("sensitive_resource_access" in r for r in reasons)


def test_activity_rate_anomaly_skipped_for_new_actor(insert_event, conn):
    raw = insert_event("page_view", category="activity", actor_id="brand-new-user")
    _score, _severity, reasons = score_event(conn, raw)
    assert not any("activity_rate_anomaly" in r for r in reasons)


def test_priv_escalation_flagged(insert_event, conn):
    raw = insert_event("role_changed", category="auth", metadata={"new_role": "admin"})
    _score, _severity, reasons = score_event(conn, raw)
    assert any("privilege_escalation" in r for r in reasons)


def test_score_is_capped_at_100(insert_event, conn):
    now = datetime.now(timezone.utc)
    raw = None
    for _ in range(5):
        raw = insert_event("login_failed", actor_id="u5", actor_ip="1.1.1.1", occurred_at=now)
    score, _severity, _reasons = score_event(conn, raw)
    assert 0 <= score <= 100
