from datetime import datetime, timezone

from event_risk_analyzer.normalize import infer_category, normalize
from event_risk_analyzer.schemas import Actor, EventIn


def test_infer_category_auth():
    assert infer_category("login_failed") == "auth"
    assert infer_category("mfa_challenge_sent") == "auth"


def test_infer_category_infra():
    assert infer_category("security_group_modified") == "infra"
    assert infer_category("admin_account_created") == "infra"


def test_infer_category_defaults_to_activity():
    assert infer_category("report_generated") == "activity"


def test_normalize_respects_explicit_category_over_inference():
    event = EventIn(event_type="widget_clicked", category="infra")
    raw = normalize(event)
    assert raw["category"] == "infra"


def test_normalize_fills_occurred_at_when_missing():
    event = EventIn(event_type="login_success")
    raw = normalize(event)
    assert raw["occurred_at"] is not None


def test_normalize_extracts_actor_fields():
    event = EventIn(
        event_type="login_success",
        actor=Actor(id="user-1", ip="10.0.0.5"),
        occurred_at=datetime.now(timezone.utc),
    )
    raw = normalize(event)
    assert raw["actor_id"] == "user-1"
    assert raw["actor_ip"] == "10.0.0.5"
