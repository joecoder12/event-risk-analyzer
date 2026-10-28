from fastapi.testclient import TestClient

from event_risk_analyzer.config import settings

HEADERS = {"X-API-Key": "dev-local-key"}


def test_health_requires_no_auth(temp_db):
    from event_risk_analyzer.app import app

    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def test_ingest_requires_api_key(temp_db):
    from event_risk_analyzer.app import app

    with TestClient(app) as client:
        resp = client.post("/events", json={"event_type": "login_failed"})
        assert resp.status_code == 401


def test_ingest_and_read_back(temp_db):
    from event_risk_analyzer.app import app

    with TestClient(app) as client:
        resp = client.post(
            "/events",
            json={
                "event_type": "login_failed",
                "actor": {"id": "u1", "ip": "1.2.3.4"},
            },
            headers=HEADERS,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["category"] == "auth"
        assert body["severity"] in ("info", "low", "medium", "high", "critical")

        listed = client.get("/events", headers=HEADERS)
        assert listed.status_code == 200
        assert len(listed.json()) == 1
        assert listed.json()[0]["id"] == body["id"]


def test_feed_defaults_to_medium_and_above(temp_db):
    from event_risk_analyzer.app import app

    with TestClient(app) as client:
        # A plain, low-signal activity event should not clear the default "medium" feed bar.
        client.post("/events", json={"event_type": "page_view"}, headers=HEADERS)
        feed_resp = client.get("/feed", headers=HEADERS)
        assert feed_resp.status_code == 200
        assert feed_resp.json() == []

        # An infra event that disables logging should clear it.
        client.post("/events", json={"event_type": "logging_disabled"}, headers=HEADERS)
        feed_resp = client.get("/feed", headers=HEADERS)
        assert len(feed_resp.json()) == 1


def test_subscriber_crud(temp_db):
    from event_risk_analyzer.app import app

    with TestClient(app) as client:
        create = client.post(
            "/subscribers",
            json={"url": "https://example.com/hook", "min_severity": "high"},
            headers=HEADERS,
        )
        assert create.status_code == 201
        sub_id = create.json()["id"]

        listed = client.get("/subscribers", headers=HEADERS)
        assert len(listed.json()) == 1

        deleted = client.delete(f"/subscribers/{sub_id}", headers=HEADERS)
        assert deleted.status_code == 204

        missing = client.delete(f"/subscribers/{sub_id}", headers=HEADERS)
        assert missing.status_code == 404


def test_root_redirects_to_the_interactive_docs(temp_db):
    from event_risk_analyzer.app import app

    with TestClient(app) as client:
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers["location"] == "/docs"
