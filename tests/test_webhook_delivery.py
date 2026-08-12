"""Regression test for a real deadlock found during manual testing.

FastAPI runs BackgroundTasks *inside* the same dependency-exit-stack scope
as the request that scheduled them. `POST /events` used to leave its DB
connection open (uncommitted) until that scope closed — which doesn't
happen until the background webhook-dispatch task finishes. The dispatch
task opens its *own* connection and blocks on the still-held write lock,
which can only be released once the dispatch task finishes: a deadlock,
broken only by SQLite's busy_timeout eventually giving up.

The fix (see app.py) is an explicit `conn.commit()` right after the writes,
before the background task is scheduled. This test spins up a real local
HTTP server as a webhook subscriber and asserts delivery completes quickly
— if the deadlock regresses, this hangs for the full busy_timeout instead
of finishing in well under a second.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": "dev-local-key"}


def _start_receiver() -> tuple[HTTPServer, int, list[dict]]:
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, received


def test_webhook_dispatch_does_not_deadlock_ingestion(temp_db):
    from event_risk_analyzer.app import app

    server, port, received = _start_receiver()
    try:
        with TestClient(app) as client:
            create = client.post(
                "/subscribers",
                json={"url": f"http://127.0.0.1:{port}/hook", "min_severity": "medium"},
                headers=HEADERS,
            )
            assert create.status_code == 201

            start = time.monotonic()
            resp = client.post(
                "/events",
                json={"event_type": "logging_disabled"},  # scores 60 -> "medium", clears the subscriber bar
                headers=HEADERS,
            )
            elapsed = time.monotonic() - start
            assert resp.status_code == 201
            # The request itself must return immediately — dispatch happens
            # in the background, so this should never approach the 10s
            # busy_timeout that a regressed deadlock would hit.
            assert elapsed < 2.0, f"ingestion took {elapsed:.2f}s — looks like the deadlock is back"

            deadline = time.monotonic() + 3.0
            while not received and time.monotonic() < deadline:
                time.sleep(0.05)
            assert received, "webhook was never delivered within 3s"
            assert received[0]["event_type"] == "logging_disabled"
    finally:
        server.shutdown()
