#!/usr/bin/env python3
"""Demo client: feeds RiskLens realistic events and prints how it scored them.

Run the service first (in another terminal):
    event-risk-analyzer
Then:
    python examples/send_events.py

Part 1 replays examples/sample_events.jsonl (stateless rules — each event
is scored on its own). Part 2 walks through a scripted, timestamped
scenario that exercises the *stateful* rules — brute-force burst, a login
from a never-seen IP, and impossible travel — so you can see the analyzer
reason about an actor's history, not just a single event in isolation.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

SAMPLE_FILE = Path(__file__).parent / "sample_events.jsonl"


def _print_result(label: str, resp: httpx.Response) -> None:
    if resp.status_code >= 300:
        print(f"  ! {label}: HTTP {resp.status_code} {resp.text}")
        return
    body = resp.json()
    reasons = ", ".join(body["reasons"]) if body["reasons"] else "-"
    print(
        f"  {label:<28} score={body['score']:>3}  severity={body['severity']:<8}  reasons=[{reasons}]"
    )


def replay_sample_file(client: httpx.Client, headers: dict) -> None:
    print("\n=== Part 1: replaying examples/sample_events.jsonl ===")
    for line in SAMPLE_FILE.read_text().splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        resp = client.post("/events", json=event, headers=headers)
        _print_result(event["event_type"], resp)


def scripted_stateful_scenario(client: httpx.Client, headers: dict) -> None:
    print("\n=== Part 2: scripted scenario (brute force, new IP, impossible travel) ===")
    now = datetime.now(timezone.utc)

    print("\n-- brute-force login burst against u-eve --")
    for i in range(5):
        event = {
            "event_type": "login_failed",
            "actor": {"id": "u-eve", "ip": "192.0.2.77"},
            "occurred_at": (now + timedelta(seconds=i * 20)).isoformat(),
        }
        resp = client.post("/events", json=event, headers=headers)
        _print_result(f"login_failed #{i + 1}", resp)

    print("\n-- u-frank logs in from a known IP, then a brand-new one --")
    event = {
        "event_type": "login_success",
        "actor": {"id": "u-frank", "ip": "203.0.113.20"},
        "occurred_at": now.isoformat(),
    }
    _print_result("login_success (known ip)", client.post("/events", json=event, headers=headers))

    event = {
        "event_type": "login_success",
        "actor": {"id": "u-frank", "ip": "45.33.12.9"},
        "occurred_at": (now + timedelta(minutes=5)).isoformat(),
    }
    _print_result("login_success (new ip)", client.post("/events", json=event, headers=headers))

    print("\n-- u-grace logs in from New York, then Singapore an hour later --")
    event = {
        "event_type": "login_success",
        "actor": {"id": "u-grace", "ip": "198.51.100.5", "geo": {"lat": 40.7128, "lon": -74.0060, "country": "US"}},
        "occurred_at": now.isoformat(),
    }
    _print_result("login_success (New York)", client.post("/events", json=event, headers=headers))

    event = {
        "event_type": "login_success",
        "actor": {"id": "u-grace", "ip": "103.21.55.9", "geo": {"lat": 1.3521, "lon": 103.8198, "country": "SG"}},
        "occurred_at": (now + timedelta(hours=1)).isoformat(),
    }
    _print_result("login_success (Singapore, +1h)", client.post("/events", json=event, headers=headers))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="dev-local-key")
    args = parser.parse_args()

    headers = {"X-API-Key": args.api_key}
    with httpx.Client(base_url=args.base_url, timeout=10) as client:
        replay_sample_file(client, headers)
        scripted_stateful_scenario(client, headers)

        print("\n=== Current feed (severity >= medium) ===")
        feed = client.get("/feed", headers=headers)
        for item in feed.json():
            print(f"  [{item['severity']:<8}] {item['event_type']:<24} score={item['score']:>3}  {item['reasons']}")


if __name__ == "__main__":
    main()
