#!/usr/bin/env python3
"""A minimal, dependency-free webhook subscriber.

Registers itself as a RiskLens subscriber, then listens for pushed
high-severity events and verifies the `X-RiskLens-Signature` header before
trusting the payload — this is the "distribute this data" half of the
project: proof that a *different* application can receive and authenticate
risk-scored events without ever touching RiskLens's database directly.

Usage:
    python examples/webhook_receiver.py --port 9000 --register http://127.0.0.1:8000

Then, in another terminal, generate some events (examples/send_events.py)
and watch verified events print here as they arrive.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

SECRET = "dev-webhook-secret"  # must match RISKLENS_WEBHOOK_SECRET on the server


def make_handler(secret: str):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            signature = self.headers.get("X-RiskLens-Signature", "")
            expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(signature, expected):
                print(f"  ! REJECTED — signature mismatch (got {signature[:12]}...)", flush=True)
                self.send_response(401)
                self.end_headers()
                return

            event = json.loads(body)
            print(
                f"  VERIFIED  severity={event['severity']:<8} score={event['score']:>3}  "
                f"{event['event_type']}  reasons={event['reasons']}",
                flush=True,
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt: str, *args) -> None:  # silence default access log
            pass

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--secret", default=SECRET)
    parser.add_argument("--min-severity", default="high")
    parser.add_argument(
        "--register",
        default=None,
        help="RiskLens base URL to auto-register this receiver against, e.g. http://127.0.0.1:8000",
    )
    parser.add_argument("--api-key", default="dev-local-key")
    args = parser.parse_args()

    if args.register:
        url = f"http://127.0.0.1:{args.port}/hook"
        resp = httpx.post(
            f"{args.register}/subscribers",
            json={"url": url, "min_severity": args.min_severity, "secret": args.secret},
            headers={"X-API-Key": args.api_key},
        )
        resp.raise_for_status()
        print(f"Registered as subscriber {resp.json()['id']} -> {url} (min_severity={args.min_severity})", flush=True)

    server = HTTPServer(("127.0.0.1", args.port), make_handler(args.secret))
    print(f"Listening on http://127.0.0.1:{args.port}/hook — waiting for pushed events (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
