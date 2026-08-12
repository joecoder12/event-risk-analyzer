"""`event-risk-analyzer` console entry point."""
from __future__ import annotations

import argparse

import uvicorn

from event_risk_analyzer.db import init_db


def main() -> None:
    parser = argparse.ArgumentParser(prog="event-risk-analyzer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    init_db()
    uvicorn.run("event_risk_analyzer.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
