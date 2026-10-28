"""Vercel entrypoint: exposes the FastAPI `app` from the src/ package layout."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from event_risk_analyzer.app import app  # noqa: E402,F401
