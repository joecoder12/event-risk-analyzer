"""Settings are read at import time, so each case runs in a fresh interpreter."""
from __future__ import annotations

import json
import os
import subprocess
import sys

_PRINT_SETTINGS = (
    "import json; from event_risk_analyzer.config import settings as s; "
    "print(json.dumps({'keys': s.api_keys, 'secret': s.webhook_secret}))"
)


def _settings_with(env: dict[str, str]) -> dict:
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("RISKLENS_", "VERCEL"))}
    result = subprocess.run(
        [sys.executable, "-c", _PRINT_SETTINGS],
        env={**clean, **env},
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def test_local_runs_fall_back_to_the_dev_defaults():
    settings = _settings_with({})
    assert settings["keys"] == ["dev-local-key"]
    assert settings["secret"] == "dev-webhook-secret"


def test_deployed_without_keys_accepts_no_key_and_never_uses_the_public_secret():
    settings = _settings_with({"VERCEL": "1"})
    assert settings["keys"] == []
    assert settings["secret"] != "dev-webhook-secret"


def test_explicit_values_win_when_deployed():
    settings = _settings_with(
        {"VERCEL": "1", "RISKLENS_API_KEYS": "a, b", "RISKLENS_WEBHOOK_SECRET": "s"}
    )
    assert settings["keys"] == ["a", "b"]
    assert settings["secret"] == "s"
