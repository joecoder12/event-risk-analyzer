# RiskLens — Event Security Risk Analyzer

RiskLens ingests security-relevant events from **any** application, scores
each one for risk using a deterministic, explainable rule engine, and
distributes flagged events to other systems through a feed API and
HMAC-signed webhooks.

It's built to demonstrate three things end to end: **ingestion** from an
arbitrary source, **detection logic** that goes beyond a flat checklist
(velocity-based brute-force detection, impossible-travel, behavioral
baselining, anti-forensic action detection), and **distribution** — the
data doesn't just sit in a dashboard, it gets pushed, authenticated, out to
whoever subscribes to it.

```
 your application(s)
        │  POST /events   (any app, any stack — X-API-Key auth)
        ▼
 ┌───────────────┐     ┌──────────────────┐     ┌────────────────┐
 │  normalize.py │ ──▶ │   scoring.py      │ ──▶ │  SQLite         │
 │  (categorize) │     │ (13 rule funcs,   │     │  raw_events     │
 └───────────────┘     │  0-100 + reasons) │     │  scored_events  │
                        └──────────────────┘     └────────┬────────┘
                                                            │
                                    ┌───────────────────────┼───────────────────────┐
                                    ▼                                               ▼
                          GET /feed, GET /events                          background task:
                          (pull, filter by severity)                      HMAC-signed webhook
                                                                           POST to subscribers
```

## Why it's not a toy scanner

- **Source-agnostic ingestion.** Only `event_type` is required. Everything
  else — category, actor, geo, metadata — is optional, so any application
  can start sending events with a single `POST` and no custom adapter.
- **The scoring is a rule engine you can audit line by line, not a black
  box.** Every rule in `scoring.py` is an independent, unit-tested function.
  A score of 75 always comes with the exact reasons that produced it
  (`reasons: ["bulk_data_access: 8400 records...", "sensitive_resource_access: ..."]`).
- **Some rules are stateful.** Brute-force detection, "have we seen this IP
  before," impossible travel, and activity-rate anomalies all query the
  actor's own history in SQLite — this isn't just per-event pattern
  matching.
- **Distribution is authenticated, not just "here's an endpoint."** Every
  webhook delivery is HMAC-SHA256 signed; `examples/webhook_receiver.py`
  verifies the signature before trusting a payload, exactly like a real
  subscriber would.
- **It secures itself.** Every route that reads or writes event data
  requires `X-API-Key`, checked with a constant-time comparison.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

event-risk-analyzer            # starts on http://127.0.0.1:8000
```

In another terminal, send it some events:

```bash
python examples/send_events.py
```

This replays `examples/sample_events.jsonl` and then runs a scripted
scenario that walks through the stateful rules (a 5-attempt brute-force
burst, a login from a never-seen IP, and an impossible-travel login pair),
printing the score and reasons for each.

### See the distribution side working

```bash
# terminal 2 — register as a subscriber and listen for pushed events
python examples/webhook_receiver.py --port 9000 --register http://127.0.0.1:8000 --min-severity medium

# terminal 3 — generate events; the receiver prints each one it verifies
python examples/send_events.py
```

The receiver checks `X-RiskLens-Signature` against its shared secret before
printing anything — a tampered or unsigned payload is rejected with 401.

## API reference

All routes except `/health` require `X-API-Key: <key>` (default dev key:
`dev-local-key`, override with `RISKLENS_API_KEYS`).

| Method | Path                     | Purpose                                                            |
|--------|--------------------------|---------------------------------------------------------------------|
| POST   | `/events`                | Ingest one event; returns its score, severity, and reasons          |
| GET    | `/events`                | Query the full scored log (`since`, `category`, `min_severity`, `limit`) |
| GET    | `/feed`                  | Distribution-facing feed — defaults to `medium`+ only                |
| POST   | `/subscribers`           | Register a webhook (`url`, `min_severity`, optional per-subscriber `secret`) |
| GET    | `/subscribers`           | List subscribers                                                     |
| DELETE | `/subscribers/{id}`      | Remove a subscriber                                                   |
| GET    | `/health`                | Liveness check, no auth                                               |

`POST /events` body (only `event_type` is required):

```json
{
  "event_type": "login_failed",
  "category": "auth",
  "occurred_at": "2026-08-12T02:14:00Z",
  "actor": {"id": "u-123", "ip": "203.0.113.5", "geo": {"lat": 40.71, "lon": -74.0}},
  "resource": "webapp",
  "metadata": {"role": "admin"}
}
```

## Scoring rules

Category is inferred from `event_type` when not given (keyword match —
`login`/`auth`/`mfa` → `auth`; `config`/`firewall`/`admin_account` →
`infra`; otherwise `activity`). Points from every rule that fires are
summed and capped at 100.

| Rule | Category | Points | Signal |
|---|---|---|---|
| `auth_fail_burst` | auth | 40 | ≥5 failed logins for the same actor/IP within 10 min |
| `new_ip_login` | auth | 20 | Successful login from an IP never seen for this actor (only once history exists) |
| `impossible_travel` | auth | 50 | Two logins imply travel faster than 1100 km/h (needs `actor.geo` on both) |
| `privilege_escalation` | auth | 35 | `role_changed` / `permission_granted` / similar |
| `off_hours_admin_login` | auth | 15 | Admin login outside business hours |
| `bulk_data_access` | activity | 30–45 | Export/download above a record-count threshold (scales up at 5×) |
| `sensitive_resource_access` | activity | 20 | Resource matches a sensitive pattern or `metadata.sensitive` |
| `activity_rate_anomaly` | activity | 25 | Current-hour event count is a z-score outlier vs. the actor's 7-day baseline |
| `off_hours_activity` | activity | 10 | First-ever off-hours activity for this actor |
| `network_control_change` | infra | 40 | Security-group / firewall-rule / ACL change |
| `new_privileged_account` | infra | 35 | Admin or service account created |
| `unauthorized_change_window` | infra | 30 | Config change outside the declared change window |
| `logging_tampering` | infra | 60 | Logging/audit disabled — a strong anti-forensic signal |

Severity buckets (`RISKLENS_THRESHOLD_*` to tune):
`0-24 info · 25-49 low · 50-74 medium · 75-89 high · 90-100 critical`.

## Distribution / webhooks

A subscriber registers a URL and a minimum severity. Every scored event
that meets that threshold is POSTed to the URL with:

```
X-RiskLens-Signature: <hex hmac-sha256(secret, raw_json_body)>
X-RiskLens-Event-Id: <scored event id>
```

`secret` falls back to the server-wide `RISKLENS_WEBHOOK_SECRET` if a
subscriber doesn't set its own. Every delivery attempt — success or
failure — is logged in the `deliveries` table for audit purposes.

## A real concurrency bug found while building this

Manual load-testing surfaced a genuine deadlock: FastAPI runs
`BackgroundTasks` *inside* the same dependency-exit-stack scope as the
request that scheduled them, so `POST /events`'s database connection
stayed open (uncommitted) for the entire lifetime of its own background
webhook-dispatch task. That task opens a *second* connection and, to log
a delivery, needs the write lock the first connection is still holding —
which only gets released once the background task finishes. Circular
wait, broken only when SQLite's `busy_timeout` gave up after 10 seconds
and every request queued behind it failed.

The fix is in `app.py`: commit explicitly right after the writes, before
scheduling the background task, so the lock is released before dispatch
ever starts. `tests/test_webhook_delivery.py` is a regression test for
this specifically — it asserts ingestion returns in well under the
`busy_timeout` and that the webhook is actually delivered, so a
reintroduced deadlock fails the test suite instead of failing silently
under load.

Two related, smaller fixes landed alongside it: WAL mode + an explicit
`busy_timeout` (`db.py`), and `check_same_thread=False` (the same
dependency-cleanup mechanics can resume a paused generator on a different
worker thread than the one that opened the connection).

## Configuration

All via environment variables (see `config.py` for the full list and
defaults): `RISKLENS_DB_PATH`, `RISKLENS_API_KEYS` (comma-separated),
`RISKLENS_WEBHOOK_SECRET`, `RISKLENS_THRESHOLD_{LOW,MEDIUM,HIGH,CRITICAL}`,
`RISKLENS_BUSINESS_HOURS_{START,END}`, `RISKLENS_SENSITIVE_PATTERNS`, and
per-rule tuning knobs (burst thresholds, lookback windows, z-score cutoff).

## Testing

```bash
pytest
```

25 tests covering category inference, every scoring rule (including the
"don't flag a brand-new actor" negative cases), the API surface, and the
deadlock regression above.

## Roadmap

- Pluggable ingestion adapters (tail a log file / poll a database table)
  for applications that can't POST directly
- Retry with backoff for failed webhook deliveries (currently one attempt,
  logged either way)
- A minimal read-only dashboard over `/feed`
- STIX-shaped export alongside the current JSON feed
