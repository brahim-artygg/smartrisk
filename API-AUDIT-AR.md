# SmartRisk Developer API v0.9 — Audit Result

## Audit status
- Tests: 148 passed, 0 failed
- Batch limits enforced from the stored plan
- Monthly usage reservation is atomic
- Active batch limits are atomic
- Idempotency is atomic and rejects a reused key with a different request
- API-key revocation/rotation is enforced
- Subscription status and expiration are enforced
- API RPS limits are persisted in the shared SQLite database
- 500-item Developer batch completes end-to-end in the test suite
- API summary responses are derived from the UnifiedRiskReport

## Programmatic result schema
Summary responses include:
- schema_version
- status
- address
- chain_id
- run_id
- risk (score, band, confidence, coverage, score_direction)
- verdict
- primary_detection
- detections
- risk_dimensions
- engines
- unknowns
- versions

Full responses return the original UnifiedRiskReport JSON produced by the engine.

## Important deployment condition
Plan/rate guarantees are enforced across processes that share the same SmartRisk SQLite database. For a multi-node deployment with independent databases, quota and rate state must move to a shared database/Redis layer before horizontal scaling.
