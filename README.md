# CyberSentinel Backend

CyberSentinel is a classical ML based security monitoring backend with a sandboxed investigation planning agent hosted in a sibling repository. This backend ingests logs, performs batch ML inference through a separate cloud-model API service, stores immutable alerts, and pushes alerts over WebSockets.

## Architecture
- FastAPI service exposes REST APIs for ingestion, auth, alerts, and ML operations.
- MongoDB stores logs and immutable alerts in separate collections.
- ML pipeline runs batch inference by calling the external cloud-model API.
- WebSockets broadcast new alerts to subscribed clients.
- Agent integration is a read-only HTTP client to a separate repo/service.
- Agent audit logs are stored in MongoDB to track requests and responses.

## ML Pipeline
1. Logs are ingested via REST into the logs collection.
2. Feature extraction converts logs into a numeric feature matrix.
3. Batch inference sends feature vectors to the cloud-model API for prediction.
4. Hybrid decision logic:
   - If Random Forest predicts a known attack with high probability, create a known attack alert.
   - Else if Isolation Forest anomaly score exceeds the threshold, create an anomaly alert.
5. Alerts are immutable and stored separately from logs.
6. Model integrity hashes are verified on load.

## Agent Boundaries
- The investigation planning agent is external and sandboxed in a separate repo: `CyberSentinel-Agentic-AI`.
- The agent only receives alert metadata (no raw logs).
- The agent cannot access internal services or databases.
- The agent cannot modify system state.

## Security Decisions
- JWT authentication with password hashing and optional TOTP-based 2FA.
- Single-admin v1 registration gate.
- Cloud-model service boundary keeps model binaries outside this backend repo.
- Audit-safe agent integration by keeping it read-only.
- Configurable detailed logging through `DETAILED_LOGGING` or `DEBUG_MODE`.

## API Overview
- `POST /api/auth/register` create the first admin user.
- `POST /api/auth/login` authenticate with optional TOTP code.
- `POST /api/logs/` ingest a log via REST.
- `POST /api/ml/batch-infer` run batch ML inference.
- `POST /api/ml/models/retrain` queue a retrain job (admin only).
- `GET /api/ml/models/retrain-jobs` list retrain jobs (admin only).
- `GET /api/ml/models/versions` list model versions (admin only).
- `POST /api/ml/models/rollback` activate a previous model version (admin only).
- `GET /api/alerts/` list alerts.
- `POST /api/alerts/{id}/confirm-known` confirm anomaly as known-attack label (admin only).
- `POST /api/alerts/{id}/investigation-plan` call the external agent service.
- `GET /api/ws/alerts` WebSocket for alert notifications.

## Notes
- Backend startup requires `MODEL_API_URL` and verifies the cloud-model API is reachable.
- Model ops endpoints require `MODEL_ADMIN_TOKEN` configured in backend and cloud-model env.
- Place model `.pkl` files in `CyberSentinel-Cloud-Model/models/` on each developer machine.
- One-time terminology migration script: `python scripts/migrate_unknown_attack_to_anomaly.py`.

For full setup instructions, see `SETUP.md`.
