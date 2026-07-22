# CyberSentinel Backend

CyberSentinel is a security monitoring backend built with FastAPI, MongoDB, raw Wazuh ingestion, and a separate cloud-model API for classical ML inference.

The backend receives logs, stores raw and normalized security events, runs ML inference through the cloud-model service, creates correlated alert incidents, broadcasts new alerts over WebSockets, and supports admin-only Model Ops workflows.

## Architecture

- FastAPI exposes REST APIs for auth, users, logs, raw Wazuh ingestion, alerts, and ML operations.
- MongoDB stores users, raw Wazuh logs, normalized logs, alert incidents, retrain jobs, suppressions, promotions, and optional agent audit records.
- The cloud-model API owns model loading, prediction, training, version listing, and activation.
- Raw Wazuh ingestion stores immutable raw payloads first, then an async worker engineers normalized logs and calls ML.
- WebSockets broadcast newly created alert incidents to subscribed clients.
- Optional external investigation-agent integration is read-only from the backend perspective.

## ML Pipeline

1. Logs are ingested through authenticated REST or raw Wazuh archive forwarding.
2. Raw Wazuh batches are accepted at `POST /api/raw_wazuh_logs` with header `x-ingestion-key`.
3. The raw Wazuh pipeline deduplicates events by ingest metadata, stores raw payloads, engineers normalized log records, and marks processing status.
4. Wazuh-native feature extraction converts supported logs into the `wazuh_native_v1` numeric schema.
5. Backend calls the cloud-model API for prediction.
6. Non-benign results create or update correlated alert incidents.
7. Analyst feedback can confirm known attacks, mark false positives, create suppressions/promotions, and feed future retraining.

## Security Decisions

- JWT authentication with password hashing and optional TOTP-based 2FA.
- Email verification is required before login.
- Single-admin v1 registration gate.
- Shared-secret Wazuh ingestion through `WAZUH_INGEST_KEY`.
- Cloud-model admin actions require matching `MODEL_ADMIN_TOKEN` in backend and cloud-model services.
- Configurable CORS origins through `CORS_ALLOW_ORIGINS`.
- Optional investigation-agent integration sends reduced alert metadata only.

## API Overview

- `GET /api/health/` health check.
- `POST /api/auth/register` create the first admin user.
- `POST /api/auth/login` authenticate with optional TOTP code.
- `GET /api/auth/me` read current user profile and notification preferences.
- `POST /api/raw_wazuh_logs` ingest raw Wazuh archive batches.
- `POST /api/logs/` ingest a manual/API log.
- `GET /api/logs/` list normalized logs.
- `GET /api/logs/count` count normalized logs.
- `GET /api/alerts/` list alert incidents.
- `GET /api/alerts/analytics` get alert analytics.
- `POST /api/alerts/{id}/confirm-known` confirm an anomaly as a known attack.
- `POST /api/alerts/{id}/mark-false-positive` suppress a false positive.
- `POST /api/alerts/{id}/investigation-plan` call the optional external agent service.
- `POST /api/ml/batch-infer` run batch ML inference for pending logs.
- `POST /api/ml/models/retrain` queue an admin retrain job.
- `GET /api/ml/models/retrain-jobs` list retrain jobs.
- `GET /api/ml/models/versions` list cloud-model versions.
- `POST /api/ml/models/rollback` activate a previous cloud-model version.
- `GET /api/ml/suppressions` list false-positive suppressions.
- `GET /api/ws/alerts` WebSocket for alert notifications.

## Documentation

- Customer setup and Wazuh runbook: `CUSTOMER_E2E_SETUP_GUIDE.md`
- Current implemented-system spec: `cybersentinel_living_spec.md`
- Forwarder script: `scripts/wazuh_archives_forwarder.py`

## Runtime Notes

- `MODEL_API_URL` is required for ML inference/model ops. Startup validates it in the background so auth, logs, alerts, and health routes can still come up if the cloud-model service is cold or rate-limited.
- MongoDB is required; use `MONGO_URI` or the `MONGO_USER`/`MONGO_PASSWORD`/`MONGO_HOST` fallback.
- `MODEL_ADMIN_TOKEN` must match in backend and cloud-model env for Model Ops.
- `WAZUH_INGEST_KEY` must match the Wazuh forwarder env.
- SMTP must be configured for production account verification and password reset flows.
