# CyberSentinel Living Specification

Status: Active  
Document type: Living specification for the currently implemented backend-centered system  
Last updated: 2026-07-15  
Canonical customer runbook: `CUSTOMER_E2E_SETUP_GUIDE.md`

Primary source repos in this workspace:

- `CyberSentinel-Backend`
- `CyberSentinel-Frontend`
- `CyberSentinel-Cloud-Model`
- `CyberSentinel-AI` for historical notebooks and model artifacts

## 1. Product Summary

CyberSentinel is a small-SOC security monitoring application built around:

- a FastAPI backend,
- a React frontend,
- MongoDB storage,
- Wazuh log ingestion,
- classical ML inference through a separate cloud-model API.

The current product:

1. Ingests manual/API logs and raw Wazuh archive events.
2. Stores raw Wazuh events separately from normalized logs.
3. Engineers Wazuh-native features for supported log types.
4. Calls a cloud-model service for predictions.
5. Creates or updates correlated alert incidents for non-benign results.
6. Lets an admin review logs, alerts, notification preferences, false positives, model versions, retrain jobs, and rollback actions.

The system is human-in-the-loop. It detects and organizes security signals, but it does not perform automated remediation.

## 2. Scope And Non-Goals

In scope today:

- Single FastAPI backend instance.
- MongoDB-backed users, logs, raw Wazuh events, alerts, retrain jobs, promotions, suppressions, and optional agent audit events.
- Single-admin bootstrap model.
- Email/password login with JWT sessions.
- Email verification before login.
- Password reset by emailed 6-digit code.
- Optional TOTP 2FA.
- Authenticated manual log ingestion.
- Shared-secret raw Wazuh ingestion.
- Async raw Wazuh processing workers.
- Cloud-model-only inference at backend startup.
- Admin Model Ops: retrain jobs, model version listing, rollback, suppressions.
- Alert analytics and correlated incident-style alert records.
- WebSocket broadcast when a new alert incident is created.
- Optional external investigation planning agent integration.

Out of scope today:

- Multi-tenant account model.
- Production-grade RBAC beyond first-admin checks.
- Automated response/remediation.
- Enterprise Wazuh cluster deployment.
- Docker Compose packaging.
- Built-in TLS termination or secrets manager integration.
- Frontend route hard guards for every authenticated page.
- Frontend WebSocket consumption.

## 3. Runtime Topology

```text
React frontend
  -> FastAPI backend
  -> MongoDB Atlas or MongoDB-compatible deployment
  -> Cloud-model API

Wazuh manager
  -> /var/ossec/logs/archives/archives.json
  -> scripts/wazuh_archives_forwarder.py
  -> POST /api/raw_wazuh_logs
  -> raw_wazuh_logs collection
  -> background raw Wazuh workers
  -> logs collection
  -> cloud-model prediction
  -> alerts collection
```

Default local ports:

- Frontend: `http://localhost:3000`
- Backend: `http://127.0.0.1:8000`
- Cloud-model API: `http://127.0.0.1:8010`

Hosted customer setup is documented in `CUSTOMER_E2E_SETUP_GUIDE.md`.

## 4. Core Domain Model

### User

Stored in MongoDB collection `user`.

Important fields:

- `email`
- `password_hash`
- `first_name`
- `last_name`
- `is_2fa_enabled`
- `totp_secret`
- `email_verified`
- `email_verification_token_hash`
- `email_verification_expires_at`
- `password_reset_code_hash`
- `password_reset_expires_at`
- `notification_prefs`
- `created_at`

Rules:

- Only the first registration succeeds.
- The earliest created user is treated as admin.
- Login is blocked until email is verified.
- Notification preferences are stored under the user document.

### Raw Wazuh Log

Stored in MongoDB collection `raw_wazuh_logs`.

Important fields:

- `ingest_key`
- `payload`
- `ingest_meta`
- `sent_at`
- `ingested_at`
- `processing.status`
- `processing.attempts`
- `processing.next_retry_at`
- `processing.last_error`
- `processing.engineered_log_id`

Rules:

- Raw Wazuh ingestion uses idempotent upsert by `ingest_key`.
- Forwarder offset metadata is preferred when present.
- Duplicate raw events are counted but not reinserted.
- Background workers claim pending/error rows and retry failures with backoff.

### Normalized Log

Stored in MongoDB collection `logs`.

Important fields:

- `timestamp`
- `source`
- `message`
- `severity`
- `metadata`
- `ingested_at`
- `ml_status`
- `ml_processed_at`
- `ml_result`
- `ml_model_version`
- `ml_error`
- `ml_skip_reason`

Rules:

- Manual/API logs are created through `POST /api/logs/`.
- Engineered Wazuh logs preserve the original Wazuh event under `metadata.raw_wazuh_payload`.
- Raw Wazuh engineered logs carry `metadata.raw_ingest_key`.
- Batch inference fetches logs whose `ml_status` is missing, `pending`, or `error`.
- Done/skipped logs are not selected by normal batch inference.

### Alert Incident

Stored in MongoDB collection `alerts`.

Important fields:

- `incident_id`
- `status`
- `created_at`
- `opened_at`
- `last_seen_at`
- `closed_at`
- `correlation_key`
- `event_count`
- `log_ids`
- `children`
- `alert_type`
- `classification`
- `source_ip`
- `destination_ip`
- `severity`
- `model_versions_seen`
- `metadata`

Rules:

- Alerts are incident-style records, not immutable one-row-per-event records.
- A new non-benign result creates a new alert incident or updates an open correlated incident.
- Correlation uses alert type, classification/anomaly sentinel, source IP, destination IP, and signal key.
- Open incidents are updated when matching events arrive within the inactivity window.
- Confirm-known and false-positive actions update both alert metadata and linked log metadata.

## 5. Primary Flows

### Registration And Login

1. User registers through `POST /api/auth/register`.
2. Backend creates the first admin user only.
3. Backend stores a password hash and email-verification token hash.
4. Backend sends a verification email through configured SMTP.
5. User verifies with `GET /api/auth/verify-email?token=...`.
6. User logs in with `POST /api/auth/login`.
7. If 2FA is enabled, login also requires a valid TOTP code.
8. Backend returns a JWT access token.

If SMTP is missing, the backend logs email content. Customer deployments should configure SMTP.

### Raw Wazuh Ingestion

1. Wazuh writes JSON lines to `archives.json`.
2. `scripts/wazuh_archives_forwarder.py` reads appended bytes with offset tracking.
3. The forwarder posts batches to `POST /api/raw_wazuh_logs`.
4. Backend validates `source="wazuh"`, `type="raw"`, request size, batch size, and `x-ingestion-key`.
5. Backend upserts raw rows into `raw_wazuh_logs`.
6. Background workers engineer normalized logs.
7. Supported logs run through cloud-model inference.
8. Non-benign results create or update alert incidents.

Primary customer Wazuh integration uses this path.

### Legacy Direct Wazuh Alert Ingestion

`POST /api/logs/wazuh` still exists and accepts individual Wazuh alert-like payloads with header `X-WAZUH-KEY`.

This endpoint is legacy compatibility, not the primary customer setup path.

### Manual/API Log Ingestion

1. Authenticated caller posts to `POST /api/logs/`.
2. Backend stores the payload through `IngestionService`.
3. Stored source is the ingestion channel (`api`), not necessarily the caller-provided source field.
4. Later `POST /api/ml/batch-infer` can process eligible logs.

### Batch Inference

1. Authenticated caller invokes `POST /api/ml/batch-infer`.
2. Backend selects eligible logs by `ml_status`.
3. Unsupported Wazuh decoders are marked skipped.
4. Supported logs are transformed to features.
5. Backend calls `POST <MODEL_API_URL>/predict`.
6. Backend marks each log done/error/skipped.
7. Non-benign predictions create or update alert incidents.

Current Wazuh ML support is scoped to decoder `web-accesslog`. Other Wazuh decoders are skipped with `decoder_not_supported_v1`.

### Analyst Feedback

Admin-only feedback actions:

- `POST /api/alerts/{alert_id}/confirm-known`
- `POST /api/alerts/{alert_id}/mark-false-positive`

Effects:

- Confirm-known stores a manual promotion fingerprint and normalized attack label.
- False-positive stores a suppression fingerprint.
- Suppressions can be listed, activated, and deactivated through `/api/ml/suppressions`.
- Feedback can augment future retraining datasets.

### Model Ops

1. Admin queues retraining through `POST /api/ml/models/retrain`.
2. Backend creates an `ml_retrain_jobs` row.
3. Backend builds a dataset from recent `raw_wazuh_logs`, with optional file fallback.
4. Backend augments the dataset with analyst feedback.
5. Backend posts the training dataset to the cloud-model API.
6. Cloud-model trains, stores a version, and activates it.
7. Admin can list versions and activate a previous version through rollback.

Retraining requires enough usable raw Wazuh data and at least benign plus one attack class.

### Optional Investigation Agent

1. Authenticated caller invokes `POST /api/alerts/{alert_id}/investigation-plan`.
2. Backend loads the alert.
3. Backend sends reduced alert metadata to `AGENT_SERVICE_URL`.
4. Backend records request/response audit events when configured.
5. Agent response is returned as an investigation plan.

The agent is advisory and cannot modify backend state through this integration.

## 6. API Surface

Health:

- `GET /api/health/`

Auth:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/2fa/setup`
- `POST /api/auth/2fa/verify`
- `POST /api/auth/2fa/disable`
- `GET /api/auth/verify-email`
- `POST /api/auth/password/forgot`
- `POST /api/auth/password/verify`
- `POST /api/auth/password/reset`
- `GET /api/auth/me`
- `PATCH /api/auth/me/notification-preferences`

Raw Wazuh:

- `POST /api/raw_wazuh_logs`

Logs:

- `GET /api/logs/`
- `GET /api/logs/count`
- `GET /api/logs/{log_id}`
- `POST /api/logs/`
- `POST /api/logs/wazuh` legacy compatibility

Alerts:

- `GET /api/alerts/`
- `GET /api/alerts/analytics`
- `GET /api/alerts/{alert_id}`
- `POST /api/alerts/{alert_id}/investigation-plan`
- `POST /api/alerts/{alert_id}/confirm-known`
- `POST /api/alerts/{alert_id}/mark-false-positive`

Users:

- `GET /api/users`
- `GET /api/users/{user_id}`

ML:

- `POST /api/ml/batch-infer`
- `POST /api/ml/models/retrain`
- `GET /api/ml/models/retrain-jobs`
- `GET /api/ml/models/retrain-jobs/{job_id}`
- `GET /api/ml/models/versions`
- `POST /api/ml/models/rollback`
- `GET /api/ml/suppressions`
- `POST /api/ml/suppressions/{fingerprint}/deactivate`
- `POST /api/ml/suppressions/{fingerprint}/activate`

WebSocket:

- `GET /api/ws/alerts`

## 7. Query Behavior

Log listing supports:

- `limit`
- `offset`
- `source`
- `severity`
- `agent`
- `origin`
- `source_app`
- `channel`
- `start_ts`
- `end_ts`

Alert listing supports:

- `limit`
- `offset`
- `severity`
- `alert_type`
- `start_ts`
- `end_ts`

Alert analytics returns:

- severity counts,
- trend buckets,
- classification/type distribution,
- total alerts,
- first and last alert timestamps.

## 8. Machine Learning Contract

Backend feature schema:

- Current primary schema: `wazuh_native_v1`
- Current feature count: 40
- Extractor: `app/ml/features/wazuh_feature_extractor.py`

Backend cloud-model expectations:

- `MODEL_API_URL` is required.
- Backend validates cloud-model reachability during startup.
- Backend warns when cloud-model expected feature count differs from backend feature count.
- Backend sends one prediction request per feature row.

Cloud-model prediction labels:

- `BENIGN`
- `ANOMALY`
- `UNKNOWN_ATTACK` treated as anomaly compatibility
- `KNOWN_ATTACK_<label>`

Backend mapping:

- `BENIGN` -> no alert.
- `ANOMALY` -> anomaly alert.
- `KNOWN_ATTACK_<label>` -> known attack alert with classification.
- Unknown labels are treated as anomaly.

Severity mapping uses prediction confidence/score:

- `>= 0.85` -> `high`
- `>= 0.70` -> `medium`
- otherwise -> `low`

Cloud-model persistence:

- The cloud-model can persist model versions in MongoDB when `MONGO_URI`/`MONGO_DB` are configured.
- It stores artifacts with GridFS-backed model version storage.
- It can restore the active model version on startup.
- It can fall back to bundled model files when no persisted active version exists.

## 9. Storage And Indexing

Indexes created on backend startup include:

`user`:

- unique `email`
- `email_verification_token_hash`
- `password_reset_code_hash`
- notification preference helper indexes

`logs`:

- descending `timestamp`
- `source`
- `severity`
- unique sparse `metadata.raw_ingest_key`
- `ml_status` plus timestamp

`alerts`:

- descending `created_at`
- `severity`
- `alert_type`
- `correlation_key`, `status`, `last_seen_at`
- `status`, `last_seen_at`
- `incident_id`
- `log_ids`

`raw_wazuh_logs`:

- descending `ingested_at`
- unique sparse `ingest_key`
- `processing.status`, `processing.next_retry_at`

Model Ops:

- `ml_promotions.fingerprint`
- `ml_suppressions.fingerprint`
- `ml_retrain_jobs.created_at`

## 10. Frontend Contract

Implemented frontend areas:

- `/login`
- `/register`
- `/forgot-password`
- `/verify-email`
- `/setup-2fa`
- `/dashboard`
- `/alerts`
- `/logs`
- `/precautions`
- `/feedback`
- `/architecture`
- `/settings`
- `/model-ops`

Backend-backed frontend behavior includes:

- auth,
- email verification,
- password reset,
- 2FA setup/disable,
- notification preference updates,
- logs listing/counts/filters,
- alert listing/detail/analytics,
- confirm-known and false-positive feedback,
- model version/retrain/rollback/suppression operations.

Known frontend limitations:

- Some dashboard visual data is still partially derived or mock-backed.
- Header notifications are not the same as the WebSocket alert stream.
- Frontend does not currently maintain a live `/api/ws/alerts` connection.

## 11. Security Model

Implemented controls:

- bcrypt password hashing through Passlib.
- JWT bearer authentication.
- Optional TOTP 2FA.
- Email verification before login.
- Password reset codes stored as hashes.
- Shared-secret Wazuh ingestion.
- Admin-only Model Ops and feedback routes.
- Configurable CORS allow-list.
- Optional read-only external agent boundary.

Operational requirements:

- Set strong `JWT_SECRET`, `MODEL_ADMIN_TOKEN`, and `WAZUH_INGEST_KEY`.
- Configure SMTP for customer deployments.
- Keep Atlas access restricted.
- Terminate TLS at the hosting platform or reverse proxy.
- Rotate any exposed secrets immediately.

Known security limitations:

- No general RBAC role matrix.
- No built-in rate limiting.
- No built-in secrets manager integration.
- No built-in application-layer IP allow-listing.

## 12. Deployment And Configuration

Canonical customer setup is `CUSTOMER_E2E_SETUP_GUIDE.md`.

Important backend env:

- `APP_ENV`
- `DEBUG_MODE`
- `DETAILED_LOGGING`
- `MONGO_URI`
- `MONGO_DB`
- `JWT_SECRET`
- `JWT_ALGORITHM`
- `JWT_EXP_MINUTES`
- `MODEL_API_URL`
- `MODEL_API_TIMEOUT_SECONDS`
- `MODEL_ADMIN_TOKEN`
- `ANOMALY_SCORE_THRESHOLD`
- `RAW_WAZUH_TRAINING_PATH`
- `RETRAIN_RAW_WAZUH_DB_LIMIT`
- `MIN_SAMPLES_PER_ATTACK_CLASS`
- `WAZUH_INGEST_KEY`
- `RAW_WAZUH_WORKER_CONCURRENCY`
- `AGENT_SERVICE_URL`
- `AGENT_TIMEOUT_SECONDS`
- `CORS_ALLOW_ORIGINS`
- `FRONTEND_BASE_URL`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_USE_TLS`
- `SMTP_USE_SSL`
- `EMAIL_FROM`
- `EMAIL_VERIFY_TTL_MINUTES`
- `PASSWORD_RESET_TTL_MINUTES`

Important cloud-model env:

- `MODEL_ADMIN_TOKEN`
- `MONGO_URI` when persisted model versions are desired
- `MONGO_DB` when persisted model versions are desired

Important frontend env:

- `REACT_APP_API_BASE_URL`

Important Wazuh forwarder env:

- `CS_BACKEND_URL`
- `WAZUH_INGEST_KEY`
- `WAZUH_ARCHIVES_PATH`
- `WAZUH_FORWARDER_OFFSET_PATH`
- `WAZUH_FORWARDER_POLL_SEC`

## 13. Automated Verification Coverage

Backend tests currently cover:

- health endpoint,
- Mongo configuration,
- auth notification preferences,
- log context and filtering,
- raw Wazuh pipeline preparation,
- Wazuh dataset builder,
- Wazuh feature extractor,
- ML batch inference flow,
- cloud-only ML behavior,
- model ops service behavior,
- alert analytics and correlation behavior,
- notification service and preference behavior.

Frontend tests currently cover:

- app/login rendering,
- dashboard behavior,
- logs page filters,
- model ops page behavior,
- settings page behavior,
- security view mappers,
- attack chart rendering.

Cloud-model tests cover:

- hybrid model version behavior.

## 14. Known Implementation Gaps

Current gaps that should remain visible:

1. Multi-user RBAC is not implemented.
2. Wazuh ML inference is currently scoped to `web-accesslog`.
3. Frontend does not consume backend WebSocket alerts.
4. Some frontend content remains mock/static.
5. Production operations need external TLS, secrets management, retention, backups, and monitoring.
6. Retraining depends on sufficient raw Wazuh data quality and volume.
7. The optional investigation agent service is external and may not be present in this workspace.

## 15. Documentation Source Of Truth

Current docs kept in the backend repo:

- `CUSTOMER_E2E_SETUP_GUIDE.md` for customer setup and Wazuh runbook.
- `cybersentinel_living_spec.md` for current implemented behavior.
- `README.md` for short backend orientation.
- `TODOS.md` for backlog notes.

When these files conflict:

1. Treat code and tests as implementation truth.
2. Update `cybersentinel_living_spec.md`.
3. Update `CUSTOMER_E2E_SETUP_GUIDE.md` if setup behavior changed.
4. Keep `README.md` brief and link to the canonical docs.
