# CyberSentinel Living Specification

Status: Active  
Document type: Living specification for the current implemented system  
Last updated: 2026-04-16  
Primary source repos in this workspace:

- `CyberSentinel-Backend`
- `CyberSentinel-Frontend`
- `CyberSentinel-AI`

## 1. Product Summary

CyberSentinel is a security monitoring platform built around classical machine learning, a FastAPI backend, a React frontend, and an optional external investigation-planning agent.

The current product does four core things:

1. Ingests security-relevant logs through authenticated API calls or a shared-secret Wazuh ingestion endpoint.
2. Stores logs in MongoDB and runs batch inference over them using Isolation Forest and Random Forest models.
3. Creates immutable alerts for suspicious results and exposes them over REST and WebSocket.
4. Lets a human analyst review alerts in a frontend dashboard and optionally request an investigation plan from an external read-only agent service.

The system is intentionally human-in-the-loop. Detection is automated. Investigation help is optional. Remediation is not automated.

## 2. Scope and Non-Goals

### In scope today

- Single-instance backend API with FastAPI
- MongoDB-backed storage for users, logs, alerts, and agent audit events
- Email/password authentication with JWT sessions
- Email verification
- Password reset by emailed 6-digit code
- Optional TOTP-based 2FA
- Log ingestion by authenticated user API
- Machine-to-machine Wazuh ingestion by shared secret
- Batch-only ML inference
- Manual model retraining and rollback
- Optional external model API integration
- Immutable alert creation
- WebSocket broadcast when alerts are created
- React frontend for auth, logs, alerts, dashboard, and settings
- Optional external investigation planning agent integration

### Explicitly out of scope today

- Automatic response or remediation
- Multi-tenant account model
- Role-based access control
- Streaming or per-event inference
- Alert acknowledgement workflow
- Alert deduplication or correlation
- Drift detection and model performance monitoring
- Dataset labeling and retraining workflow UI
- Frontend consumption of live WebSocket alerts

## 3. Repository and Runtime Topology

### `CyberSentinel-Backend`

Authoritative runtime backend. Hosts REST APIs, WebSocket endpoint, MongoDB integration, auth flows, batch inference, model registry loading, and optional agent calls.

### `CyberSentinel-Frontend`

React frontend. Provides login, registration, email verification, password reset, dashboard, alerts, logs, precautions, architecture placeholder, feedback placeholder, and settings pages.

### `CyberSentinel-AI`

Auxiliary ML repo. Contains notebooks, trained model artifacts, and a minimal FastAPI model API that can be called by the backend when `MODEL_API_URL` is configured.

### `CyberSentinel-Agentic-AI`

Expected external agent service repo, but in this workspace the directory is only a placeholder Git repo with no checked-out implementation files. The backend still supports an external agent service through `AGENT_SERVICE_URL`.

## 4. High-Level Architecture

```text
                +----------------------+
                |  React Frontend      |
                |  CyberSentinel-      |
                |  Frontend            |
                +----------+-----------+
                           |
                           | REST + JWT
                           | WebSocket /api/ws/alerts
                           v
+-------------+   +----------------------+   +----------------------+
| Log Senders  |-->| FastAPI Backend      |-->| MongoDB              |
| API clients  |   | CyberSentinel-       |   | users, logs, alerts, |
| Wazuh        |   | Backend              |   | agent_audit          |
+-------------+   +----------+-----------+   +----------------------+
                           |
                           | batch inference
                           v
                +----------------------+
                | ML runtime           |
                | local registry or    |
                | external model API   |
                +----------------------+
                           |
                           | optional HTTP /plan
                           v
                +----------------------+
                | External investigation|
                | agent service         |
                +----------------------+
```

## 5. Core Domain Model

### User

Stored in MongoDB collection `user`.

Implemented fields include:

- `email`
- `password_hash`
- `is_2fa_enabled`
- `totp_secret`
- `email_verified`
- `email_verification_token_hash`
- `email_verification_expires_at`
- `password_reset_code_hash`
- `password_reset_expires_at`
- `first_name`
- `last_name`
- `created_at`

Constraints:

- Only the first registration succeeds.
- After the first user exists, later registration attempts return conflict.
- In practice, CyberSentinel is currently a single-admin system.

### Log

Stored in MongoDB collection `logs`.

Implemented fields include:

- `timestamp`
- `source`
- `message`
- `metadata`
- `severity`
- `ingested_at`

Current implementation note:

- `source` is normalized by ingestion path, not preserved from caller input.
- Logs created by `POST /api/logs/` are stored with `source="api"`.
- Logs created by `POST /api/logs/wazuh` are stored with `source="wazuh"`.
- For Wazuh logs, the original Wazuh payload is preserved under `metadata`.
- For manual API ingestion, the caller-provided `source` is required by the request schema but is not persisted as the stored top-level `source`.

### Alert

Stored in MongoDB collection `alerts`.

Implemented fields include:

- `created_at`
- `log_id`
- `alert_type`
- `severity`
- `classification`
- `anomaly_score`
- `model_version`
- `metadata`

Important properties:

- Alerts are append-only in current implementation.
- There is no alert update, acknowledgement, or delete API.
- Alert metadata is intentionally small and currently stores only selected log context, not full raw logs.

### Agent Audit Event

Stored in MongoDB collection `agent_audit`.

Implemented fields include:

- `event`
- `payload`
- `alert_id` when available
- `timestamp`

## 6. Primary Flows

### 6.1 Registration and login

1. User registers through `POST /api/auth/register`.
2. Backend creates the first and only user, hashes the password, generates an email verification token, and sends verification email content.
3. User must verify email through `GET /api/auth/verify-email?token=...`.
4. User logs in through `POST /api/auth/login`.
5. If 2FA is enabled, login also requires a valid TOTP code.
6. Backend returns a JWT bearer token.

Behavioral notes:

- If SMTP is not configured, email contents are logged rather than sent.
- Frontend optionally stores `pending2fa` in local storage after registration, but that flag is frontend-only and not a backend user state.

### 6.2 2FA lifecycle

1. Authenticated user requests setup through `POST /api/auth/2fa/setup`.
2. Backend generates a TOTP secret and provisioning URI.
3. User confirms setup through `POST /api/auth/2fa/verify`.
4. User can disable 2FA through `POST /api/auth/2fa/disable` with a current code.

### 6.3 Password reset

1. User requests password reset through `POST /api/auth/password/forgot`.
2. Backend generates a 6-digit code, stores only its hash and expiry, and sends the code by email.
3. User verifies the code through `POST /api/auth/password/verify`.
4. User resets password through `POST /api/auth/password/reset`.

### 6.4 Log ingestion

Two ingestion paths exist:

1. Human or application ingestion: `POST /api/logs/`
2. Wazuh ingestion: `POST /api/logs/wazuh`

Wazuh normalization rules:

- Auth uses `X-WAZUH-KEY`.
- Severity is derived from Wazuh rule level:
  - `>= 12` -> `high`
  - `>= 7` and `< 12` -> `medium`
  - otherwise -> `low`
- Message is derived from `rule.description`, then `full_log`, then decoder name fallback.

### 6.5 Batch inference and alert generation

1. Authenticated caller invokes `POST /api/ml/batch-infer`.
2. Backend fetches a batch of logs ordered by oldest `timestamp` first.
3. Feature extractor converts logs into a fixed 78-feature numeric matrix.
4. Backend uses either:
  - locally loaded model registry artifacts, or
  - an external model API if `MODEL_API_URL` is set.
5. For each non-benign result, backend creates an alert and broadcasts an `alert_created` WebSocket event.

Current implementation caveat:

- There is no processed marker on logs.
- Re-running batch inference over the same dataset can produce duplicate alerts for the same log records.

### 6.6 Investigation planning

1. Authenticated caller invokes `POST /api/alerts/{alert_id}/investigation-plan`.
2. Backend loads the alert and sends a reduced payload to the external agent service.
3. Backend records request and response audit events in `agent_audit`.
4. Backend returns a structured plan to the frontend caller.

Agent payload sent by backend:

- `alert_id`
- `alert_type`
- `severity`
- `classification`
- `metadata`

Expected agent response shape:

- `alert_id`
- `steps[]`
- each step contains `title`, `description`, `priority`

## 7. API Surface

### Health

- `GET /api/health/`

### Auth

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

### Logs

- `GET /api/logs`
- `GET /api/logs/count`
- `GET /api/logs/{log_id}`
- `POST /api/logs/`
- `POST /api/logs/wazuh`

### Alerts

- `GET /api/alerts`
- `GET /api/alerts/{alert_id}`
- `POST /api/alerts/{alert_id}/investigation-plan`

### Users

- `GET /api/users`
- `GET /api/users/{user_id}`

### ML

- `POST /api/ml/batch-infer`
- `POST /api/ml/retrain`
- `POST /api/ml/rollback`

### WebSocket

- `GET /api/ws/alerts` as a WebSocket endpoint

## 8. Query and Response Behavior

### Log listing filters

`GET /api/logs` and `GET /api/logs/count` support:

- `source`
- `severity`
- `start_ts`
- `end_ts`

Current source filter behavior:

- Source filtering is a case-insensitive prefix match against stored `logs.source`.
- Because stored `logs.source` is normalized to `api` or `wazuh`, filtering by original source system name does not currently work as a top-level query.

### Alert listing filters

`GET /api/alerts` supports:

- `severity`
- `alert_type`
- `start_ts`
- `end_ts`

## 9. Machine Learning Specification

### 9.1 Feature extraction

The backend feature extractor is the operational contract for inference and expects a 78-feature vector aligned to CICIDS2017-style fields.

Properties:

- Fixed output shape: 78 features
- Alias-aware key normalization
- Missing or non-numeric values default to `0.0`
- String severities map to numeric values:
  - `low` -> `0.2`
  - `medium` -> `0.5`
  - `high` -> `0.8`
  - `critical` -> `1.0`

### 9.2 Local model registry

Expected layout:

```text
app/ml/models/
  registry.json
  versions/
    <version>/
      isolation_forest.joblib
      random_forest.joblib
      metadata.json
```

Runtime safeguards:

- Optional SHA-256 artifact verification
- Runtime warning if model metadata scikit-learn version differs from current runtime
- Validation that both models expect the same feature count
- Validation that inference input matches expected feature count

### 9.3 Local inference decision logic

Current backend logic is:

1. Compute Isolation Forest anomaly scores as negative `score_samples`.
2. Compute Random Forest class probabilities and predictions.
3. If Random Forest max class probability is `>= 0.7`, classify as `known_attack`.
4. Else if anomaly score is `>= ANOMALY_SCORE_THRESHOLD`, classify as `anomaly`.
5. Else classify as `benign`.

Alert severity mapping after inference:

- `known_attack` -> `high`
- `anomaly` -> `medium`
- `benign` -> no alert

### 9.4 External model API mode

If `MODEL_API_URL` is configured, backend calls `POST <MODEL_API_URL>/predict` per feature row.

Current invocation pattern:

- One HTTP request is made per feature row.
- The backend does not currently batch multiple feature rows into one external model request.

Expected cloud-model response semantics:

- `BENIGN`
- `UNKNOWN_ATTACK`
- `KNOWN_ATTACK_<label>`

### 9.5 Retraining and rollback

Retraining is manual and API-triggered.

`POST /api/ml/retrain` requires:

- `reason`
- full `features`
- full `labels`

Current backend training behavior:

- Isolation Forest is trained on the full provided feature matrix.
- Random Forest is trained on the provided feature matrix and labels.
- New model version is saved and immediately activated.

Rollback behavior:

- `POST /api/ml/rollback` switches the active version if the target version directory exists.

## 10. Investigation Agent Boundary

The investigation agent is optional and external.

Hard boundaries enforced by current architecture:

- Backend only sends reduced alert payloads.
- Agent access is over HTTP only.
- Agent does not receive direct MongoDB access.
- Agent does not receive backend credentials.
- Agent does not modify logs, alerts, models, or users.
- Backend records audit events for agent requests and responses.

This makes the agent advisory, not authoritative.

## 11. Frontend Specification

### Implemented routes

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

### Implemented behavior

- Login, registration, email verification, password reset, and 2FA flows are wired to backend APIs.
- Dashboard loads alerts and logs over REST and derives summary counts client-side.
- Alerts page supports REST-backed severity and alert-type filtering plus client-side search and CSV export.
- Logs page supports REST-backed filtering by source, severity, and time range plus responsive pagination.
- Settings page persists 2FA changes through backend APIs.

### Current frontend limitations

- Dashboard charts use static mock data from `src/data/mockData.js`.
- Header notifications are mock data.
- Frontend does not currently connect to `/api/ws/alerts`.
- Email notification, frequency, and severity preference settings are local UI state only and are not persisted to backend storage.
- `Architecture` page is placeholder text.
- `Feedback` page is placeholder text.
- `Precautions` page is static guidance content, not dynamic system output.

## 12. Security Model

Implemented security controls:

- Password hashing with bcrypt via Passlib
- JWT bearer auth
- Optional TOTP via `pyotp`
- Email verification before login
- Password reset codes stored as hashes, not plaintext
- Shared-secret Wazuh ingestion
- Configurable CORS origins
- Optional model artifact integrity verification
- Read-only style isolation for external agent integration

Security limits and required operational hardening:

- No built-in RBAC
- No built-in TLS termination
- No built-in secrets manager integration
- No inbound network restriction at application layer
- No rate limiting
- No log-level data redaction framework beyond operator discipline

## 13. Storage and Indexing

Indexes created on startup:

### `user`

- unique `email`
- `email_verification_token_hash`
- `password_reset_code_hash`

### `logs`

- descending `timestamp`
- `source`
- `severity`

### `alerts`

- descending `created_at`
- `severity`
- `alert_type`
- `log_id`

There is currently no explicit index creation for `agent_audit`.

## 14. Deployment and Configuration

### Backend deployment

Implemented deployment assets:

- `SETUP.md`
- `.env`

Current runtime scope:

- Backend process only
- MongoDB is expected to be external
- Frontend is expected to be run separately

### Core environment variables

Application:

- `APP_ENV`
- `DEBUG_MODE`
- `DETAILED_LOGGING`

Database:

- `MONGO_URI`
- `MONGO_DB`

Auth:

- `JWT_SECRET`
- `JWT_ALGORITHM`
- `JWT_EXP_MINUTES`

Wazuh:

- `WAZUH_INGEST_KEY`

Models:

- `MODEL_DIR`
- `MODEL_INTEGRITY_REQUIRED`
- `ANOMALY_SCORE_THRESHOLD`
- `MODEL_API_URL`
- `MODEL_API_TIMEOUT_SECONDS`

Agent:

- `AGENT_SERVICE_URL`
- `AGENT_TIMEOUT_SECONDS`

Frontend/email:

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

## 15. Automated Verification Coverage

Current backend automated tests cover:

- health endpoint
- feature extractor output shape and alias handling

Current gaps:

- auth flow tests
- ingestion tests
- alert creation tests
- ML inference integration tests
- model registry tests
- agent integration tests
- frontend tests for real backend interactions

## 16. Known Implementation Gaps and Honest Notes

These items are part of the current truth and should not be hidden by the spec:

1. Alert generation can duplicate results because logs are re-read without a processed state.
2. Stored log `source` currently reflects ingestion channel (`api` or `wazuh`) rather than original source identifier.
3. `POST /api/logs/` echoes caller payload in the response, which can differ from the stored document's `source`.
4. Frontend dashboards are partially real and partially mocked.
5. Frontend does not yet use the backend WebSocket stream even though the backend emits it.
6. Agent integration contract exists, but the agent implementation itself is not present in this workspace.
7. Retraining requires caller-supplied feature arrays and labels over API; there is no managed dataset pipeline in the backend.

## 17. Change Policy

This document should be updated whenever any of the following changes:

- API routes or request/response contracts
- Auth lifecycle or security requirements
- Data storage model or indexing strategy
- Feature extraction logic
- Inference decision logic
- Model registry layout
- Agent request/response contract
- Frontend pages that move from mocked to real backend-backed behavior
- Deployment model or required environment variables

This document does not need to change for purely internal refactors that preserve behavior.

## 18. Canonical Source Rule

When other docs conflict with this file, this file should be treated as the authoritative living spec and the other docs should be reconciled.

At the time of this update, older docs in the repo include stale assumptions that this file corrects, including:

- the older backend living spec
- deployment notes that reference an outdated feature-count assumption
- UI pages that imply live features which are still mocked
