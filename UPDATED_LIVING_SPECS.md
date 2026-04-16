# CyberSentinel Updated Living Specs
Last updated: 2026-04-10

This document is an operational snapshot that complements the canonical spec:
- `cybersentinel_living_spec.md` is the authoritative source of truth.
- This file records implementation deltas and runbook notes.

## 1. Snapshot of Current Implementation
Backend stack:
- FastAPI + MongoDB + classical ML inference service.
- JWT auth, email verification, optional TOTP 2FA.
- Password reset flow with 6-digit code verification.

Detection pipeline:
- Batch inference only (`POST /api/ml/batch-infer`).
- Isolation Forest + Random Forest hybrid decision logic.
- Alert generation is immutable and broadcast over WebSocket (`/api/ws/alerts`).

Ingestion:
- Human/API ingestion path: `POST /api/logs/` (JWT).
- Machine/Wazuh ingestion path: `POST /api/logs/wazuh` (`X-WAZUH-KEY`).

Agent integration:
- Investigation planning is optional and external (`AGENT_SERVICE_URL`).
- Backend records request/response audit events in `agent_audit` collection.

Frontend state:
- Auth, logs, alerts, dashboard, and settings pages are wired to backend REST APIs.
- Dashboard chart series and notification dropdown remain static mock data.
- Frontend currently does not consume the WebSocket alert stream.

## 2. Model and Artifact Contract
Expected model registry layout:
- `app/ml/models/registry.json`
- `app/ml/models/versions/<version>/isolation_forest.joblib`
- `app/ml/models/versions/<version>/random_forest.joblib`
- `app/ml/models/versions/<version>/metadata.json`

Model/runtime safeguards:
- Optional SHA-256 integrity checks at load time.
- Feature-count compatibility checks across models and inference input.
- scikit-learn version mismatch warning from model metadata.

## 3. Key Changes Since v1.0 Spec
- Added Wazuh machine-ingestion route with shared key validation.
- Added email verification and password reset lifecycle.
- Added model feature-shape validation in inference engine.
- Added bootstrap utility for importing pretrained model artifacts.
- Added Wazuh sender utility and setup documentation.

## 4. Operational Risks to Track
- Rotate secrets immediately if exposed in logs or chats (`JWT_SECRET`, DB credentials, `WAZUH_INGEST_KEY`, SMTP credentials).
- Restrict inbound network access to backend ports by trusted sources only.
- Keep training and inference dependency versions aligned (especially scikit-learn).
- Add TLS reverse proxy before internet exposure.

## 5. Minimal Verification Runbook
Health check:
```bash
curl http://127.0.0.1:8000/api/health/
```

Batch inference smoke check (requires token):
```bash
curl -X POST http://127.0.0.1:8000/api/ml/batch-infer \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"batch_size":100}'
```

Wazuh ingestion smoke check:
```bash
curl -X POST http://127.0.0.1:8000/api/logs/wazuh \
  -H "X-WAZUH-KEY: <ingest-key>" \
  -H "Content-Type: application/json" \
  -d '{"rule":{"level":10,"description":"Test Wazuh alert"},"agent":{"name":"wazuh-manager"}}'
```

## 6. Source of Truth Policy
When this file conflicts with `cybersentinel_living_spec.md`, treat the canonical spec as correct and update this file in the same change.
