# CyberSentinel Updated Living Specs

Last updated: 2026-03-08

## 1. Objective

Deploy CyberSentinel backend and hybrid ML inference in cloud, and ingest Wazuh alerts directly into backend for downstream detection and alerting.

## 2. Current Cloud State

### 2.1 Backend VM (Oracle Cloud)

- Instance name: `cybersentinel-backend`
- Region: `India South (Hyderabad)`
- Public IP: `129.159.230.230`
- OS: Ubuntu 22.04
- Runtime: Docker

### 2.2 Backend Service

- Container name: `cs-backend`
- Image: `cybersentinel-backend:prod`
- Exposed port: `8000`
- Health endpoint: `GET /api/health/` -> `ok`

### 2.3 Model Runtime

- Model directory mounted into container:
  - host: `~/apps/CyberSentinel-Backend/app/ml/models`
  - container: `/app/app/ml/models` (read-only)
- Loaded model version: `20260307123306`
- Hybrid inference engine active (Isolation Forest + Random Forest)

### 2.4 Wazuh Ingestion

- Endpoint: `POST /api/logs/wazuh`
- Auth header: `X-WAZUH-KEY`
- Verified cloud ingest success (sample inserted):
  - id: `69ad7b4f2ea1a0197f4cacfd`

## 3. Implemented Backend Changes

### 3.1 New config

- Added env setting:
  - `WAZUH_INGEST_KEY`

### 3.2 New route

- Added machine-ingest endpoint in logs routes:
  - `POST /api/logs/wazuh`
- Behavior:
  - validates `X-WAZUH-KEY`
  - normalizes Wazuh payload
  - maps `rule.level` to severity (`low|medium|high`)
  - stores full payload in `metadata`

### 3.3 Model safety and tooling

- Added model feature-shape validation in inference engine
- Added bootstrap script to import model artifacts into backend registry format
- Added Wazuh sender helper script
- Added Wazuh setup guide

## 4. Data/ML Contract (Current)

### 4.1 Feature extraction

- Backend feature extractor emits 78 CICIDS-style features in fixed order

### 4.2 Model artifacts expected

- `app/ml/models/registry.json`
- `app/ml/models/versions/<version>/isolation_forest.joblib`
- `app/ml/models/versions/<version>/random_forest.joblib`
- `app/ml/models/versions/<version>/metadata.json`

## 5. Open Issues / Risks

1. Secret exposure occurred during setup logs/chat.
   - Must rotate:
   - MongoDB credentials
   - `JWT_SECRET`
   - `WAZUH_INGEST_KEY`
   - SMTP app password
   - issued access tokens
2. NSG currently may allow broad source access to port `8000`.
   - Restrict to trusted source IPs only.
3. scikit-learn version warning seen while loading old artifacts.
   - Keep training/inference sklearn versions aligned.

## 6. Required Next Steps

1. Rotate all exposed secrets and update `.env`.
2. Restart backend container:
   - `docker restart cs-backend`
3. Re-test:
   - `GET /api/health/`
   - `POST /api/logs/wazuh` with new key
4. Provision separate Wazuh VM and wire forwarding to backend endpoint.
5. Add HTTPS reverse proxy (Nginx + certbot) for backend.

## 7. Quick Operations

### 7.1 Check backend container

```bash
docker ps --filter name=cs-backend
docker logs --tail 120 cs-backend
```

### 7.2 Restart backend

```bash
docker restart cs-backend
```

### 7.3 Verify health

```bash
curl http://127.0.0.1:8000/api/health/
```

### 7.4 Verify public health

```powershell
Invoke-RestMethod -Method Get -Uri "http://129.159.230.230:8000/api/health/"
```
