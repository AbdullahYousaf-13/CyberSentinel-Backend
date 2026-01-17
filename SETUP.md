# Setup Guide

Follow each step in order.

## 1) Prerequisites
1. Install Docker Desktop.
2. Install Git.
3. Install Python 3.9+ if you want to run locally without Docker.

## 2) Clone the repositories
1. Clone this repo.
2. Clone the sibling agent repo into the same parent folder as this repo:
   - `CyberSentinel-Backend`
   - `CyberSentinel-Agentic-AI`

## 3) Start infrastructure with Docker
1. From the backend repo root, run:
   - `docker compose up --build`
2. Wait until MongoDB and Kafka show healthy logs.

## 4) Initialize the first admin user
1. Open a new terminal.
2. Register the first admin:
   ```bash
   curl -X POST http://localhost:8000/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@example.com","password":"ChangeMe123!"}'
   ```
3. Log in:
   ```bash
   curl -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@example.com","password":"ChangeMe123!"}'
   ```
4. Store the `access_token` from the response for later calls.

## 5) (Optional) Enable TOTP 2FA
1. Call setup:
   ```bash
   curl -X POST http://localhost:8000/api/auth/2fa/setup \
     -H "Authorization: Bearer <TOKEN>"
   ```
2. Scan the provisioning URI in your authenticator app.
3. Verify:
   ```bash
   curl -X POST http://localhost:8000/api/auth/2fa/verify \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"totp_code":"123456"}'
   ```

## 6) Create an initial model version
1. Use the retrain endpoint with sample data:
   ```bash
   curl -X POST http://localhost:8000/api/ml/retrain \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"reason":"initial bootstrap","features":[[0.1,1,0.5,0.2,0.1],[0.9,2,0.8,0.7,0.3]],"labels":[0,1]}'
   ```
2. Confirm the response includes a version.

## 7) Ingest logs
1. Ingest a log via REST:
   ```bash
   curl -X POST http://localhost:8000/api/logs/ \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"timestamp":"2025-01-17T12:00:00Z","source":"endpoint","message":"failed login","metadata":{"ip":"10.0.0.1"},"severity":"medium"}'
   ```

## 8) Run batch inference
1. Trigger batch inference:
   ```bash
   curl -X POST http://localhost:8000/api/ml/batch-infer \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"batch_size":100}'
   ```

## 9) View alerts
1. List alerts:
   ```bash
   curl -X GET http://localhost:8000/api/alerts/ \
     -H "Authorization: Bearer <TOKEN>"
   ```

## 10) Run locally without Docker (optional)
1. Create a virtual environment and install deps:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Set environment variables (PowerShell example):
   ```powershell
   $env:MONGO_URI='mongodb://localhost:27017'
   $env:MONGO_DB='cybersentinel'
   $env:JWT_SECRET='change_me'
   $env:KAFKA_ENABLED='false'
   ```
3. Start the API:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## 11) WebSocket alerts
1. Connect to `ws://localhost:8000/api/ws/alerts` for alert notifications.
