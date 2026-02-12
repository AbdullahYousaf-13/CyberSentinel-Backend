# Setup Guide

Follow each step in order.

## 1) Prerequisites

1. Install Docker Desktop.
2. Install Git.
3. Install Python 3.11 if you want to run locally without Docker. If you have multiple Python versions, use the Python Launcher (`py`) to target 3.11 in the steps below.

## 2) Clone the repositories

1. Clone this repo.
2. Clone the sibling agent repo into the same parent folder as this repo:
  - `CyberSentinel-Backend`
  - `CyberSentinel-Agentic-AI`

## 2.1) Environment file

1. Copy the sample env:
  - `copy .env.sample .env` (Windows)
2. Update at least:
  - `JWT_SECRET` (use a long random string)
  - `MONGO_URI` (see local vs Docker steps below)

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
   py -3.11 -m venv .venv (or `python -m venv .venv`)
   .\.venv\Scripts\activate
   pip install -r requirements.txt
  ```
2. Start MongoDB (if you don't have it installed locally):
  ```powershell
   docker run --name cs-mongo -p 27017:27017 -d mongo:6
  ```
3. Use `.env` instead of setting env vars inline:
  - `MONGO_URI=mongodb://localhost:27017`
  - `MONGO_DB=cybersentinel`
  - `JWT_SECRET=<your_secret>`
  - `KAFKA_ENABLED=false`
4. Start the API:
  ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
  ```
5. First run note:
  - You will see "Model registry not initialized" until you call the retrain endpoint in step 6.

## 10.1) Seed dev admin + alerts (optional)

1. Ensure `.env` is set for local DB:
  - `MONGO_URI=mongodb://localhost:27017`
  - `MONGO_DB=cybersentinel`
  - `JWT_SECRET=<your_secret>`
2. With your virtual environment active, run:
  ```bash
   python scripts/dev_seed.py --email admin@example.com --password ChangeMe123! --alerts 12 --token-days 60
  ```
3. The script will:
  - Create or reuse the admin user by email.
  - Append sample alerts into the `alerts` collection.
  - Print a 60-day access token you can use for frontend requests.

## 11) WebSocket alerts

1. Connect to `ws://localhost:8000/api/ws/alerts` for alert notifications.

## 12) MongoDB quick check (optional)

1. Open a Mongo shell (Docker container):
  ```powershell
   docker exec -it cs-mongo mongosh
  ```
2. Basic commands:
  ```javascript
   show dbs // List all databases to verify Mongo is reachable.
   use cybersentinel // Switch to the app database.
   show collections // Show tables/collections in this database.
   db.users.find().pretty() // Inspect all users (admin registration check).
   db.alerts.find().pretty() // Inspect alert records.
   db.logs.find().pretty() // Inspect ingested log records.
   db.users.findOne() // Quick sanity check for a single user doc.
   db.alerts.countDocuments() // Count alerts to confirm inserts.
   db.logs.countDocuments() // Count logs to confirm ingestion.
   db.logs.find({ "metadata.ip": "10.0.0.1" }).pretty() // Filter by a field.
   db.logs.createIndex({ timestamp: -1 }) // Add index to speed recent-log queries.
   db.logs.deleteMany({ source: "test" }) // Clean up test data.
   db.stats() // Database size and storage stats.
  ```

.venv\Scripts\activate  
pip install -r requirements.txt  
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 

Creds:
Email:abdullahyousaf132@gmail.com
Password:abd@1234