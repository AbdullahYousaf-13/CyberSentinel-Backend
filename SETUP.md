# CyberSentinel Setup (Cloud-Only Models)

This setup is for clone-and-run development where each developer runs all services locally on their own machine.

## 1) Required Local Services and Ports

1. Cloud model API: `http://127.0.0.1:8010`
2. Backend API: `http://127.0.0.1:8000`
3. Frontend app: `http://127.0.0.1:3000`

## 2) Prepare Cloud Model Files

Model files are shared manually by project owner. Place these files on every developer machine:

1. `CyberSentinel-Cloud-Model/models/isolation_forest.pkl`
2. `CyberSentinel-Cloud-Model/models/random_forest.pkl`

## 3) Start Cloud Model API

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Cloud-Model
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --host 0.0.0.0 --port 8010
```

Verify:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8010/health
```

## 4) Configure and Start Backend

Copy env file:

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
copy .env.sample .env
```

Set at least:

```env
APP_ENV=dev
DEBUG_MODE=true
MONGO_URI=mongodb+srv://<DB_USER>:<URL_ENCODED_PASSWORD>@<ATLAS_HOST>/?retryWrites=true&w=majority
MONGO_DB=cybersentinel
JWT_SECRET=<LONG_RANDOM_SECRET>
MODEL_API_URL=http://127.0.0.1:8010
MODEL_API_TIMEOUT_SECONDS=10
```

Start backend:

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Notes:

1. Backend fails startup if `MODEL_API_URL` is empty, invalid, or unreachable.
2. Local backend model registry is not used in cloud-only mode.
3. `/api/ml/retrain` and `/api/ml/rollback` return `501`.

## 5) Configure and Start Frontend

In `CyberSentinel-Frontend/.env` set:

```env
REACT_APP_API_BASE_URL=http://127.0.0.1:8000
```

Start:

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Frontend
npm install
npm start
```

## 6) Smoke Check

1. Open `http://localhost:3000`
2. Open `http://127.0.0.1:8000/docs`
3. Open `http://127.0.0.1:8010/health`
4. Login and call `POST /api/ml/batch-infer`

## 7) Wazuh Scope

Wazuh VM integration is optional and independent from default startup. Enable it only when you need real Wazuh log ingestion.
