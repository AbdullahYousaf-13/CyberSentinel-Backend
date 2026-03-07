# Setup Guide (Atlas-First)

Follow these steps to run CyberSentinel with a shared MongoDB Atlas database.

## 1) Prerequisites

1. Python 3.11
2. Node.js + npm
3. MongoDB Atlas cluster + DB user + IP allowlist configured

## 2) Backend environment

From backend root:

```powershell
copy .env.sample .env
```

Set these in `.env`:

```env
MONGO_URI=mongodb+srv://<DB_USER>:<URL_ENCODED_PASSWORD>@<ATLAS_HOST>/?retryWrites=true&w=majority&appName=cybersentinel-dev
MONGO_DB=cybersentinel
JWT_SECRET=<LONG_RANDOM_SECRET>
KAFKA_ENABLED=false
```

## 3) Run backend locally

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend URL: `http://localhost:8000`

## 4) Run frontend locally

In `CyberSentinel-Frontend/.env`:

```env
REACT_APP_API_BASE_URL=http://localhost:8000
```

Start frontend:

```powershell
cd ..\CyberSentinel-Frontend
npm install
npm start
```

Frontend URL: `http://localhost:3000`

## 5) Verify shared database (both devices)

Run on each device:

```powershell
.\.venv\Scripts\python -c "from pymongo import MongoClient; from app.core.config import get_settings; s=get_settings(); db=MongoClient(s.mongo_uri)[s.mongo_db]; print('logs=',db.logs.count_documents({})); print('alerts=',db.alerts.count_documents({}))"
```

If both outputs match, both devices are connected to the same Atlas database.

## 6) Optional: seed development data

```powershell
python scripts/dev_seed.py --email admin@example.com --password ChangeMe123! --alerts 12 --token-days 60
```

---

CS Creds:
Email: abdullahyousaf132@gmail.com
Password: abd@1234

Atlas:
Usar Name: abdullahyousaf132
Password: abd@1234

---