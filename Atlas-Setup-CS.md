# CyberSentinel Shared Atlas Setup

Use this if you and your friend should always see the same live data.

## 1) Create Atlas resources (one time, owner account)

1. Create a MongoDB Atlas project and cluster.
2. Create a database user (username/password).
3. In Network Access, allow both of your IPs (or temporary `0.0.0.0/0` for testing only).
4. Copy the SRV connection string from Atlas.

## 2) Configure backend on both PCs

Edit `CyberSentinel-Backend/.env` on both machines:

```env
MONGO_URI=mongodb+srv://<DB_USER>:<DB_PASS>@<CLUSTER_URL>/?retryWrites=true&w=majority
MONGO_DB=cybersentinel
```

Keep other values per developer (JWT secret, SMTP, etc.) as needed.

## 3) Run backend locally (both PCs)

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 4) Run frontend locally (both PCs)

`CyberSentinel-Frontend/.env`:

```env
REACT_APP_API_BASE_URL=http://localhost:8000
```

Start:

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Frontend
npm install
npm start
```

## 5) Migrate current local DB to Atlas (optional, one time)

From your machine with current source Mongo data:

```powershell
mongodump --uri "<SOURCE_MONGO_URI>" --db cybersentinel --out .\dump
mongorestore --uri "mongodb+srv://<DB_USER>:<DB_PASS>@<CLUSTER_URL>/?retryWrites=true&w=majority" --nsInclude "cybersentinel.*" .\dump\cybersentinel
```

## 6) Basic DB queries (where to run)

You do not need to work only in Atlas web UI.
Keep running the app locally in terminal; Atlas is only the remote database.

Local terminal workflow:

```powershell
# Backend
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
.\.venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (new terminal)
cd E:\Programing\CyberSentinel\CyberSentinel-Frontend
npm start
```

Option A: Atlas UI
1. Atlas -> your cluster -> `Browse Collections`.
2. Open database `cybersentinel`.
3. Open collection (`logs`, `alerts`, `user`) and use `Filter` + `Sort`.

Option B: Terminal with `mongosh` (PowerShell/CMD)
1. Open terminal on your PC.
2. Connect:

```powershell
mongosh "mongodb+srv://<DB_USER>:<URL_ENCODED_DB_PASS>@<CLUSTER_URL>/cybersentinel?retryWrites=true&w=majority"
```

3. Run queries:

```javascript
use cybersentinel

db.user.countDocuments()
db.logs.countDocuments()
db.alerts.countDocuments()

db.logs.find().sort({ timestamp: -1 }).limit(5).pretty()
db.alerts.find().sort({ created_at: -1 }).limit(5).pretty()

db.user.find({}, { email: 1, email_verified: 1, is_2fa_enabled: 1 }).pretty()
```

4. Delete one user by email:

```javascript
db.user.deleteOne({ email: "admin@example.com" })
```

Option C: Local terminal without `mongosh` (Python one-liner)

```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
.\.venv\Scripts\python -c "from pymongo import MongoClient; from app.core.config import get_settings; s=get_settings(); db=MongoClient(s.mongo_uri)[s.mongo_db]; print('users=',db.user.count_documents({})); print('logs=',db.logs.count_documents({})); print('alerts=',db.alerts.count_documents({}))"
```
