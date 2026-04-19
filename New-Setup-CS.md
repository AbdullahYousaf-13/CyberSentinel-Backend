# New Setup (Cloud-Only Model + Atlas DB)

## Cloud-Only Quickstart (Per Developer Machine)

Standard local ports:
- Frontend: `3000`
- Backend: `8000`
- Cloud model API: `8010`

1) You share these two files manually with your friend:
- `isolation_forest.pkl`
- `random_forest.pkl`

2) Friend places model files in:
- `CyberSentinel-Cloud-Model/models/isolation_forest.pkl`
- `CyberSentinel-Cloud-Model/models/random_forest.pkl`

3) Start cloud model API:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Cloud-Model
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload --host 0.0.0.0 --port 8010
```

4) Configure backend env in `CyberSentinel-Backend/.env`:
- `MONGO_URI=mongodb+srv://<user>:<url_encoded_password>@<atlas-host>/?retryWrites=true&w=majority&appName=cybersentinel-dev`
- `MONGO_DB=cybersentinel`
- `JWT_SECRET=your_long_random_secret`
- `MODEL_API_URL=http://127.0.0.1:8010`

5) Start backend:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

6) Ensure frontend env (`CyberSentinel-Frontend/.env`) is:
- `REACT_APP_API_BASE_URL=http://127.0.0.1:8000`

7) Start frontend:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Frontend
npm install
npm start
```

8) Open:
- Frontend: `http://localhost:3000`
- Backend docs: `http://localhost:8000/docs`
- Cloud model health: `http://127.0.0.1:8010/health`

9) Verify shared Atlas data:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
.\.venv\Scripts\python -c "from pymongo import MongoClient; from app.core.config import get_settings; from app.db.mongo import resolve_mongo_uri; s=get_settings(); db=MongoClient(resolve_mongo_uri(s))[s.mongo_db]; print('logs=',db.logs.count_documents({})); print('alerts=',db.alerts.count_documents({}))"
```

## Notes

- Backend is cloud-model-only: local backend model registry/retrain/rollback are disabled.
- Wazuh is optional and separate; turn it on only when you need log ingestion from VM.

## Wazuh VM Status

- VM name: `Wazuh-Server`
- Ubuntu username: `dark-knight`
- Current VM IP: `192.168.137.96`
- Dashboard URL: `https://192.168.137.96`
- Dashboard username: `admin`
- Dashboard password: `Dk.13022`

## Wazuh Current State

- Wazuh all-in-one stack installed successfully on Ubuntu 24.04.4
- Windows agent enrolled successfully
- Agent name: `PC`
- Agent status: `Active`
- Agent OS: `Microsoft Windows 11 Pro`

## Wazuh Resume Notes

- SSH from Windows:
```powershell
ssh dark-knight@192.168.137.96
```

- If the VM IP changes after reboot, check it in the VM with:
```bash
hostname -I
```

- Safe shutdown:
```bash
sudo shutdown -h now
```

- Recommended: take a VirtualBox snapshot after major working milestones
