# New Setup (Atlas Shared DB)

- Configure backend env in `CyberSentinel-Backend/.env`:
  - `MONGO_URI=mongodb+srv://<user>:<url_encoded_password>@<atlas-host>/?retryWrites=true&w=majority&appName=cybersentinel-dev`
  - `MONGO_DB=cybersentinel`
  - `JWT_SECRET=your_long_random_secret`

- Start backend:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- Ensure frontend env (`CyberSentinel-Frontend/.env`) is:
  - `REACT_APP_API_BASE_URL=http://localhost:8000`

- Start frontend:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Frontend
npm install
npm start
```

- Open:
  - Frontend: `http://localhost:3000`
  - Backend docs: `http://localhost:8000/docs`

- Verify shared Atlas data:
```powershell
cd E:\Programing\CyberSentinel\CyberSentinel-Backend
.\.venv\Scripts\python -c "from pymongo import MongoClient; from app.core.config import get_settings; s=get_settings(); db=MongoClient(s.mongo_uri)[s.mongo_db]; print('logs=',db.logs.count_documents({})); print('alerts=',db.alerts.count_documents({}))"
```
