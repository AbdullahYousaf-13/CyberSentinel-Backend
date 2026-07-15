# CyberSentinel Customer E2E Setup Guide

This guide is for setting up CyberSentinel for a small customer lab or first paid installation. It covers:

- CyberSentinel frontend
- CyberSentinel backend API
- CyberSentinel cloud-model API
- MongoDB Atlas
- SMTP email for account verification and password resets
- Wazuh all-in-one setup
- Wazuh Windows agent enrollment
- Wazuh raw archive forwarding into CyberSentinel
- Basic Model Ops validation

This guide intentionally uses placeholders. Do not paste real customer secrets, IP addresses, database passwords, SMTP passwords, or Wazuh credentials into customer-facing copies.

If any real secret was exposed during setup, rotate it before handing the system to a customer.

## 1. Deployment Model

Primary customer path:

1. Customer owns MongoDB Atlas and SMTP credentials.
2. Installer deploys CyberSentinel services using the private release bundle.
3. Render free tier is used as the default hosted deployment path.
4. A local Windows validation path is available before or after hosted deployment.
5. Wazuh runs on an Ubuntu machine or VM.
6. Customer Windows endpoints enroll into Wazuh.
7. A CyberSentinel forwarder runs on the Wazuh manager and streams raw `archives.json` events to the CyberSentinel backend.

Render free-tier limitation:

- Free services can sleep after idle time.
- The first request after sleep can be slow.
- Use free tier for demos, pilot installs, or budget-constrained customers.
- For production customers that require always-on behavior, move the same services to an always-on tier without changing the app env contracts.



## 2. Architecture

Runtime services:


| Service         | Default local URL           | Hosted URL placeholder      | Purpose                                                 |
| --------------- | --------------------------- | --------------------------- | ------------------------------------------------------- |
| Frontend        | `http://localhost:3000`     | `<FRONTEND_URL>`            | Browser UI                                              |
| Backend API     | `http://127.0.0.1:8000`     | `<BACKEND_URL>`             | Auth, logs, alerts, Wazuh ingestion, Model Ops          |
| Cloud-model API | `http://127.0.0.1:8010`     | `<MODEL_API_URL>`           | ML inference and model version actions                  |
| MongoDB Atlas   | n/a                         | `<MONGO_URI>`               | Users, logs, alerts, raw Wazuh logs, model ops metadata |
| Wazuh dashboard | `https://<WAZUH_SERVER_IP>` | `https://<WAZUH_SERVER_IP>` | Wazuh monitoring UI                                     |


Wazuh data flow:

```text
Windows endpoint
  -> Wazuh agent
  -> Wazuh manager
  -> /var/ossec/logs/archives/archives.json
  -> CyberSentinel forwarder
  -> POST <BACKEND_URL>/api/raw_wazuh_logs
  -> raw_wazuh_logs collection
  -> CyberSentinel async worker
  -> normalized logs
  -> cloud-model inference
  -> alerts
  -> frontend Logs and Alerts pages
```

The primary Wazuh path is raw archive forwarding to `POST /api/raw_wazuh_logs`. The older direct alert hook `POST /api/logs/wazuh` is not part of this customer setup path.

## 3. Required Customer Inputs

Collect these before deployment:


| Value                      | Example placeholder      | Notes                             |
| -------------------------- | ------------------------ | --------------------------------- |
| Customer name              | `<CUSTOMER_NAME>`        | Used for naming only              |
| Atlas URI                  | `<MONGO_URI>`            | Must include URL-encoded password |
| Atlas database             | `cybersentinel`          | Usually keep this default         |
| SMTP host                  | `<SMTP_HOST>`            | Example: `smtp.gmail.com`         |
| SMTP port                  | `587`                    | Use customer provider value       |
| SMTP username              | `<SMTP_USER>`            | Required for verification email   |
| SMTP password/app password | `<SMTP_PASSWORD>`        | Store only in secret env vars     |
| From email                 | `<EMAIL_FROM>`           | Example: `security@example.com`   |
| Frontend URL               | `<FRONTEND_URL>`         | Render static site URL            |
| Backend URL                | `<BACKEND_URL>`          | Render backend URL                |
| Cloud-model URL            | `<MODEL_API_URL>`        | Render cloud-model URL            |
| Wazuh server IP            | `<WAZUH_SERVER_IP>`      | Ubuntu Wazuh manager/dashboard IP |
| Wazuh admin password       | `<WAZUH_ADMIN_PASSWORD>` | Do not store in this guide        |


Generate strong shared secrets:

PowerShell:

```powershell
[Convert]::ToBase64String([byte[]](1..48 | ForEach-Object { Get-Random -Maximum 256 }))
```

Bash:

```bash
openssl rand -base64 48
```

Use separate generated values for:

- `JWT_SECRET`
- `MODEL_ADMIN_TOKEN`
- `WAZUH_INGEST_KEY`



## 4. Source Package Requirements

The private customer release bundle must include:

```text
CyberSentinel-Frontend/
CyberSentinel-Backend/
CyberSentinel-Cloud-Model/
render.yaml
```

The cloud-model service must include bundled model artifacts:

```text
CyberSentinel-Cloud-Model/models/random_forest.pkl
CyberSentinel-Cloud-Model/models/isolation_forest.pkl
```

Optional, if supplied by the release:

```text
CyberSentinel-Cloud-Model/models/label_map.json
```

The cloud-model API fails startup when the required `.pkl` files are missing and no persisted active model can be restored.

## 5. MongoDB Atlas Setup

1. Customer creates or provides a MongoDB Atlas project.
2. Create a cluster.
3. Create an application database user.
4. Add the backend and cloud-model deployment outbound IPs to the Atlas Network Access list.
5. For quick pilots only, customer may temporarily allow broad access. Replace this with explicit IP allow-listing before handoff.
6. Copy the SRV connection string.
7. URL-encode the database password before placing it in the URI.

Expected env values:

```env
MONGO_URI=mongodb+srv://<DB_USER>:<URL_ENCODED_DB_PASSWORD>@<ATLAS_HOST>/?retryWrites=true&w=majority&appName=<APP_NAME>
MONGO_DB=cybersentinel
```

Do not put raw database passwords in documentation or screenshots.

## 6. Local Validation On Windows

Use this path to prove the app works before hosted deployment, or to debug customer setup locally.

Required local tools:

- Python 3.11
- Node.js and npm
- Access to customer Atlas URI
- SMTP credentials
- Private release bundle with model artifacts



### 6.1 Cloud-Model API

Open PowerShell:

```powershell
cd <RELEASE_ROOT>\CyberSentinel-Cloud-Model
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Optional `.env` for Model Ops/version persistence:

```env
MODEL_ADMIN_TOKEN=<MODEL_ADMIN_TOKEN>
MONGO_URI=<MONGO_URI>
MONGO_DB=cybersentinel
```

Start the service:

```powershell
python -m uvicorn app:app --reload --host 0.0.0.0 --port 8010
```

Verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8010/health
```

Expected result:

- `status` is `ok`
- `models_loaded` is `true`
- `expected_feature_count` is present when the model exposes it



### 6.2 Backend API

Open a second PowerShell terminal:

```powershell
cd <RELEASE_ROOT>\CyberSentinel-Backend
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.sample .env
```

Edit `CyberSentinel-Backend/.env` and set at minimum:

```env
APP_ENV=dev
DEBUG_MODE=false
DETAILED_LOGGING=false

MONGO_URI=<MONGO_URI>
MONGO_DB=cybersentinel

JWT_SECRET=<JWT_SECRET>
JWT_ALGORITHM=HS256
JWT_EXP_MINUTES=1440

MODEL_API_URL=http://127.0.0.1:8010
MODEL_API_TIMEOUT_SECONDS=10
MODEL_ADMIN_TOKEN=<MODEL_ADMIN_TOKEN>
ANOMALY_SCORE_THRESHOLD=0.65

WAZUH_INGEST_KEY=<WAZUH_INGEST_KEY>
RAW_WAZUH_WORKER_CONCURRENCY=6

CORS_ALLOW_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
FRONTEND_BASE_URL=http://localhost:3000

SMTP_HOST=<SMTP_HOST>
SMTP_PORT=587
SMTP_USER=<SMTP_USER>
SMTP_PASSWORD=<SMTP_PASSWORD>
SMTP_USE_TLS=true
SMTP_USE_SSL=false
EMAIL_FROM=<EMAIL_FROM>
EMAIL_VERIFY_TTL_MINUTES=1440
PASSWORD_RESET_TTL_MINUTES=15
```

Start the backend:

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health/
```

Expected result:

```json
{"status":"ok"}
```

If startup fails, check:

- `MODEL_API_URL` is reachable from the backend machine.
- Atlas Network Access allows the backend machine.
- `MONGO_URI` has a URL-encoded password.
- Model `.pkl` files exist in the cloud-model service.



### 6.3 Frontend

Open a third PowerShell terminal:

```powershell
cd <RELEASE_ROOT>\CyberSentinel-Frontend
```

Create or edit `CyberSentinel-Frontend/.env`:

```env
REACT_APP_API_BASE_URL=http://127.0.0.1:8000
```

Install and start:

```powershell
npm install
npm start
```

Open:

```text
http://localhost:3000
```



### 6.4 Local Auth Smoke Test

1. Open the frontend.
2. Register the first admin user.
3. Confirm SMTP sends the verification email.
4. Click the verification link.
5. Log in.
6. Open Dashboard, Logs, Alerts, and Model Ops.

If registration works but email is not received:

- Check `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_USE_TLS`, and `EMAIL_FROM`.
- Check spam/junk folders.
- Confirm the SMTP provider allows app passwords or SMTP login.



## 7. Render Deployment

The repository includes `render.yaml` as the Blueprint definition. Before customer deployment, confirm:

- Repo URLs point to private repos or a customer-accessible release source.
- `rootDir` values match the deployed repository layout.
- Cloud-model build context contains the bundled model files.
- No real secrets are committed to the repository.



### 7.1 Create The Blueprint

1. Push the customer release source to the private deployment repo.
2. In Render, create a Blueprint from the repo.
3. Render should create:
  - `cybersentinel-backend`
  - `cybersentinel-cloud-model`
  - `cybersentinel-frontend`
4. Keep the generated service URLs for later env updates.



### 7.2 Backend Render Env

Set these backend env vars in Render:

```env
APP_ENV=prod
DEBUG_MODE=false
DETAILED_LOGGING=false

MONGO_URI=<MONGO_URI>
MONGO_DB=cybersentinel

JWT_SECRET=<JWT_SECRET>
JWT_ALGORITHM=HS256
JWT_EXP_MINUTES=1440

MODEL_API_URL=<MODEL_API_URL>
MODEL_API_TIMEOUT_SECONDS=10
MODEL_ADMIN_TOKEN=<MODEL_ADMIN_TOKEN>
ANOMALY_SCORE_THRESHOLD=0.65

WAZUH_INGEST_KEY=<WAZUH_INGEST_KEY>
RAW_WAZUH_WORKER_CONCURRENCY=6

CORS_ALLOW_ORIGINS=<FRONTEND_URL>
FRONTEND_BASE_URL=<FRONTEND_URL>

SMTP_HOST=<SMTP_HOST>
SMTP_PORT=587
SMTP_USER=<SMTP_USER>
SMTP_PASSWORD=<SMTP_PASSWORD>
SMTP_USE_TLS=true
SMTP_USE_SSL=false
EMAIL_FROM=<EMAIL_FROM>
EMAIL_VERIFY_TTL_MINUTES=1440
PASSWORD_RESET_TTL_MINUTES=15
```

Optional for future integrations, leave empty unless separately deployed:

```env
AGENT_SERVICE_URL=
AGENT_TIMEOUT_SECONDS=10
```



### 7.3 Cloud-Model Render Env

Set these cloud-model env vars:

```env
MODEL_ADMIN_TOKEN=<MODEL_ADMIN_TOKEN>
```

For Model Ops version persistence, also set:

```env
MONGO_URI=<MONGO_URI>
MONGO_DB=cybersentinel
```

`MODEL_ADMIN_TOKEN` must match the backend value.

### 7.4 Frontend Render Env

Set:

```env
REACT_APP_API_BASE_URL=<BACKEND_URL>
```



### 7.5 Redeploy And Verify Hosted Services

After setting final URLs and secrets, redeploy all services.

Verify cloud-model:

```powershell
Invoke-RestMethod <MODEL_API_URL>/health
```

Verify backend:

```powershell
Invoke-RestMethod <BACKEND_URL>/api/health/
```

Verify frontend:

```text
<FRONTEND_URL>
```

Hosted auth smoke test:

1. Register the first admin user from `<FRONTEND_URL>`.
2. Confirm SMTP verification email is delivered.
3. Verify the email.
4. Log in.
5. Open Model Ops and confirm the page loads.



## 8. Wazuh All-In-One Setup

Use an Ubuntu server or VM for Wazuh. For a small lab, Wazuh's quickstart all-in-one installation is the simplest path.

Recommended minimum for a small lab:

- 4 vCPU
- 8 GiB RAM
- 50 GB disk
- Ubuntu 22.04 or 24.04

Install Wazuh all-in-one on the Ubuntu Wazuh server:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

When installation completes, save the generated dashboard credentials securely.

Open the Wazuh dashboard:

```text
https://<WAZUH_SERVER_IP>
```

The first browser visit may show a certificate warning because the default certificate is self-signed.

If credentials are needed later, retrieve them on the Wazuh server:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Optional package stability step for lab installs:

```bash
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```



## 9. Enroll A Windows Endpoint In Wazuh

Primary customer endpoint path is Windows.

1. Open the Wazuh dashboard.
2. Go to `Agents management` -> `Summary`.
3. Click `Deploy new agent`.
4. Select Windows.
5. Enter the Wazuh manager IP or hostname: `<WAZUH_SERVER_IP>`.
6. Copy the generated install command.
7. Run it in an elevated PowerShell or CMD session on the Windows endpoint.
8. Start or restart the Wazuh agent when instructed.
9. Return to the dashboard and confirm the agent status becomes `Active`.

If the agent does not become active:

- Confirm endpoint can reach the Wazuh server.
- Check Windows firewall and network profile.
- Confirm the manager address used during enrollment is reachable from the endpoint.
- Restart the Wazuh agent service on Windows.

Linux endpoints can also be enrolled from the same Wazuh dashboard flow, but this guide treats Windows as the first customer path.

## 10. Enable Wazuh Archive JSON

CyberSentinel's primary Wazuh integration reads raw Wazuh archive JSON lines from:

```text
/var/ossec/logs/archives/archives.json
```

On the Wazuh server, back up the config:

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%Y%m%d%H%M%S)
```

Edit:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Inside the `<global>` section, set:

```xml
<logall_json>yes</logall_json>
```

Also confirm JSON alert output remains enabled:

```xml
<jsonout_output>yes</jsonout_output>
```

Restart Wazuh manager:

```bash
sudo systemctl restart wazuh-manager
```

Verify the archive file exists after events arrive:

```bash
sudo ls -lah /var/ossec/logs/archives/archives.json
sudo tail -n 3 /var/ossec/logs/archives/archives.json
```

If the file does not exist yet:

- Wait for endpoint activity.
- Confirm the Windows agent is active.
- Confirm `<logall_json>yes</logall_json>` is in the active config.
- Check Wazuh manager status:

```bash
sudo systemctl status wazuh-manager
```



## 11. Install The CyberSentinel Wazuh Forwarder

The forwarder script is:

```text
CyberSentinel-Backend/scripts/wazuh_archives_forwarder.py
```

It:

- Reads appended bytes from `archives.json`.
- Tracks file offsets.
- Handles log rotation.
- Sends batches to CyberSentinel.
- Retries failures with backoff.
- Does not transform Wazuh payloads before sending.

Copy the script to the Wazuh server.

From the installer machine:

```bash
scp CyberSentinel-Backend/scripts/wazuh_archives_forwarder.py <WAZUH_USER>@<WAZUH_SERVER_IP>:/tmp/wazuh_archives_forwarder.py
```

On the Wazuh server:

```bash
sudo mkdir -p /opt/cybersentinel
sudo mv /tmp/wazuh_archives_forwarder.py /opt/cybersentinel/wazuh_archives_forwarder.py
sudo chmod 750 /opt/cybersentinel/wazuh_archives_forwarder.py
```



## 12. Test Forwarder In Foreground

On the Wazuh server:

```bash
export CS_BACKEND_URL="<BACKEND_URL>"
export WAZUH_INGEST_KEY="<WAZUH_INGEST_KEY>"
export WAZUH_ARCHIVES_PATH="/var/ossec/logs/archives/archives.json"
export WAZUH_FORWARDER_OFFSET_PATH="$HOME/.cybersentinel-wazuh-forwarder.offset.json"
export WAZUH_FORWARDER_POLL_SEC="4"
```

Connectivity test:

```bash
curl -i "$CS_BACKEND_URL/api/health/"
```

Run the forwarder:

```bash
sudo -E python3 /opt/cybersentinel/wazuh_archives_forwarder.py
```

Leave it running for one or two polling cycles, then stop it with `Ctrl+C`.

Expected backend ingestion behavior:

- New raw Wazuh lines are sent to `POST /api/raw_wazuh_logs`.
- Header used by the forwarder: `x-ingestion-key`.
- Payload shape:

```json
{
  "source": "wazuh",
  "type": "raw",
  "logs": [],
  "sentAt": 0
}
```

If the forwarder returns HTTP 401:

- `WAZUH_INGEST_KEY` on Wazuh server does not match backend env.
- Update the value and restart the backend/forwarder.

If the forwarder cannot connect:

- Confirm `<BACKEND_URL>` is reachable from the Wazuh server.
- Confirm Render service is awake.
- Confirm firewalls allow outbound HTTPS from the Wazuh server.



## 13. Install Forwarder As A systemd Service

Create a state directory:

```bash
sudo mkdir -p /var/lib/cybersentinel-wazuh-forwarder
sudo chmod 700 /var/lib/cybersentinel-wazuh-forwarder
```

Create:

```bash
sudo nano /etc/systemd/system/cybersentinel-wazuh-forwarder.service
```

Paste:

```ini
[Unit]
Description=CyberSentinel Wazuh Archive Forwarder
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/cybersentinel
Environment=CS_BACKEND_URL=<BACKEND_URL>
Environment=WAZUH_INGEST_KEY=<WAZUH_INGEST_KEY>
Environment=WAZUH_ARCHIVES_PATH=/var/ossec/logs/archives/archives.json
Environment=WAZUH_FORWARDER_OFFSET_PATH=/var/lib/cybersentinel-wazuh-forwarder/offset.json
Environment=WAZUH_FORWARDER_POLL_SEC=4
ExecStart=/usr/bin/python3 /opt/cybersentinel/wazuh_archives_forwarder.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cybersentinel-wazuh-forwarder
```

Check status:

```bash
sudo systemctl status cybersentinel-wazuh-forwarder
sudo journalctl -u cybersentinel-wazuh-forwarder -n 100 --no-pager
```

Follow logs during validation:

```bash
sudo journalctl -u cybersentinel-wazuh-forwarder -f
```



## 14. Curated Wazuh Web Access Test

CyberSentinel's current Wazuh ML inference path supports Wazuh events with decoder `web-accesslog`. Use this curated sample to validate the full ingestion path even if the customer does not yet have a real web server log source.

On the Wazuh server:

```bash
cat > /tmp/cybersentinel-web-access-sample.jsonl <<'EOF'
{"timestamp":"2026-01-01T00:00:00Z","agent":{"id":"001","name":"windows-endpoint"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"web-accesslog"},"rule":{"id":"31151","level":10,"description":"Web accesslog sensitive file probe"},"location":"/var/log/apache2/access.log","full_log":"192.0.2.10 - - [01/Jan/2026:00:00:00 +0000] \"GET /wp-config.php.bak HTTP/1.1\" 404 123 \"-\" \"Mozilla/5.0\"","data":{"srcip":"192.0.2.10","url":"/wp-config.php.bak","protocol":"GET","status":"404"}}
EOF
```

Run a one-time foreground send using the same forwarder:

```bash
export CS_BACKEND_URL="<BACKEND_URL>"
export WAZUH_INGEST_KEY="<WAZUH_INGEST_KEY>"
export WAZUH_ARCHIVES_PATH="/tmp/cybersentinel-web-access-sample.jsonl"
export WAZUH_FORWARDER_OFFSET_PATH="/tmp/cybersentinel-web-access-sample.offset.json"
export WAZUH_FORWARDER_POLL_SEC="4"

timeout 10s sudo -E python3 /opt/cybersentinel/wazuh_archives_forwarder.py
```

`timeout` may return exit code `124`; that is expected because the forwarder is a continuous process.

Validate in CyberSentinel:

1. Log in to the frontend.
2. Open Logs.
3. Look for source `windows-endpoint` or Wazuh metadata from the sample.
4. Open Alerts.
5. If an alert appears, the model classified the sample as anomaly or known attack.
6. If no alert appears but the log appears, ingestion worked and the bundled model likely classified the sample as benign.

The Alerts outcome depends on the bundled model prediction. Log visibility is the minimum acceptance condition for raw Wazuh ingestion.

## 15. Model Ops Validation

Model Ops uses:

- Backend admin endpoints under `/api/ml`.
- Cloud-model admin endpoints under `/train`, `/models/versions`, and `/models/activate`.
- `MODEL_ADMIN_TOKEN` shared between backend and cloud-model.
- Raw Wazuh data in MongoDB for retraining.

Required env:

Backend:

```env
MODEL_API_URL=<MODEL_API_URL>
MODEL_ADMIN_TOKEN=<MODEL_ADMIN_TOKEN>
RETRAIN_RAW_WAZUH_DB_LIMIT=10000
MIN_SAMPLES_PER_ATTACK_CLASS=50
```

Cloud-model:

```env
MODEL_ADMIN_TOKEN=<MODEL_ADMIN_TOKEN>
MONGO_URI=<MONGO_URI>
MONGO_DB=cybersentinel
```

Open the frontend Model Ops page:

1. Confirm the page loads for the first admin user.
2. Confirm model versions list appears, or an empty/no-versions state appears cleanly.
3. Confirm retrain actions are visible to admin users.

Retraining requirements:

- At least 400 usable training samples.
- At least benign and one attack class.
- Enough raw Wazuh data in `raw_wazuh_logs`, or a configured fallback dataset.
- Current minimum attack-class setting defaults to `50`.

If retraining fails with `Training dataset too small` or a raw Wazuh dataset error, continue collecting Wazuh data and retry later.

Rollback smoke flow:

1. Open Model Ops.
2. List model versions.
3. Select a non-active previous version if one exists.
4. Trigger rollback.
5. Confirm active version changes.

Do not run retraining or rollback during customer demos unless the customer understands model changes can affect alert behavior.

## 16. End-To-End Acceptance Checklist

Use this checklist before handoff.

Services:

- [ ] Cloud-model `/health` returns `status: ok`.
- [ ] Backend `/api/health/` returns `{"status":"ok"}`.
- [ ] Frontend loads from `<FRONTEND_URL>`.
- [ ] Backend CORS allows `<FRONTEND_URL>`.
- [ ] Atlas connection works from backend.
- [ ] SMTP verification email is delivered.

Auth:

- [ ] First admin can register.
- [ ] First admin receives verification email.
- [ ] First admin can verify email.
- [ ] First admin can log in.

Wazuh:

- [ ] Wazuh dashboard opens at `https://<WAZUH_SERVER_IP>`.
- [ ] Windows endpoint agent status is `Active`.
- [ ] `/var/ossec/logs/archives/archives.json` exists.
- [ ] Forwarder can call `<BACKEND_URL>/api/health/`.
- [ ] Forwarder runs in foreground without auth errors.
- [ ] Forwarder runs under systemd.
- [ ] Curated `web-accesslog` sample appears in CyberSentinel Logs.

Alerts and ML:

- [ ] Cloud-model is reachable from backend.
- [ ] Wazuh sample is processed by ML, or log metadata shows ML status clearly.
- [ ] Alerts page loads.
- [ ] If the sample produces an alert, alert detail opens correctly.

Model Ops:

- [ ] Model Ops page loads for admin.
- [ ] Model versions list or empty state displays cleanly.
- [ ] Retrain requirements are explained to customer.

Security:

- [ ] No real secrets are stored in docs.
- [ ] Customer has stored Atlas, SMTP, Render, and Wazuh credentials securely.
- [ ] Any secret exposed in chat, screenshots, or setup notes has been rotated.



## 17. Common Setup Problems

Backend fails on startup:

- Cloud-model service is not reachable.
- `MODEL_API_URL` is empty or wrong.
- Atlas URI is invalid.
- Atlas Network Access does not allow the backend.
- Model API health is failing because model files are missing.

Frontend cannot call backend:

- `REACT_APP_API_BASE_URL` points to the wrong backend URL.
- Backend `CORS_ALLOW_ORIGINS` does not include the frontend URL.
- Render backend is asleep and needs time to wake.

Admin cannot log in after registration:

- Email verification is required.
- SMTP email was not delivered.
- Verification link points to the wrong `FRONTEND_BASE_URL`.

Wazuh forwarder returns 401:

- `WAZUH_INGEST_KEY` mismatch.
- Backend was not restarted after env update.
- systemd unit still contains the old key.

Wazuh logs do not appear:

- `archives.json` is not being written.
- `logall_json` is not set to `yes`.
- Forwarder offset file already advanced past test data.
- Backend URL is unreachable from Wazuh server.
- Render backend is asleep or unhealthy.

Logs appear but alerts do not:

- The model classified the sample as benign.
- The event decoder is not `web-accesslog`.
- Cloud-model prediction failed.
- The backend marked ML status as skipped or error.



## 18. What This Guide Does Not Cover

This guide does not cover:

- Developer notebooks.
- Unit tests.
- Code architecture deep dives.
- Docker Compose packaging.
- External agent service integration.
- Enterprise high-availability Wazuh clusters.
- Advanced Wazuh tuning.
- The legacy direct Wazuh alert endpoint `/api/logs/wazuh`.



## 19. Official References

Use these official Wazuh references when updating this guide:

- Wazuh Quickstart: [https://documentation.wazuh.com/current/quickstart.html](https://documentation.wazuh.com/current/quickstart.html)
- Wazuh global config options, including `logall_json` and `jsonout_output`: [https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html)
- Wazuh external integrations reference: [https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- Wazuh agent deployment: [https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)

