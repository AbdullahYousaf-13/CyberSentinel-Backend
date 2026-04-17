# Wazuh Forwarder Setup (Ubuntu -> Windows Backend)

This project includes:
- Forwarder script: `scripts/wazuh_archives_forwarder.py`
- Ingestion endpoint: `POST /api/raw_wazuh_logs`

Use this guide when Wazuh runs on Ubuntu and backend runs on Windows.

## 1) Backend (Windows) requirements

1. In backend `.env` set:

```env
WAZUH_INGEST_KEY=your_shared_secret_here
```

2. Start backend so Ubuntu can reach it on LAN:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

3. Ensure Windows firewall allows inbound TCP 8000.

## 2) Ubuntu (Wazuh machine) requirements

You need Python 3 available and either:
- backend repo cloned on Ubuntu, or
- only `scripts/wazuh_archives_forwarder.py` copied to Ubuntu.

Set runtime environment variables:

```bash
export CS_BACKEND_URL="http://<WINDOWS_IP>:8000"
export WAZUH_INGEST_KEY="your_shared_secret_here"
export WAZUH_ARCHIVES_PATH="/var/ossec/logs/archives/archives.json"
export WAZUH_FORWARDER_OFFSET_PATH="/var/lib/cybersentinel-wazuh-forwarder.offset.json"
export WAZUH_FORWARDER_POLL_SEC="4"
```

Notes:
- `CS_BACKEND_URL` must use Windows IP, not localhost.
- `WAZUH_INGEST_KEY` must exactly match backend `.env`.
- Poll interval is clamped to 3-5 seconds by the script.

## 3) Connectivity test from Ubuntu

```bash
curl -i "http://<WINDOWS_IP>:8000/api/health"
```

If this fails, fix IP/firewall/backend startup before running the forwarder.

## 4) Run forwarder on Ubuntu

```bash
python3 scripts/wazuh_archives_forwarder.py
```

## 5) Optional: run as systemd service on Ubuntu

Create file:

`/etc/systemd/system/cybersentinel-wazuh-forwarder.service`

```ini
[Unit]
Description=CyberSentinel Wazuh Forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/CyberSentinel-Backend
Environment=CS_BACKEND_URL=http://<WINDOWS_IP>:8000
Environment=WAZUH_INGEST_KEY=your_shared_secret_here
Environment=WAZUH_ARCHIVES_PATH=/var/ossec/logs/archives/archives.json
Environment=WAZUH_FORWARDER_OFFSET_PATH=/var/lib/cybersentinel-wazuh-forwarder.offset.json
Environment=WAZUH_FORWARDER_POLL_SEC=4
ExecStart=/usr/bin/python3 /opt/CyberSentinel-Backend/scripts/wazuh_archives_forwarder.py
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
sudo systemctl status cybersentinel-wazuh-forwarder
```

## 6) Behavior guarantees implemented by script

- Reads only appended bytes using file offset tracking
- Detects log rotation (file size shrink) and safely resets offset
- Parses line-by-line JSON and discards invalid JSON lines
- Sends batches in near real-time (3-5 sec)
- Retries failed requests with exponential backoff
- Keeps request limits within:
  - max `500` logs per request
  - max `1MB` payload per request
- Does not transform or enrich Wazuh log content
