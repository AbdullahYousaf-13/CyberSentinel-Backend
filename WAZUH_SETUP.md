# Wazuh -> CyberSentinel Ingestion Setup

This setup sends Wazuh alerts to:

- `POST /api/logs/wazuh`
- Header: `X-WAZUH-KEY: <your-secret>`

## 1) Configure backend key

In `CyberSentinel-Backend/.env` set:

```env
WAZUH_INGEST_KEY=replace-with-long-random-secret
```

Restart backend after updating `.env`.

## 2) Verify endpoint exists

```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:8000/openapi.json" | ConvertTo-Json -Depth 3
```

Confirm path `/api/logs/wazuh` appears.

## 3) Test from local machine

```powershell
$headers = @{ "X-WAZUH-KEY" = "replace-with-long-random-secret" }
$body = @{
  timestamp = (Get-Date).ToUniversalTime().ToString("o")
  agent = @{ name = "wazuh-manager"; id = "000" }
  rule = @{ id = "5710"; level = 10; description = "Test Wazuh alert" }
  full_log = "Test full log line"
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/logs/wazuh" -Headers $headers -ContentType "application/json" -Body $body
```

## 4) Send from Wazuh manager host

Use helper script:

```bash
python3 wazuh_sender.py \
  --backend-url "https://your-backend-domain" \
  --ingest-key "replace-with-long-random-secret" \
  --alert-file "/path/to/one-alert.json"
```

Script location in this repo:

- `scripts/wazuh_sender.py`

## 5) Wazuh integration hook

Configure Wazuh manager integration to call a custom script that forwards each alert JSON
to your backend using the same endpoint and key.

At minimum, ensure:

1. Backend URL is reachable from Wazuh manager.
2. `X-WAZUH-KEY` matches backend `.env`.
3. Wazuh manager can execute the sender script.
4. Outbound firewall from Wazuh manager allows HTTPS to backend.
