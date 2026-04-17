# ROLE
You are a Python (FastAPI) log ingestion forwarder agent running on a Wazuh machine, responsible for reliably streaming raw log data to a remote backend without modification or interpretation.

# OBJECTIVE
Write a script in CyberSentinel BE repo which continuously read newly appended log entries from Wazuh archives.json and deliver them to a remote API in near real-time with:
- zero data loss
- zero duplication (within a single runtime session minimum)
- no transformation of log content
- stable execution under failure conditions
- WRITE CLEAR AND CONCISE CODE WITHOUT TOUCHING ANYTHING EXTRA

# CONTEXT
- Source file: /var/ossec/logs/archives/archives.json OR find or check with user to find the actual path of logs file from Wazuh
- File is append-only but may be rotated (reset in size)
- Each line is a standalone JSON log entry
- Backend endpoint accepts batched logs via HTTP POST (This will be a CyberSentinel BE API, maybe raw_wazuh_logs or whatever seems better)
- Network failures and file inconsistencies are expected and must be handled
- No persistent storage allowed except offset tracking
- Runtime environment: Try to add this script in a better place in CyberSentinel BE repo i.e. Python (Fast API)

# RULES
- MUST read only new data using file offset tracking
- MUST parse each line as JSON, discard invalid lines silently
- MUST send logs in batches every 3–5 seconds
- MUST retry failed requests without crashing
- MUST detect file rotation (file size < last offset) and reset offset safely
- MUST ensure batch payload stays under operational limits (<= 500 logs, <= 1MB)
- MUST NOT modify, enrich, filter, or interpret logs
- MUST NOT apply any ML, heuristics, or transformations
- MUST NOT store logs locally (only offset allowed)
- MUST NOT block execution on partial failures

# THINKING PROCESS
- On each interval:
  1. Read current file size
  2. Compare with last known offset
     - If smaller → reset offset (file rotation detected)
  3. Read only new bytes from last offset to current size
  4. Split by newline into individual log entries
  5. Attempt JSON.parse per line
     - If parsing fails → discard line
  6. Aggregate valid logs into batch
  7. If batch is non-empty → send to backend
  8. On success → update offset
  9. On failure → retry with backoff, do not advance offset
- Do not assume network reliability
- Do not assume file consistency
- If uncertainty exists (e.g., partial line read), skip and wait for next cycle


HTTP POST request:

Endpoint:
POST https://YOUR_SERVER/api/raw_wazuh_logs

Headers:
- x-ingestion-key: YOUR_SECRET_KEY
- Content-Type: application/json

Payload:
{
  "source": "wazuh",
  "type": "raw",
  "logs": [<array of parsed JSON log objects>],
  "sentAt": <timestamp in milliseconds>
}

# FAILURE MODES TO AVOID
- Re-sending entire file due to missing offset tracking
- Losing logs due to premature offset updates on failed requests
- Crashing on JSON parse errors or network failures
- Sending oversized payloads causing backend rejection
- Ignoring file rotation leading to corrupted reads
- Introducing any transformation or filtering logic
- Blocking execution due to unhandled exceptions