"""
Stream Wazuh archives.json (append-only, possibly rotated) to CyberSentinel
POST /api/raw_wazuh_logs with byte offset tracking only (no local log storage).

Environment:
  CS_BACKEND_URL      Base URL, e.g. https://your-host (no trailing slash required)
  WAZUH_INGEST_KEY    Same value as server WAZUH_INGEST_KEY (header x-ingestion-key)
  WAZUH_ARCHIVES_PATH Path to archives.json (default: /var/ossec/logs/archives/archives.json)
  WAZUH_FORWARDER_OFFSET_PATH  File to persist byte offset (default: ~/.cybersentinel-wazuh-forwarder.offset.json)
  WAZUH_FORWARDER_POLL_SEC     Poll interval in seconds (default: 4, clamped 3–5)
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_MAX_LOGS = 500
_MAX_PAYLOAD_BYTES = 1024 * 1024
_DEFAULT_POLL = 4.0
_BACKOFF_CAP_SEC = 60.0


def _env(name: str, default: Optional[str] = None) -> str:
    val = os.environ.get(name, default)
    if val is None or val.strip() == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val.strip()


def _load_state(path: Path) -> Tuple[int, str]:
    if not path.is_file():
        return 0, ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        off = int(data.get("byte_offset", 0))
        p = str(data.get("archive_path", "") or "")
        return max(off, 0), p
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        return 0, ""


def _save_state(path: Path, byte_offset: int, archive_path: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"byte_offset": byte_offset, "archive_path": archive_path}, separators=(",", ":"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)


def _partition_lines(buf: bytes) -> Tuple[List[bytes], bytes]:
    if not buf:
        return [], b""
    parts = buf.split(b"\n")
    if buf.endswith(b"\n"):
        incomplete = b""
        lines = parts[:-1] if parts and parts[-1] == b"" else parts
    else:
        incomplete = parts[-1]
        lines = parts[:-1]
    return lines, incomplete


def _parse_log_lines(raw_lines: List[bytes]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in raw_lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _wrapped_payload_bytes(logs: List[Dict[str, Any]], sent_at_ms: int) -> int:
    body = {"source": "wazuh", "type": "raw", "logs": logs, "sentAt": sent_at_ms}
    return len(json.dumps(body, separators=(",", ":")).encode("utf-8"))


def _build_batches(entries: List[Dict[str, Any]], sent_at_ms: int) -> List[List[Dict[str, Any]]]:
    batches: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []

    for entry in entries:
        if _wrapped_payload_bytes([entry], sent_at_ms) > _MAX_PAYLOAD_BYTES:
            print(
                f"[wazuh-forwarder] skipping one log line that exceeds {_MAX_PAYLOAD_BYTES} bytes as a request",
                file=sys.stderr,
            )
            continue

        trial = current + [entry]
        if len(trial) > _MAX_LOGS or _wrapped_payload_bytes(trial, sent_at_ms) > _MAX_PAYLOAD_BYTES:
            if current:
                batches.append(current)
                current = [entry]
                if _wrapped_payload_bytes(current, sent_at_ms) > _MAX_PAYLOAD_BYTES:
                    print("[wazuh-forwarder] skipping oversized line after split", file=sys.stderr)
                    current = []
            else:
                current = [entry]
        else:
            current = trial

    if current:
        batches.append(current)
    return batches


def _post_batch(base_url: str, ingest_key: str, logs: List[Dict[str, Any]], sent_at_ms: int) -> None:
    url = f"{base_url.rstrip('/')}/api/raw_wazuh_logs"
    body = json.dumps(
        {"source": "wazuh", "type": "raw", "logs": logs, "sentAt": sent_at_ms},
        separators=(",", ":"),
    ).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-ingestion-key": ingest_key,
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        resp.read()


def _send_with_retries(base_url: str, ingest_key: str, logs: List[Dict[str, Any]], sent_at_ms: int) -> None:
    delay = 1.0
    while True:
        try:
            _post_batch(base_url, ingest_key, logs, sent_at_ms)
            return
        except urllib.error.HTTPError as exc:
            err_body = exc.read() if exc.fp else b""
            print(
                f"[wazuh-forwarder] HTTP {exc.code} {exc.reason!r} {err_body[:500]!r}",
                file=sys.stderr,
            )
        except urllib.error.URLError as exc:
            print(f"[wazuh-forwarder] URL error: {exc.reason!r}", file=sys.stderr)
        except OSError as exc:
            print(f"[wazuh-forwarder] OS error: {exc}", file=sys.stderr)

        time.sleep(delay)
        delay = min(delay * 2.0, _BACKOFF_CAP_SEC)


def _poll_interval_sec() -> float:
    raw = os.environ.get("WAZUH_FORWARDER_POLL_SEC", str(_DEFAULT_POLL))
    try:
        v = float(raw)
    except ValueError:
        v = _DEFAULT_POLL
    return max(3.0, min(5.0, v))


def cycle_once(
    archive_path: Path,
    state_path: Path,
    base_url: str,
    ingest_key: str,
) -> None:
    if not archive_path.is_file():
        return

    byte_offset, stored_path = _load_state(state_path)
    ap_str = str(archive_path)
    if stored_path and stored_path != ap_str:
        byte_offset = 0

    try:
        size = archive_path.stat().st_size
    except OSError as exc:
        print(f"[wazuh-forwarder] stat failed: {exc}", file=sys.stderr)
        return

    if size < byte_offset:
        byte_offset = 0

    to_read = size - byte_offset
    chunk = b""
    if to_read > 0:
        try:
            with archive_path.open("rb") as f:
                f.seek(byte_offset)
                chunk = f.read(to_read)
        except OSError as exc:
            print(f"[wazuh-forwarder] read failed: {exc}", file=sys.stderr)
            return

    raw_lines, incomplete = _partition_lines(chunk)
    entries = _parse_log_lines(raw_lines)
    sent_at_ms = int(time.time() * 1000)

    if entries:
        for batch in _build_batches(entries, sent_at_ms):
            _send_with_retries(base_url, ingest_key, batch, sent_at_ms)

    new_offset = size - len(incomplete)
    if new_offset < 0:
        new_offset = 0
    _save_state(state_path, new_offset, ap_str)


def main() -> int:
    base_url = _env("CS_BACKEND_URL")
    ingest_key = _env("WAZUH_INGEST_KEY")
    archive = Path(os.environ.get("WAZUH_ARCHIVES_PATH", "/var/ossec/logs/archives/archives.json"))
    state_path = Path(
        os.environ.get(
            "WAZUH_FORWARDER_OFFSET_PATH",
            str(Path.home() / ".cybersentinel-wazuh-forwarder.offset.json"),
        )
    )
    interval = _poll_interval_sec()

    while True:
        try:
            cycle_once(archive, state_path, base_url, ingest_key)
        except Exception as exc:  # noqa: BLE001 — forwarder must not exit
            print(f"[wazuh-forwarder] cycle error: {exc}", file=sys.stderr)
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
