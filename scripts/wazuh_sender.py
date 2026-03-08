import argparse
import json
import sys
from pathlib import Path
from urllib import request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send Wazuh alerts to CyberSentinel backend.")
    parser.add_argument("--backend-url", required=True, help="Backend base URL (e.g. https://api.example.com)")
    parser.add_argument("--ingest-key", required=True, help="Value of WAZUH_INGEST_KEY")
    parser.add_argument(
        "--alert-file",
        help="Path to a JSON alert file. If omitted, JSON is read from stdin.",
    )
    return parser.parse_args()


def load_payload(alert_file: str | None) -> dict:
    if alert_file:
        raw = Path(alert_file).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Alert payload must be a JSON object")
    return payload


def send_payload(base_url: str, ingest_key: str, payload: dict) -> None:
    url = f"{base_url.rstrip('/')}/api/logs/wazuh"
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-WAZUH-KEY": ingest_key,
        },
    )
    with request.urlopen(req, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="replace")
        print(f"status={resp.status}")
        print(content)


def main() -> int:
    args = parse_args()
    payload = load_payload(args.alert_file)
    send_payload(args.backend_url, args.ingest_key, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
