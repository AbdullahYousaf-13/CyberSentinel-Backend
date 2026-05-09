import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer

HTTP_REQUEST_RE = re.compile(r'^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)')
ATTACK_RULES: List[Tuple[str, List[str]]] = [
    ("PATH_TRAVERSAL", [r"\.\.", r"%2e%2e", r"boot\.ini", r"etc/passwd", r"%00"]),
    ("WORDPRESS_PROBE", [r"wp-login\.php", r"wp-json", r"\?author="]),
    ("GIT_PROBE", [r"\.git/"]),
    ("WEBDAV_PROBE", [r"^PROPFIND\b"]),
    ("PROXY_SPIDER_PROBE", [r"^https?://", r"www\.google\.com:80", r"www\.wikipedia\.org:80", r"www\.computerhistory\.org:80", r"@localhost"]),
    ("SQLI_PROBE", [r"updatexml", r"union(?:\+|%20)select"]),
    ("PHPMYADMIN_PROBE", [r"phpMyAdmin"]),
    ("COLDFUSION_PROBE", [r"/CFIDE/", r"coldfusion"]),
    ("PHP_INJECTION_PROBE", [r"allow_url_include", r"auto_prepend_file=php://input"]),
    ("CGI_PROBE", [r"/cgi-bin/"]),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a heuristic-labeled web_access seed dataset from raw Wazuh JSON exports."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to exported raw Wazuh logs JSON file (for example cybersentinel.raw_wazuh_logs (1).json)",
    )
    parser.add_argument(
        "--payload-out",
        required=True,
        help="Path to write training payload JSON for the cloud model /train endpoint",
    )
    parser.add_argument(
        "--review-out",
        help="Optional path to write review JSONL with per-sample labels and heuristic reasons",
    )
    parser.add_argument(
        "--min-benign",
        type=int,
        default=1000,
        help="Minimum benign sample count required (default: 1000)",
    )
    parser.add_argument(
        "--min-attack",
        type=int,
        default=200,
        help="Minimum attack-labeled sample count required (default: 200)",
    )
    parser.add_argument(
        "--reason",
        default="bootstrap_web_access_seed_dataset",
        help="Reason string recorded in the generated training payload",
    )
    parser.add_argument(
        "--min-class-support",
        type=int,
        default=10,
        help="Collapse attack labels with fewer than this many samples into WEB_ATTACK_GENERIC (default: 10)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    payload_out = Path(args.payload_out)
    review_out = Path(args.review_out) if args.review_out else None
    if not input_path.is_file():
        raise FileNotFoundError(f"Input JSON file not found: {input_path}")

    rows = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise RuntimeError("Input JSON must contain a top-level list")

    engineer = WazuhFamilyFeatureEngineer()
    compiled_rules = [(label, [re.compile(pattern, re.IGNORECASE) for pattern in patterns]) for label, patterns in ATTACK_RULES]

    staged_rows: List[Dict[str, Any]] = []
    raw_label_counts = Counter()

    for raw_row in rows:
        payload = raw_row.get("payload") if isinstance(raw_row, dict) else None
        if not isinstance(payload, dict):
            continue
        engineered = engineer.engineer_payload(payload, message_override=payload.get("full_log"))
        if engineered.get("model_family") != "web_access":
            continue
        schema = engineered.get("feature_schema_version")
        features = (engineered.get("engineered_features") or {}).get(schema)
        if not isinstance(schema, str) or not isinstance(features, dict):
            continue

        message = str(payload.get("full_log") or "")
        method, path = parse_request(message)
        raw_label_name, heuristic_reason = classify_web_access_sample(method, path, compiled_rules)
        raw_label_counts[raw_label_name] += 1
        staged_rows.append(
            {
                "timestamp": payload.get("timestamp"),
                "raw_label": raw_label_name,
                "heuristic_reason": heuristic_reason,
                "method": method,
                "path": path,
                "message": message,
                "model_family": "web_access",
                "feature_schema_version": schema,
                "features": features,
            }
        )

    label_to_id: Dict[str, int] = {"BENIGN": 0}
    review_rows: List[Dict[str, Any]] = []
    samples: List[Dict[str, Any]] = []
    labels: List[int] = []
    timestamps: List[str] = []
    attack_count = 0
    benign_count = 0
    final_label_counts = Counter()

    for row in staged_rows:
        label_name = normalize_attack_label(row["raw_label"], raw_label_counts, args.min_class_support)
        final_label_counts[label_name] += 1
        label_to_id.setdefault(label_name, len(label_to_id))
        if label_name == "BENIGN":
            benign_count += 1
        else:
            attack_count += 1

        samples.append(row["features"])
        labels.append(label_to_id[label_name])
        timestamps.append(str(row.get("timestamp") or ""))
        review_rows.append(
            {
                "timestamp": row.get("timestamp"),
                "label": label_name,
                "raw_label": row.get("raw_label"),
                "heuristic_reason": row.get("heuristic_reason"),
                "method": row.get("method"),
                "path": row.get("path"),
                "message": row.get("message"),
                "model_family": row.get("model_family"),
                "feature_schema_version": row.get("feature_schema_version"),
            }
        )

    if benign_count < args.min_benign or attack_count < args.min_attack:
        raise RuntimeError(
            f"Dataset thresholds not met: benign={benign_count} attack={attack_count} "
            f"(required benign>={args.min_benign}, attack>={args.min_attack})"
        )

    payload_body = {
        "reason": args.reason,
        "model_family": "web_access",
        "feature_schema_version": "web_access_v1",
        "samples": samples,
        "labels": labels,
        "timestamps": timestamps,
        "label_map": {str(label_id): label_name for label_name, label_id in label_to_id.items()},
    }

    payload_out.parent.mkdir(parents=True, exist_ok=True)
    payload_out.write_text(json.dumps(payload_body, indent=2), encoding="utf-8")

    if review_out is not None:
        review_out.parent.mkdir(parents=True, exist_ok=True)
        with review_out.open("w", encoding="utf-8") as handle:
            for row in review_rows:
                handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    print(f"web_access benign samples: {benign_count}")
    print(f"web_access attack samples: {attack_count}")
    print(f"label distribution: {json.dumps(dict(final_label_counts), sort_keys=True)}")
    print(f"raw heuristic distribution: {json.dumps(dict(raw_label_counts), sort_keys=True)}")
    print(f"training payload: {payload_out.resolve()}")
    if review_out is not None:
        print(f"review labels: {review_out.resolve()}")


def parse_request(message: str) -> Tuple[str, str]:
    match = HTTP_REQUEST_RE.match(message)
    if not match:
        return "", ""
    return match.group("method").upper(), match.group("path")


def classify_web_access_sample(
    method: str,
    path: str,
    compiled_rules: Iterable[Tuple[str, List[re.Pattern[str]]]],
) -> Tuple[str, str]:
    text = f"{method} {path}"
    for label, patterns in compiled_rules:
        for pattern in patterns:
            if pattern.search(text):
                return label, pattern.pattern
    return "BENIGN", ""


def normalize_attack_label(label_name: str, label_counts: Counter, min_class_support: int) -> str:
    if label_name == "BENIGN":
        return label_name
    if int(label_counts.get(label_name, 0)) < min_class_support:
        return "WEB_ATTACK_GENERIC"
    return label_name


if __name__ == "__main__":
    main()
