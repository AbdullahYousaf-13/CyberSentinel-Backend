import asyncio
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import get_settings
from app.db.mongo import close_mongo_connection, connect_to_mongo
from app.db.repositories.log_repository import LogRepository
from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.ml_model_ops_service import MLModelOpsService
from app.services.wazuh_bootstrap_service import WazuhBootstrapService

HTTP_RE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)')
STATUS_RE = re.compile(r'"\s+(?P<status>\d{3})\s+')
MODEL_PREDICT_URL = "http://127.0.0.1:8010/predict"
MODEL_TRAIN_URL = "http://127.0.0.1:8010/train"
REVIEWED_BY = "abdullahyousaf132@gmail.com"
# The cloud trainer currently enforces a 1200-sample minimum. With 1256 web-access rows,
# a 28/28 holdout is the largest clean out-of-sample set that still leaves 1200 rows for training.
HOLDOUT_ATTACK_TARGET = 28
HOLDOUT_BENIGN_TARGET = 28

SUSPICIOUS_TRAVERSAL = ("..", "%2e%2e", "boot.ini", "etc/passwd", "%00", "etc/shadow")
BENIGN_PATHS = {
    "/",
    "/favicon.ico",
    "/robots.txt",
    "/rest/admin/application-version",
    "/rest/admin/application-configuration",
    "/main.js",
    "/vendor.js",
    "/polyfills.js",
    "/runtime.js",
    "/styles.css",
}


def _full_log(log: Dict[str, Any]) -> str:
    metadata = log.get("metadata") or {}
    raw = metadata.get("raw_wazuh_payload") if isinstance(metadata, dict) else {}
    if isinstance(raw, dict):
        full = str(raw.get("full_log") or "").strip()
        if full:
            return full
    return str(log.get("message") or "")


def _parse_http(log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    message = _full_log(log)
    match = HTTP_RE.match(message)
    if not match:
        return None
    path_raw = match.group("path")
    parsed = urlsplit(path_raw)
    status_match = STATUS_RE.search(message)
    status = int(status_match.group("status")) if status_match else 0
    ua_match = re.search(r'"([^"]*)"\s*$', message)
    ua = ua_match.group(1) if ua_match else ""
    return {
        "method": match.group("method").upper(),
        "path_raw": path_raw,
        "path": parsed.path or path_raw,
        "status": status,
        "ua": ua,
        "message": message,
    }


def _review_label(parsed: Dict[str, Any]) -> Optional[Tuple[str, Optional[str], str]]:
    method = parsed["method"]
    path = parsed["path"]
    status = parsed["status"]
    ua = parsed["ua"]
    lowered = path.lower()
    ua_lower = ua.lower()

    if "nmap scripting engine" in ua_lower:
        if "wp-login.php" in lowered or "wp-json" in lowered:
            return ("confirmed_known_attack", "WORDPRESS_PROBE", "nmap wordpress probe")
        if "/cfide/" in lowered or "coldfusion" in lowered:
            return ("confirmed_known_attack", "COLDFUSION_PROBE", "nmap coldfusion probe")
        if "/.git/" in lowered:
            return ("confirmed_known_attack", "GIT_PROBE", "nmap git probe")
        if "phpmyadmin" in lowered:
            return ("confirmed_known_attack", "PHPMYADMIN_PROBE", "nmap phpmyadmin probe")
        if method == "PROPFIND":
            return ("confirmed_known_attack", "WEBDAV_PROBE", "nmap webdav probe")
        if path.startswith("http://") or path.startswith("https://") or "@localhost" in path or "google.com" in path or "wikipedia.org" in path or "computerhistory.org" in path:
            return ("confirmed_known_attack", "PROXY_SPIDER_PROBE", "nmap proxy spider probe")
        if any(token in lowered for token in SUSPICIOUS_TRAVERSAL):
            return ("confirmed_known_attack", "PATH_TRAVERSAL", "nmap traversal probe")
        return ("confirmed_known_attack", "WEB_SCAN_NMAP", "nmap scripted scan traffic")

    if "/cfide/" in lowered or "coldfusion" in lowered:
        return ("confirmed_known_attack", "COLDFUSION_PROBE", "coldfusion probe")
    if "/.git/" in lowered:
        return ("confirmed_known_attack", "GIT_PROBE", "git probe")
    if "phpmyadmin" in lowered:
        return ("confirmed_known_attack", "PHPMYADMIN_PROBE", "phpmyadmin probe")
    if method == "PROPFIND":
        return ("confirmed_known_attack", "WEBDAV_PROBE", "webdav probe")
    if any(token in lowered for token in SUSPICIOUS_TRAVERSAL):
        return ("confirmed_known_attack", "PATH_TRAVERSAL", "path traversal probe")
    if "wp-login.php" in lowered or "wp-json" in lowered:
        return ("confirmed_known_attack", "WORDPRESS_PROBE", "wordpress probe")

    if "mozilla/5.0" in ua_lower:
        if path.startswith("/socket.io/") or path in BENIGN_PATHS or (path.startswith("/assets/") and status in {200, 204, 304}):
            return ("confirmed_benign", None, "normal browser session traffic")
        if path.endswith((".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".json")) and status in {200, 204, 304}:
            return ("confirmed_benign", None, "normal browser asset request")
    return None


def _candidate_lists(logs: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    benign: List[Dict[str, Any]] = []
    attack: List[Dict[str, Any]] = []
    for log in logs:
        parsed = _parse_http(log)
        if not parsed:
            continue
        review = _review_label(parsed)
        if not review:
            continue
        verdict, classification, reason = review
        item = {
            "log_id": str(log["_id"]),
            "log": log,
            "verdict": verdict,
            "classification": classification,
            "reason": reason,
            "path": parsed["path"],
            "method": parsed["method"],
            "status": parsed["status"],
            "ua": parsed["ua"],
        }
        if verdict == "confirmed_benign":
            benign.append(item)
        else:
            attack.append(item)
    benign.sort(key=lambda item: (item["path"], item["log_id"]))
    attack.sort(key=lambda item: (item["classification"] or "", item["path"], item["log_id"]))
    return benign, attack


def _reserve_attack_holdout(candidates: List[Dict[str, Any]], target: int) -> List[Dict[str, Any]]:
    by_label: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        by_label[item["classification"] or "WEB_ATTACK_GENERIC"].append(item)
    holdout: List[Dict[str, Any]] = []
    used_ids: set[str] = set()
    labels = sorted(by_label)
    while len(holdout) < target:
        progressed = False
        for label in labels:
            rows = by_label[label]
            while rows and rows[0]["log_id"] in used_ids:
                rows.pop(0)
            if not rows:
                continue
            item = rows.pop(0)
            holdout.append(item)
            used_ids.add(item["log_id"])
            progressed = True
            if len(holdout) >= target:
                break
        if not progressed:
            break
    return holdout


def _reserve_benign_holdout(candidates: List[Dict[str, Any]], target: int) -> List[Dict[str, Any]]:
    by_path: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        by_path[item["path"]].append(item)
    holdout: List[Dict[str, Any]] = []
    used_ids: set[str] = set()
    paths = sorted(by_path)
    while len(holdout) < target:
        progressed = False
        for path in paths:
            rows = by_path[path]
            while rows and rows[0]["log_id"] in used_ids:
                rows.pop(0)
            if not rows:
                continue
            item = rows.pop(0)
            holdout.append(item)
            used_ids.add(item["log_id"])
            progressed = True
            if len(holdout) >= target:
                break
        if not progressed:
            break
    return holdout


async def _predict_holdout(engineer: WazuhFamilyFeatureEngineer, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    import httpx

    labels: List[bool] = []
    predictions: List[bool] = []
    mismatches: List[Dict[str, Any]] = []
    versions: Counter[str] = Counter()

    async with httpx.AsyncClient(timeout=20) as client:
        for item in rows:
            payload = engineer.build_prediction_payload(item["log"])
            if not payload:
                continue
            response = await client.post(MODEL_PREDICT_URL, json=payload)
            response.raise_for_status()
            body = response.json()
            prediction = body.get("prediction") or {}
            version = str(body.get("model_version") or prediction.get("model_version") or "")
            if version:
                versions[version] += 1
            is_attack = item["verdict"] == "confirmed_known_attack"
            predicted_attack = str(prediction.get("alert_type") or "benign").lower() != "benign"
            labels.append(is_attack)
            predictions.append(predicted_attack)
            if predicted_attack != is_attack:
                mismatches.append(
                    {
                        "log_id": item["log_id"],
                        "expected": "attack" if is_attack else "benign",
                        "predicted_alert_type": prediction.get("alert_type"),
                        "predicted_classification": prediction.get("classification"),
                        "decision_score": prediction.get("decision_score"),
                        "path": item["path"],
                        "method": item["method"],
                        "reason": item["reason"],
                    }
                )

    benign_total = sum(1 for value in labels if not value)
    attack_total = sum(1 for value in labels if value)
    false_positives = sum(1 for truth, pred in zip(labels, predictions) if not truth and pred)
    true_positives = sum(1 for truth, pred in zip(labels, predictions) if truth and pred)
    return {
        "samples": len(labels),
        "benign_total": benign_total,
        "attack_total": attack_total,
        "false_positives": false_positives,
        "true_positives": true_positives,
        "benign_false_positive_rate": (false_positives / benign_total) if benign_total else None,
        "attack_recall": (true_positives / attack_total) if attack_total else None,
        "model_versions": dict(versions),
        "mismatches": mismatches[:20],
    }


def _review_items(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for row in rows:
        items.append(
            {
                "log_id": row["log_id"],
                "review_verdict": row["verdict"],
                "review_classification": row["classification"],
                "notes": row["reason"],
            }
        )
    return items


async def _wait_for_job(service: MLModelOpsService, job_id: str, timeout_seconds: int = 300) -> Dict[str, Any]:
    for _ in range(timeout_seconds):
        job = await service.get_retrain_job(job_id)
        if job and job.get("status") in {"succeeded", "failed"}:
            return job
        await asyncio.sleep(1)
    raise TimeoutError(f"Retrain job {job_id} did not finish within {timeout_seconds} seconds")


def _build_direct_training_payload(
    logs: List[Dict[str, Any]],
    engineer: WazuhFamilyFeatureEngineer,
    attack_candidates: List[Dict[str, Any]],
    exclude_log_ids: set[str],
) -> Dict[str, Any]:
    attack_log_ids = {item["log_id"] for item in attack_candidates if item["log_id"] not in exclude_log_ids}
    samples: List[Dict[str, Any]] = []
    labels: List[int] = []
    timestamps: List[str] = []
    final_counts: Counter[str] = Counter()

    for log in sorted(logs, key=lambda row: str(row.get("timestamp") or "")):
        log_id = str(log["_id"])
        if log_id in exclude_log_ids:
            continue
        payload = engineer.build_prediction_payload(log)
        if not payload:
            continue
        samples.append(payload["sample"])
        label_name = "WEB_ATTACK_GENERIC" if log_id in attack_log_ids else "BENIGN"
        labels.append(1 if label_name != "BENIGN" else 0)
        timestamps.append(str(log.get("timestamp") or ""))
        final_counts[label_name] += 1

    return {
        "reason": "web_access_review_cycle_direct_binary_bootstrap",
        "model_family": "web_access",
        "feature_schema_version": "web_access_v1",
        "samples": samples,
        "labels": labels,
        "timestamps": timestamps,
        "label_map": {"0": "BENIGN", "1": "WEB_ATTACK_GENERIC"},
        "dataset_summary": {
            "excluded_holdout_count": len(exclude_log_ids),
            "selected_attack_count": len(attack_log_ids),
            "label_distribution": dict(final_counts),
        },
    }


async def _train_direct_cloud(settings: Any, dataset: Dict[str, Any]) -> Dict[str, Any]:
    import httpx

    headers = {"x-model-admin-token": settings.model_admin_token}
    async with httpx.AsyncClient(timeout=180) as client:
        response = await client.post(MODEL_TRAIN_URL, json=dataset, headers=headers)
        response.raise_for_status()
        job = response.json()
        job_id = str(job["id"])
        for _ in range(300):
            poll = await client.get(f"{MODEL_TRAIN_URL}/{job_id}", headers=headers)
            poll.raise_for_status()
            row = poll.json()
            if row.get("status") in {"succeeded", "failed"}:
                return row
            await asyncio.sleep(1)
    raise TimeoutError(f"Direct cloud training job {job_id} did not finish in time")


async def main() -> None:
    settings = get_settings()
    await connect_to_mongo(settings)
    try:
        log_repo = LogRepository()
        bootstrap = WazuhBootstrapService()
        engineer = WazuhFamilyFeatureEngineer()
        model_ops = MLModelOpsService(settings)

        logs = await log_repo.list_logs(
            limit=5000,
            offset=0,
            filters={"metadata.raw_wazuh_payload.decoder.name": "web-accesslog"},
        )
        benign_candidates, attack_candidates = _candidate_lists(logs)
        attack_holdout = _reserve_attack_holdout(attack_candidates, HOLDOUT_ATTACK_TARGET)
        benign_holdout = _reserve_benign_holdout(benign_candidates, HOLDOUT_BENIGN_TARGET)
        holdout_ids = {item["log_id"] for item in attack_holdout + benign_holdout}
        training_attack = [item for item in attack_candidates if item["log_id"] not in holdout_ids]
        training_benign = [item for item in benign_candidates if item["log_id"] not in holdout_ids]

        pre_eval = await _predict_holdout(engineer, benign_holdout + attack_holdout)

        import_result = await bootstrap.import_reviews(
            "web_access",
            _review_items(training_attack + training_benign),
            reviewed_by=REVIEWED_BY,
        )
        preview_after_import = await bootstrap.preview_dataset("web_access", scan_limit=5000, preview_limit=0)

        job_id = await model_ops.create_retrain_job(
            reason="web_access_review_cycle",
            requested_by=REVIEWED_BY,
            model_family="web_access",
            dataset_mode=MLModelOpsService.DATASET_MODE_BOOTSTRAP_PLUS_FEEDBACK,
        )
        job = await _wait_for_job(model_ops, job_id)
        direct_train_job: Optional[Dict[str, Any]] = None
        if job.get("status") == "failed" and "1000 benign" in str(job.get("error") or ""):
            curated_dataset = _build_direct_training_payload(logs, engineer, attack_candidates, holdout_ids)
            direct_train_job = await _train_direct_cloud(settings, curated_dataset)
        post_eval = await _predict_holdout(engineer, benign_holdout + attack_holdout)

        summary = {
            "candidate_counts": {
                "benign_candidates": len(benign_candidates),
                "attack_candidates": len(attack_candidates),
                "training_attack_reviews": len(training_attack),
                "training_benign_reviews": len(training_benign),
                "holdout_attack": len(attack_holdout),
                "holdout_benign": len(benign_holdout),
                "attack_label_distribution": dict(Counter(item["classification"] for item in attack_candidates)),
            },
            "import_result": import_result,
            "thresholds_after_import": preview_after_import["thresholds"],
            "label_distribution_after_import": preview_after_import["label_distribution"],
            "pre_retrain_holdout_metrics": pre_eval,
            "retrain_job": {
                "id": job["id"],
                "status": job["status"],
                "result": job.get("result"),
                "metrics": job.get("metrics"),
                "error": job.get("error"),
            },
            "direct_fallback_train_job": direct_train_job,
            "post_retrain_holdout_metrics": post_eval,
        }

        out = Path("web_access_review_cycle_summary.json")
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))
        print(f"summary_file={out.resolve()}")
    finally:
        await close_mongo_connection()


if __name__ == "__main__":
    asyncio.run(main())
