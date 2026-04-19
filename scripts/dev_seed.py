from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List

from pymongo import MongoClient

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.core.config import get_settings
from app.core.security import create_access_token, hash_password
from app.db.mongo import resolve_mongo_uri


def ensure_admin_user(db, email: str, password: str) -> Dict[str, Any]:
    users = db.get_collection("user")
    existing = users.find_one({"email": email})
    if existing:
        return existing
    payload = {
        "email": email,
        "password_hash": hash_password(password),
        "totp_secret": None,
        "is_2fa_enabled": False,
        "email_verified": True,
        "created_at": datetime.utcnow(),
    }
    result = users.insert_one(payload)
    payload["_id"] = result.inserted_id
    return payload


def build_seed_alerts(count: int) -> List[Dict[str, Any]]:
    templates = [
        {
            "alert_type": "brute_force",
            "severity": "high",
            "classification": "credential_attack",
            "anomaly_score": 0.12,
            "metadata": {"ip": "10.0.0.12", "username": "admin", "source": "auth", "tags": ["seed"]},
        },
        {
            "alert_type": "anomaly",
            "severity": "medium",
            "classification": None,
            "anomaly_score": 0.81,
            "metadata": {"ip": "10.0.0.22", "source": "endpoint", "hostname": "ws-07", "tags": ["seed"]},
        },
        {
            "alert_type": "malware",
            "severity": "critical",
            "classification": "ransomware",
            "anomaly_score": 0.94,
            "metadata": {"ip": "10.0.0.33", "source": "edr", "hostname": "fs-02", "tags": ["seed"]},
        },
        {
            "alert_type": "policy_violation",
            "severity": "low",
            "classification": "access_policy",
            "anomaly_score": 0.22,
            "metadata": {"ip": "10.0.0.44", "source": "proxy", "hostname": "lt-11", "tags": ["seed"]},
        },
    ]
    alerts: List[Dict[str, Any]] = []
    now = datetime.utcnow()
    for index in range(count):
        template = templates[index % len(templates)]
        alerts.append(
            {
                "created_at": now - timedelta(minutes=index * 5),
                "log_id": f"seed-log-{index + 1}",
                "alert_type": template["alert_type"],
                "severity": template["severity"],
                "classification": template["classification"],
                "anomaly_score": template["anomaly_score"],
                "model_version": "dev-seed-v1",
                "metadata": template["metadata"],
            }
        )
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed a dev admin user and sample alerts.")
    parser.add_argument("--email", default="admin@example.com", help="Admin email.")
    parser.add_argument("--password", default="ChangeMe123!", help="Admin password.")
    parser.add_argument("--alerts", type=int, default=12, help="Number of alerts to insert.")
    parser.add_argument("--token-days", type=int, default=60, help="Token lifetime in days.")
    args = parser.parse_args()

    settings = get_settings()
    client = MongoClient(resolve_mongo_uri(settings))
    db = client[settings.mongo_db]

    user = ensure_admin_user(db, args.email, args.password)
    token_minutes = args.token_days * 24 * 60
    token = create_access_token(
        {"sub": str(user["_id"]), "email": user["email"]},
        settings,
        exp_minutes=token_minutes,
    )

    alert_docs = build_seed_alerts(args.alerts)
    if alert_docs:
        db.get_collection("alerts").insert_many(alert_docs)

    expires_at = datetime.utcnow() + timedelta(days=args.token_days)
    print("Dev seed complete.")
    print(f"Admin email: {user['email']}")
    print(f"Token expires: {expires_at.isoformat()}Z")
    print("Access token:")
    print(token)
    if settings.jwt_secret == "change_me":
        print("Warning: JWT_SECRET is still the default 'change_me'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
