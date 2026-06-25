import os
from functools import lru_cache
from pathlib import Path
from typing import Optional
from pydantic import BaseSettings, Field

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_ENV_FILE = _PROJECT_ROOT / ".env"

class Settings(BaseSettings):
    app_env: str = Field("dev", env="APP_ENV")
    debug_mode: bool = Field(False, env="DEBUG_MODE")
    detailed_logging: bool = Field(False, env="DETAILED_LOGGING")

    mongo_uri: Optional[str] = Field(None, env="MONGO_URI")
    mongo_user: str = Field("", env="MONGO_USER")
    mongo_password: str = Field("", env="MONGO_PASSWORD")
    mongo_host: str = Field("", env="MONGO_HOST")
    mongo_db: str = Field("cybersentinel", env="MONGO_DB")

    jwt_secret: str = Field("change_me", env="JWT_SECRET")
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    jwt_exp_minutes: int = Field(60, env="JWT_EXP_MINUTES")

    wazuh_ingest_key: Optional[str] = Field(None, env="WAZUH_INGEST_KEY")

    # Legacy local-model settings kept for backward env compatibility.
    model_dir: str = Field("app/ml/models", env="MODEL_DIR")
    model_integrity_required: bool = Field(True, env="MODEL_INTEGRITY_REQUIRED")
    anomaly_score_threshold: float = Field(0.65, env="ANOMALY_SCORE_THRESHOLD")
    model_api_url: Optional[str] = Field(None, env="MODEL_API_URL")
    model_api_timeout_seconds: int = Field(10, env="MODEL_API_TIMEOUT_SECONDS")
    model_admin_token: Optional[str] = Field(None, env="MODEL_ADMIN_TOKEN")
    raw_wazuh_training_path: str = Field(
        "C:/Users/anumy/Downloads/cybersentinel_raw_wazuh_logs.json",
        env="RAW_WAZUH_TRAINING_PATH",
    )
    retrain_raw_wazuh_db_limit: int = Field(50000, env="RETRAIN_RAW_WAZUH_DB_LIMIT")
    min_samples_per_attack_class: int = Field(50, env="MIN_SAMPLES_PER_ATTACK_CLASS")
    raw_wazuh_worker_concurrency: int = Field(4, env="RAW_WAZUH_WORKER_CONCURRENCY")

    agent_service_url: Optional[str] = Field(None, env="AGENT_SERVICE_URL")
    agent_timeout_seconds: int = Field(10, env="AGENT_TIMEOUT_SECONDS")

    cors_allow_origins: str = Field(
        "http://localhost:3000,http://127.0.0.1:3000", env="CORS_ALLOW_ORIGINS"
    )
    frontend_base_url: str = Field("http://localhost:3000", env="FRONTEND_BASE_URL")

    smtp_host: Optional[str] = Field(None, env="SMTP_HOST")
    smtp_port: int = Field(587, env="SMTP_PORT")
    smtp_user: Optional[str] = Field(None, env="SMTP_USER")
    smtp_password: Optional[str] = Field(None, env="SMTP_PASSWORD")
    smtp_use_tls: bool = Field(True, env="SMTP_USE_TLS")
    smtp_use_ssl: bool = Field(False, env="SMTP_USE_SSL")
    email_from: str = Field("no-reply@cybersentinel.local", env="EMAIL_FROM")
    email_verify_ttl_minutes: int = Field(60 * 24, env="EMAIL_VERIFY_TTL_MINUTES")
    password_reset_ttl_minutes: int = Field(15, env="PASSWORD_RESET_TTL_MINUTES")

    class Config:
        env_file = str(_DEFAULT_ENV_FILE) if _DEFAULT_ENV_FILE.is_file() else ".env"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    # Empty OS env var overrides .env in pydantic BaseSettings; treat as unset so .env can load.
    if os.environ.get("MONGO_URI") == "":
        os.environ.pop("MONGO_URI", None)
    if os.environ.get("WAZUH_INGEST_KEY") == "":
        os.environ.pop("WAZUH_INGEST_KEY", None)
    if os.environ.get("MODEL_API_URL") == "":
        os.environ.pop("MODEL_API_URL", None)
    return Settings()
