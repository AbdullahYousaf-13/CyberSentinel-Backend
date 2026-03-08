from functools import lru_cache
from typing import Optional

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    app_env: str = Field("dev", env="APP_ENV")
    debug_mode: bool = Field(False, env="DEBUG_MODE")
    detailed_logging: bool = Field(False, env="DETAILED_LOGGING")

    mongo_uri: str = Field("", env="MONGO_URI")
    mongo_db: str = Field("cybersentinel", env="MONGO_DB")

    jwt_secret: str = Field("change_me", env="JWT_SECRET")
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    jwt_exp_minutes: int = Field(60, env="JWT_EXP_MINUTES")

    kafka_enabled: bool = Field(False, env="KAFKA_ENABLED")
    kafka_bootstrap_servers: str = Field("", env="KAFKA_BOOTSTRAP_SERVERS")
    kafka_topic: str = Field("cybersentinel-logs", env="KAFKA_TOPIC")
    kafka_group_id: str = Field("cybersentinel-backend", env="KAFKA_GROUP_ID")
    wazuh_ingest_key: Optional[str] = Field(None, env="WAZUH_INGEST_KEY")

    model_dir: str = Field("app/ml/models", env="MODEL_DIR")
    model_integrity_required: bool = Field(True, env="MODEL_INTEGRITY_REQUIRED")
    anomaly_score_threshold: float = Field(0.65, env="ANOMALY_SCORE_THRESHOLD")

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
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
