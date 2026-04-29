from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import Settings, get_settings
from app.core.email import send_email
from app.core.security import (
    build_totp_uri,
    create_access_token,
    generate_totp_secret,
    hash_password,
    validate_jwt,
    verify_password,
    verify_totp,
)
from app.db.repositories.user_repository import UserRepository
from app.services.notification_preferences import (
    VALID_FREQUENCIES,
    compute_next_digest_at,
    default_notification_prefs,
    ensure_valid_timezone,
    normalize_severities,
    sanitize_stored_notification_prefs,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._users = UserRepository()

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _build_email_verification_link(self, token: str) -> str:
        return f"{self._settings.frontend_base_url.rstrip('/')}/verify-email?token={token}"

    def _send_verification_email(self, email: str, token: str) -> None:
        link = self._build_email_verification_link(token)
        subject = "Verify your CyberSentinel account"
        body = (
            "Welcome to CyberSentinel!\n\n"
            "Please verify your email address by clicking the link below:\n"
            f"{link}\n\n"
            "If you did not create this account, you can ignore this email."
        )
        send_email(self._settings, email, subject, body)

    def _send_password_reset_email(self, email: str, code: str) -> None:
        subject = "CyberSentinel password reset code"
        body = (
            "We received a request to reset your CyberSentinel password.\n\n"
            f"Your reset code is: {code}\n\n"
            "This code expires soon. If you did not request this, you can ignore this email."
        )
        send_email(self._settings, email, subject, body)

    async def register_admin(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
    ) -> Dict[str, str]:
        if await self._users.count_users() > 0:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Admin already exists")
        verification_token = secrets.token_urlsafe(32)
        verification_hash = self._hash_token(verification_token)
        verification_expires_at = datetime.utcnow() + timedelta(
            minutes=self._settings.email_verify_ttl_minutes
        )
        user_payload = {
            "email": email,
            "password_hash": hash_password(password),
            "totp_secret": None,
            "is_2fa_enabled": False,
            "email_verified": False,
            "email_verification_token_hash": verification_hash,
            "email_verification_expires_at": verification_expires_at,
            "first_name": first_name,
            "last_name": last_name,
            "created_at": datetime.utcnow(),
            "notification_prefs": default_notification_prefs(datetime.utcnow()),
        }
        user_id = await self._users.create_user(user_payload)
        self._send_verification_email(email, verification_token)
        return {
            "id": user_id,
            "email": email,
            "created_at": user_payload["created_at"],
            "first_name": first_name,
            "last_name": last_name,
            "notification_prefs": user_payload["notification_prefs"],
        }

    async def authenticate(self, email: str, password: str, totp_code: Optional[str]) -> str:
        user = await self._users.get_by_email(email)
        if not user or not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if user.get("email_verified") is False:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
        if user.get("is_2fa_enabled"):
            if not totp_code or not verify_totp(totp_code, user["totp_secret"]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
        token = create_access_token({"sub": str(user["_id"]), "email": user["email"]}, self._settings)
        return token

    async def setup_totp(self, email: str) -> Dict[str, str]:
        user = await self._users.get_by_email(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if user.get("is_2fa_enabled"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="2FA already enabled")
        secret = generate_totp_secret()
        provisioning_uri = build_totp_uri(email, secret)
        await self._users._collection.update_one(
            {"_id": user["_id"]}, {"$set": {"totp_secret": secret}}
        )
        return {"totp_secret": secret, "provisioning_uri": provisioning_uri}

    async def enable_totp(self, email: str, code: str) -> None:
        user = await self._users.get_by_email(email)
        if not user or not user.get("totp_secret"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not verify_totp(code, user["totp_secret"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")
        await self._users._collection.update_one(
            {"_id": user["_id"]}, {"$set": {"is_2fa_enabled": True}}
        )

    async def disable_totp(self, email: str, code: str) -> None:
        user = await self._users.get_by_email(email)
        if not user or not user.get("totp_secret"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not verify_totp(code, user["totp_secret"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")
        await self._users._collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"is_2fa_enabled": False}, "$unset": {"totp_secret": ""}},
        )

    async def verify_email(self, token: str) -> None:
        token_hash = self._hash_token(token)
        user = await self._users._collection.find_one(
            {"email_verification_token_hash": token_hash}
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token")
        expires_at = user.get("email_verification_expires_at")
        if not expires_at or expires_at < datetime.utcnow():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification token expired")
        await self._users._collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {"email_verified": True},
                "$unset": {"email_verification_token_hash": "", "email_verification_expires_at": ""},
            },
        )

    async def request_password_reset(self, email: str) -> None:
        user = await self._users.get_by_email(email)
        if not user:
            return
        code = f"{secrets.randbelow(1000000):06d}"
        code_hash = self._hash_token(code)
        expires_at = datetime.utcnow() + timedelta(
            minutes=self._settings.password_reset_ttl_minutes
        )
        await self._users._collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_reset_code_hash": code_hash,
                    "password_reset_expires_at": expires_at,
                }
            },
        )
        self._send_password_reset_email(email, code)

    async def verify_password_reset_code(self, email: str, code: str) -> None:
        user = await self._users.get_by_email(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset code")
        code_hash = self._hash_token(code)
        if code_hash != user.get("password_reset_code_hash"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset code")
        expires_at = user.get("password_reset_expires_at")
        if not expires_at or expires_at < datetime.utcnow():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reset code expired")

    async def reset_password(self, email: str, code: str, new_password: str) -> None:
        await self.verify_password_reset_code(email, code)
        user = await self._users.get_by_email(email)
        await self._users._collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {"password_hash": hash_password(new_password)},
                "$unset": {"password_reset_code_hash": "", "password_reset_expires_at": ""},
            },
        )

    async def get_current_user(self, token: str) -> Dict[str, Any]:
        try:
            payload = validate_jwt(token, self._settings)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = await self._users.get_by_email(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        admin_rows = await self._users.list_users(limit=1)
        admin_email = str(admin_rows[0].get("email") or "").strip().lower() if admin_rows else ""
        is_admin = str(user.get("email") or "").strip().lower() == admin_email if admin_email else False
        prefs = sanitize_stored_notification_prefs(user.get("notification_prefs"), datetime.utcnow())
        return {
            "id": str(user["_id"]),
            "email": user["email"],
            "is_admin": is_admin,
            "is_2fa_enabled": user["is_2fa_enabled"],
            "email_verified": user.get("email_verified", True),
            "created_at": user["created_at"],
            "first_name": user.get("first_name"),
            "last_name": user.get("last_name"),
            "notification_prefs": prefs,
        }

    async def update_notification_preferences(
        self,
        email: str,
        email_enabled: bool,
        frequency: str,
        severities: list[str],
        timezone_name: str,
    ) -> Dict[str, Any]:
        user = await self._users.get_by_email(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if email_enabled and user.get("email_verified") is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email notifications require a verified email address",
            )

        normalized_frequency = str(frequency).strip().lower()
        if normalized_frequency not in VALID_FREQUENCIES:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid frequency")
        try:
            normalized_timezone = ensure_valid_timezone(timezone_name)
            normalized_severities = normalize_severities(severities)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        now_utc = datetime.utcnow()
        existing = sanitize_stored_notification_prefs(user.get("notification_prefs"), now_utc)
        if email_enabled and not normalized_severities:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="At least one severity must be selected when notifications are enabled",
            )
        effective_severities = normalized_severities or existing["severities"]

        next_digest_at = None
        if email_enabled and normalized_frequency == "daily":
            next_digest_at = compute_next_digest_at(now_utc, normalized_timezone)

        updated = {
            "email_enabled": email_enabled,
            "frequency": normalized_frequency,
            "severities": effective_severities,
            "timezone": normalized_timezone,
            "cursor_at": now_utc,
            "last_digest_sent_at": existing.get("last_digest_sent_at"),
            "next_digest_at": next_digest_at,
        }
        await self._users.update_notification_preferences(str(user["_id"]), updated)
        return updated


def get_auth_service(settings: Settings = Depends(get_settings)) -> AuthService:
    return AuthService(settings)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    auth_service: AuthService = Depends(get_auth_service),
) -> Dict[str, Any]:
    return await auth_service.get_current_user(token)


async def get_current_admin_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    This project currently uses a single-admin bootstrap model.
    The earliest created account is treated as the admin account.
    """
    repo = UserRepository()
    users = await repo.list_users(limit=1)
    if not users:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin account not found")
    admin_email = str(users[0].get("email") or "").strip().lower()
    current_email = str(current_user.get("email") or "").strip().lower()
    if not admin_email or current_email != admin_email:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user
