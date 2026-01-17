from datetime import datetime
from typing import Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import Settings, get_settings
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._users = UserRepository()

    async def register_admin(self, email: str, password: str) -> Dict[str, str]:
        if await self._users.count_users() > 0:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Admin already exists")
        user_payload = {
            "email": email,
            "password_hash": hash_password(password),
            "totp_secret": None,
            "is_2fa_enabled": False,
            "created_at": datetime.utcnow(),
        }
        user_id = await self._users.create_user(user_payload)
        return {"id": user_id, "email": email, "created_at": user_payload["created_at"]}

    async def authenticate(self, email: str, password: str, totp_code: Optional[str]) -> str:
        user = await self._users.get_by_email(email)
        if not user or not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
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

    async def get_current_user(self, token: str) -> Dict[str, str]:
        payload = validate_jwt(token, self._settings)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = await self._users.get_by_email(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {
            "id": str(user["_id"]),
            "email": user["email"],
            "is_2fa_enabled": user["is_2fa_enabled"],
            "created_at": user["created_at"],
        }


def get_auth_service(settings: Settings = Depends(get_settings)) -> AuthService:
    return AuthService(settings)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    auth_service: AuthService = Depends(get_auth_service),
) -> Dict[str, str]:
    return await auth_service.get_current_user(token)
