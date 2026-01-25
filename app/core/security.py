from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import pyotp
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import Settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: Dict[str, Any], settings: Settings, exp_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=exp_minutes or settings.jwt_exp_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str, settings: Settings) -> Dict[str, Any]:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_totp_uri(email: str, secret: str, issuer: str = "CyberSentinel") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(code: str, secret: str) -> bool:
    return pyotp.TOTP(secret).verify(code)


def validate_jwt(token: str, settings: Settings) -> Dict[str, Any]:
    try:
        return decode_access_token(token, settings)
    except JWTError as exc:
        raise ValueError("Invalid token") from exc
