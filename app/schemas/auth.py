from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TOTPSetupResponse(BaseModel):
    totp_secret: str
    provisioning_uri: str


class TOTPVerifyRequest(BaseModel):
    totp_code: str


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    is_2fa_enabled: bool
    created_at: datetime
    first_name: Optional[str] = None
    last_name: Optional[str] = None
