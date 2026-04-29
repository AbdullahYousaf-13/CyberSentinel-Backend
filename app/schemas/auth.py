from datetime import datetime
from typing import Literal, Optional

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


class TOTPDisableRequest(BaseModel):
    totp_code: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyResetCodeRequest(BaseModel):
    email: EmailStr
    code: str


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


class EmailVerifyResponse(BaseModel):
    verified: bool


class NotificationPreferencesResponse(BaseModel):
    email_enabled: bool
    frequency: Literal["immediate", "daily"]
    severities: list[Literal["high", "medium", "low"]]
    timezone: str
    cursor_at: datetime
    last_digest_sent_at: Optional[datetime] = None
    next_digest_at: Optional[datetime] = None


class NotificationPreferencesUpdateRequest(BaseModel):
    email_enabled: bool
    frequency: Literal["immediate", "daily"]
    severities: list[Literal["high", "medium", "low"]]
    timezone: str


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    is_admin: bool = False
    is_2fa_enabled: bool
    email_verified: bool = False
    created_at: datetime
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    notification_prefs: NotificationPreferencesResponse
