from fastapi import APIRouter, Depends, status

from app.schemas.auth import (
    EmailVerifyResponse,
    ForgotPasswordRequest,
    LoginRequest,
    NotificationPreferencesResponse,
    NotificationPreferencesUpdateRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TOTPDisableRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TokenResponse,
    UserResponse,
    VerifyResetCodeRequest,
)
from app.services.auth_service import AuthService, get_auth_service, get_current_user

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_admin(payload: RegisterRequest, auth_service: AuthService = Depends(get_auth_service)) -> UserResponse:
    user = await auth_service.register_admin(
        payload.email,
        payload.password,
        payload.first_name,
        payload.last_name,
    )
    return UserResponse(
        id=user["id"],
        email=user["email"],
        is_2fa_enabled=False,
        email_verified=False,
        created_at=user.get("created_at"),
        first_name=user.get("first_name"),
        last_name=user.get("last_name"),
        notification_prefs=user["notification_prefs"],
    )


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, auth_service: AuthService = Depends(get_auth_service)) -> TokenResponse:
    token = await auth_service.authenticate(payload.email, payload.password, payload.totp_code)
    return TokenResponse(access_token=token)


@router.post("/2fa/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> TOTPSetupResponse:
    result = await auth_service.setup_totp(current_user["email"])
    return TOTPSetupResponse(**result)


@router.post("/2fa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_2fa(
    payload: TOTPVerifyRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> None:
    await auth_service.enable_totp(current_user["email"], payload.totp_code)


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_2fa(
    payload: TOTPDisableRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> None:
    await auth_service.disable_totp(current_user["email"], payload.totp_code)


@router.get("/verify-email", response_model=EmailVerifyResponse)
async def verify_email(token: str, auth_service: AuthService = Depends(get_auth_service)) -> EmailVerifyResponse:
    await auth_service.verify_email(token)
    return EmailVerifyResponse(verified=True)


@router.post("/password/forgot", status_code=status.HTTP_204_NO_CONTENT)
async def forgot_password(
    payload: ForgotPasswordRequest, auth_service: AuthService = Depends(get_auth_service)
) -> None:
    await auth_service.request_password_reset(payload.email)


@router.post("/password/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_reset_code(
    payload: VerifyResetCodeRequest, auth_service: AuthService = Depends(get_auth_service)
) -> None:
    await auth_service.verify_password_reset_code(payload.email, payload.code)


@router.post("/password/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    payload: ResetPasswordRequest, auth_service: AuthService = Depends(get_auth_service)
) -> None:
    await auth_service.reset_password(payload.email, payload.code, payload.new_password)


@router.get("/me", response_model=UserResponse)
async def me(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    return current_user


@router.patch("/me/notification-preferences", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    payload: NotificationPreferencesUpdateRequest,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> NotificationPreferencesResponse:
    updated = await auth_service.update_notification_preferences(
        email=current_user["email"],
        email_enabled=payload.email_enabled,
        frequency=payload.frequency,
        severities=payload.severities,
        timezone_name=payload.timezone,
    )
    return NotificationPreferencesResponse(**updated)
