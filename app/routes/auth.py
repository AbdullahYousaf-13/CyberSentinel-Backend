from fastapi import APIRouter, Depends, status

from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TokenResponse,
    UserResponse,
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
        created_at=user.get("created_at"),
        first_name=user.get("first_name"),
        last_name=user.get("last_name"),
    )


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, auth_service: AuthService = Depends(get_auth_service)) -> TokenResponse:
    token = await auth_service.authenticate(payload.email, payload.password, payload.totp_code)
    return TokenResponse(access_token=token)


@router.post("/2fa/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    current_user: UserResponse = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> TOTPSetupResponse:
    result = await auth_service.setup_totp(current_user.email)
    return TOTPSetupResponse(**result)


@router.post("/2fa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_2fa(
    payload: TOTPVerifyRequest,
    current_user: UserResponse = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> None:
    await auth_service.enable_totp(current_user.email, payload.totp_code)


@router.get("/me", response_model=UserResponse)
async def me(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    return current_user
