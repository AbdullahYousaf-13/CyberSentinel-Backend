from fastapi import APIRouter, Depends, HTTPException, status

from app.db.repositories.user_repository import UserRepository
from app.schemas.auth import UserResponse
from app.services.auth_service import get_current_user

router = APIRouter()


@router.get("/", response_model=list[UserResponse])
async def list_users(
    current_user: dict = Depends(get_current_user),
    limit: int = 50,
) -> list[UserResponse]:
    repo = UserRepository()
    users = await repo.list_users(limit=limit)
    response = []
    for user in users:
        response.append(
            UserResponse(
                id=str(user["_id"]),
                email=user["email"],
                is_2fa_enabled=user.get("is_2fa_enabled", False),
                created_at=user["created_at"],
            )
        )
    return response


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
) -> UserResponse:
    repo = UserRepository()
    user = await repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(
        id=str(user["_id"]),
        email=user["email"],
        is_2fa_enabled=user.get("is_2fa_enabled", False),
        created_at=user["created_at"],
    )
