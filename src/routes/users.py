"""
Users API routes with scope-guarded access.

# SECURITY BOUNDARY:
# Do not assume caller identity is trustworthy.
# admin:users does NOT inherit from read:users — each checked explicitly.
# All inputs validated with hostile assumptions.

Demonstrates:
- Hierarchical scope model (read:users vs admin:users)
- No implicit privilege inheritance
- Strict input validation on updates
"""

import uuid
from datetime import UTC, datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from src.auth import TokenPayload, Scope, get_current_token, require_scope
from src.logging import get_security_logger
from src.middleware import get_rate_limiter
from src.models import APIResponse, UserResponse, UserUpdateRequest


router = APIRouter(prefix="/users", tags=["users"])

# In-memory store (production would use proper storage)
_users_store: dict[str, dict] = {
    "user-001": {
        "id": "user-001",
        "display_name": "Alice Service",
        "email": "alice@internal.example",
        "role": "editor",
        "created_at": datetime(2024, 1, 1),
        "last_active": datetime(2024, 1, 15),
    },
    "user-002": {
        "id": "user-002",
        "display_name": "Bob Service",
        "email": "bob@internal.example",
        "role": "viewer",
        "created_at": datetime(2024, 1, 5),
        "last_active": None,
    },
}


@router.get(
    "",
    response_model=APIResponse[list[UserResponse]],
    dependencies=[Depends(require_scope(Scope.READ_USERS))],
)
async def list_users(
    token: TokenPayload = Depends(get_current_token),
    limit: int = 50,
    offset: int = 0,
) -> APIResponse[list[UserResponse]]:
    """
    List all users.
    
    Requires: read:users scope
    """
    limiter = get_rate_limiter()
    limiter.check_rate_limit(token.token_hash, "/users")
    
    users = list(_users_store.values())[offset:offset + limit]
    return APIResponse(
        data=[UserResponse(**u) for u in users],
    )


@router.get(
    "/{user_id}",
    response_model=APIResponse[UserResponse],
    dependencies=[Depends(require_scope(Scope.READ_USERS))],
)
async def get_user(
    user_id: str,
    token: TokenPayload = Depends(get_current_token),
) -> APIResponse[UserResponse]:
    """
    Get a specific user by ID.
    
    Requires: read:users scope
    """
    limiter = get_rate_limiter()
    limiter.check_rate_limit(token.token_hash, "/users")
    
    user = _users_store.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    return APIResponse(data=UserResponse(**user))


@router.put(
    "/{user_id}",
    response_model=APIResponse[UserResponse],
    dependencies=[Depends(require_scope(Scope.ADMIN_USERS))],
)
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    token: TokenPayload = Depends(get_current_token),
) -> APIResponse[UserResponse]:
    """
    Update user attributes.
    
    Requires: admin:users scope
    
    Security note: Only admin scope can modify users.
    read:users scope is NOT sufficient — scopes do not inherit.
    """
    logger = get_security_logger()
    limiter = get_rate_limiter()
    
    limiter.check_rate_limit(token.token_hash, "/users")
    
    user = _users_store.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    logger.log_validation_success(
        token_hash=token.token_hash,
        route=f"/users/{user_id}",
        model="UserUpdateRequest",
    )
    
    # Update only provided fields
    if body.display_name is not None:
        user["display_name"] = body.display_name
    if body.email is not None:
        user["email"] = body.email
    if body.role is not None:
        user["role"] = body.role.value
    user["last_active"] = datetime.now(UTC)
    
    return APIResponse(data=UserResponse(**user))
