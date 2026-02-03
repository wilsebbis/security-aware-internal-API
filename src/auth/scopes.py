"""
Scope definitions and route-level guards.

Design principle: Tokens are CAPABILITIES, not identities.
Each scope grants specific, minimal permissions.
No implicit privilege inheritance.
"""

from enum import Enum
from typing import Callable
from fastapi import HTTPException, status, Depends


class Scope(str, Enum):
    """
    Explicit scope definitions.
    
    Naming convention: action:resource
    No hierarchical inheritance — read:metrics does NOT imply write:metrics.
    """
    READ_METRICS = "read:metrics"
    WRITE_METRICS = "write:metrics"
    READ_USERS = "read:users"
    ADMIN_USERS = "admin:users"


def require_scope(*required_scopes: Scope) -> Callable:
    """
    Dependency factory for route-level scope guards.
    
    Usage:
        @router.get("/metrics", dependencies=[Depends(require_scope(Scope.READ_METRICS))])
        async def get_metrics():
            ...
    
    Security model:
        - Token must have ALL required scopes
        - Missing scope = 403 Forbidden (not 401)
        - Logs scope check result for forensics
    """
    from .oauth import get_current_token, TokenPayload
    from src.logging.security_logger import get_security_logger
    
    async def scope_guard(token: TokenPayload = Depends(get_current_token)) -> TokenPayload:
        logger = get_security_logger()
        
        missing_scopes = [s.value for s in required_scopes if s.value not in token.scopes]
        
        if missing_scopes:
            logger.log_authorization_failure(
                token_hash=token.token_hash,
                required_scopes=[s.value for s in required_scopes],
                provided_scopes=token.scopes,
                missing_scopes=missing_scopes,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient scope",
                headers={"WWW-Authenticate": f'Bearer scope="{" ".join(s.value for s in required_scopes)}"'},
            )
        
        logger.log_authorization_success(
            token_hash=token.token_hash,
            scopes_used=[s.value for s in required_scopes],
        )
        return token
    
    return scope_guard
