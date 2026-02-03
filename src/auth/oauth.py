"""
OAuth2/JWT token validation.

Security principles:
- Tokens are validated, not trusted
- Token hash logged, never raw token
- Explicit issuer/audience validation
- Expiration strictly enforced
"""

import hashlib
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel, Field

from src.logging.security_logger import get_security_logger


# Configuration — in production, load from secure config
JWT_SECRET = os.getenv("JWT_SECRET", "INSECURE_DEV_SECRET_CHANGE_IN_PROD")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "security-aware-api")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "internal-services")


class TokenPayload(BaseModel):
    """Validated token payload with security metadata."""
    sub: str = Field(..., description="Subject/service identifier")
    scopes: list[str] = Field(default_factory=list, description="Granted scopes")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued-at timestamp")
    iss: str = Field(..., description="Token issuer")
    aud: str = Field(..., description="Intended audience")
    token_hash: str = Field(..., description="SHA-256 hash of token for logging")


# Bearer token extractor
bearer_scheme = HTTPBearer(auto_error=False)


def _hash_token(token: str) -> str:
    """Generate SHA-256 hash of token for forensic logging."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


async def get_current_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TokenPayload:
    """
    Validate JWT and extract payload.
    
    Security checks:
    1. Token presence
    2. Signature validity
    3. Expiration
    4. Issuer match
    5. Audience match
    """
    logger = get_security_logger()
    
    if credentials is None:
        logger.log_authentication_failure(
            reason="missing_token",
            token_hash=None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    token_hash = _hash_token(token)
    
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
    except JWTError as e:
        logger.log_authentication_failure(
            reason="invalid_token",
            token_hash=token_hash,
            error_type=type(e).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Validate expiration explicitly (belt and suspenders)
    exp = payload.get("exp", 0)
    if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(tz=timezone.utc):
        logger.log_authentication_failure(
            reason="expired_token",
            token_hash=token_hash,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Build validated payload
    validated = TokenPayload(
        sub=payload.get("sub", "unknown"),
        scopes=payload.get("scopes", []),
        exp=exp,
        iat=payload.get("iat", 0),
        iss=payload.get("iss", ""),
        aud=payload.get("aud", ""),
        token_hash=token_hash,
    )
    
    logger.log_authentication_success(
        token_hash=token_hash,
        subject=validated.sub,
        scopes=validated.scopes,
    )
    
    return validated


def create_test_token(
    sub: str,
    scopes: list[str],
    exp_minutes: int = 60,
) -> str:
    """
    Create a test token for development/testing.
    NOT FOR PRODUCTION USE.
    """
    from datetime import timedelta
    
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": sub,
        "scopes": scopes,
        "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
