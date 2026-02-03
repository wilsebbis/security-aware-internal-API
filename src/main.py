"""
Security-Aware Internal API

Main application with:
- Security middleware
- Validation error handling with penalty escalation
- Sanitized error responses
- Request logging
"""

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.logging import get_security_logger
from src.middleware import get_rate_limiter
from src.models import ErrorResponse
from src.routes import metrics_router, users_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan manager."""
    logger = get_security_logger()
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title="Security-Aware Internal API",
    description="Internal API with hostile-input assumptions",
    version="0.1.0",
    lifespan=lifespan,
    # CORS disabled — internal API
    # docs_url=None,  # Uncomment for production
    # redoc_url=None,  # Uncomment for production
)


# ─── Exception Handlers ──────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """
    Handle Pydantic validation errors.
    
    Security actions:
    1. Log validation failure with field info (not values)
    2. Apply rate limit penalty for malformed input
    3. Return sanitized error (no internal details)
    """
    logger = get_security_logger()
    limiter = get_rate_limiter()
    
    # Extract token hash if available
    token_hash = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        import hashlib
        token = auth_header[7:]
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    
    # Log validation failure (field names only, no values)
    error_fields = [
        ".".join(str(loc) for loc in err.get("loc", []))
        for err in exc.errors()
    ]
    
    logger.log_validation_failure(
        token_hash=token_hash,
        route=request.url.path,
        error_count=len(exc.errors()),
        error_fields=error_fields,
    )
    
    # Apply penalty if authenticated
    if token_hash:
        try:
            limiter.record_malformed_request(
                token_hash=token_hash,
                reason="validation_failure",
            )
        except Exception:
            # Already blocked — let the 429 propagate
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content=ErrorResponse(
                    error="rate_limited",
                    detail="Temporarily blocked due to repeated malformed requests",
                ).model_dump(mode="json"),
            )
    
    # Return sanitized error
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error="validation_error",
            detail=f"Request validation failed: {len(exc.errors())} error(s)",
        ).model_dump(mode="json"),
    )


# ─── Middleware ──────────────────────────────────────────────────────────

@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log all requests with timing."""
    logger = get_security_logger()
    start_time = time.time()
    
    response = await call_next(request)
    
    duration_ms = (time.time() - start_time) * 1000
    
    # Extract token hash for logging
    token_hash = "<anonymous>"
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        import hashlib
        token = auth_header[7:]
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    
    logger.log_request(
        token_hash=token_hash,
        method=request.method,
        route=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    
    return response


# ─── Routes ──────────────────────────────────────────────────────────────

app.include_router(metrics_router)
app.include_router(users_router)


@app.get("/health")
async def health_check():
    """Health check endpoint — no auth required."""
    return {"status": "healthy"}
