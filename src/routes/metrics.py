"""
Metrics API routes with scope-guarded access.

Demonstrates:
- Scope-based authorization (read:metrics vs write:metrics)
- Strict input validation
- Rate limiting integration
- Security logging
"""

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from src.auth import TokenPayload, Scope, get_current_token, require_scope
from src.logging import get_security_logger
from src.middleware import get_rate_limiter
from src.models import (
    APIResponse,
    ErrorResponse,
    MetricCreateRequest,
    MetricResponse,
    MetricUpdateRequest,
)


router = APIRouter(prefix="/metrics", tags=["metrics"])

# In-memory store (production would use proper storage)
_metrics_store: dict[str, dict] = {}


@router.get(
    "",
    response_model=APIResponse[list[MetricResponse]],
    dependencies=[Depends(require_scope(Scope.READ_METRICS))],
)
async def list_metrics(
    request: Request,
    token: TokenPayload = Depends(get_current_token),
    limit: int = 100,
    offset: int = 0,
) -> APIResponse[list[MetricResponse]]:
    """
    List all metrics.
    
    Requires: read:metrics scope
    Rate limited: 120 req/min
    """
    limiter = get_rate_limiter()
    limiter.check_rate_limit(token.token_hash, "/metrics")
    
    metrics = list(_metrics_store.values())[offset:offset + limit]
    return APIResponse(
        data=[MetricResponse(**m) for m in metrics],
    )


@router.get(
    "/{metric_id}",
    response_model=APIResponse[MetricResponse],
    dependencies=[Depends(require_scope(Scope.READ_METRICS))],
)
async def get_metric(
    metric_id: str,
    token: TokenPayload = Depends(get_current_token),
) -> APIResponse[MetricResponse]:
    """
    Get a specific metric by ID.
    
    Requires: read:metrics scope
    """
    limiter = get_rate_limiter()
    limiter.check_rate_limit(token.token_hash, "/metrics")
    
    metric = _metrics_store.get(metric_id)
    if not metric:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metric not found",
        )
    
    return APIResponse(data=MetricResponse(**metric))


@router.post(
    "",
    response_model=APIResponse[MetricResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope(Scope.WRITE_METRICS))],
)
async def create_metric(
    request: Request,
    body: MetricCreateRequest,
    token: TokenPayload = Depends(get_current_token),
) -> APIResponse[MetricResponse]:
    """
    Create a new metric.
    
    Requires: write:metrics scope
    Validates: Strict Pydantic model with type/length constraints
    """
    logger = get_security_logger()
    limiter = get_rate_limiter()
    
    limiter.check_rate_limit(token.token_hash, "/metrics")
    
    # Log successful validation
    logger.log_validation_success(
        token_hash=token.token_hash,
        route="/metrics",
        model="MetricCreateRequest",
    )
    
    # Create metric
    now = datetime.utcnow()
    metric = {
        "id": str(uuid.uuid4()),
        "name": body.name,
        "metric_type": body.metric_type,  # Already a string due to use_enum_values
        "value": body.value,
        "description": body.description,
        "tags": body.tags,
        "created_at": now,
        "updated_at": now,
    }
    
    _metrics_store[metric["id"]] = metric
    
    return APIResponse(data=MetricResponse(**metric))


@router.patch(
    "/{metric_id}",
    response_model=APIResponse[MetricResponse],
    dependencies=[Depends(require_scope(Scope.WRITE_METRICS))],
)
async def update_metric(
    metric_id: str,
    body: MetricUpdateRequest,
    token: TokenPayload = Depends(get_current_token),
) -> APIResponse[MetricResponse]:
    """
    Update an existing metric.
    
    Requires: write:metrics scope
    """
    logger = get_security_logger()
    limiter = get_rate_limiter()
    
    limiter.check_rate_limit(token.token_hash, "/metrics")
    
    metric = _metrics_store.get(metric_id)
    if not metric:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metric not found",
        )
    
    logger.log_validation_success(
        token_hash=token.token_hash,
        route=f"/metrics/{metric_id}",
        model="MetricUpdateRequest",
    )
    
    # Update only provided fields
    if body.value is not None:
        metric["value"] = body.value
    if body.description is not None:
        metric["description"] = body.description
    if body.tags is not None:
        metric["tags"] = body.tags
    metric["updated_at"] = datetime.utcnow()
    
    return APIResponse(data=MetricResponse(**metric))
