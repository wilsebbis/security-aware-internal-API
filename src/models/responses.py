"""
Standardized response models.

Design principles:
- Consistent envelope structure
- No internal details in error responses
- Type-safe response construction
"""

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standard successful response envelope."""
    
    model_config = ConfigDict(strict=True)
    
    success: bool = True
    data: T
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    """
    Standard error response.
    
    Note: 'detail' is sanitized — never expose:
    - Stack traces
    - Internal paths
    - Database errors
    - Token values
    """
    
    model_config = ConfigDict(strict=True)
    
    success: bool = False
    error: str = Field(..., description="Error category")
    detail: str = Field(..., description="Human-readable (sanitized) message")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MetricResponse(BaseModel):
    """Metric data response."""
    
    model_config = ConfigDict(strict=True)
    
    id: str
    name: str
    metric_type: str
    value: float
    description: Optional[str] = None
    tags: Optional[dict[str, str]] = None
    created_at: datetime
    updated_at: datetime


class UserResponse(BaseModel):
    """User data response (sanitized)."""
    
    model_config = ConfigDict(strict=True)
    
    id: str
    display_name: str
    email: str
    role: str
    created_at: datetime
    last_active: Optional[datetime] = None
