"""
Strict request models with hostile-input assumptions.

Design principles:
- strict=True: No implicit type coercion
- extra="forbid": Reject unknown fields
- Explicit length limits on all strings
- Enum constraints for categorical fields
"""

from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ─── Enums ───────────────────────────────────────────────────────────────

class MetricType(str, Enum):
    """Allowed metric types — categorical constraint."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class UserRole(str, Enum):
    """Allowed user roles — categorical constraint."""
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


# ─── Strict String Types ─────────────────────────────────────────────────

# Constrained string types to prevent oversized inputs
ShortString = Annotated[str, Field(min_length=1, max_length=64)]
MediumString = Annotated[str, Field(min_length=1, max_length=256)]
LongString = Annotated[str, Field(min_length=1, max_length=1024)]


# ─── Request Models ──────────────────────────────────────────────────────

class MetricCreateRequest(BaseModel):
    """
    Request to create a new metric.
    
    All fields are strictly validated:
    - name: 1-64 chars, alphanumeric + underscore only
    - metric_type: Must be valid enum value
    - description: Optional, max 256 chars
    - value: Must be finite number
    - tags: Optional dict, max 10 entries
    """
    
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )
    
    name: ShortString = Field(
        ...,
        description="Metric name (alphanumeric + underscore only)",
        examples=["request_count", "memory_usage_mb"],
    )
    metric_type: MetricType
    description: Optional[MediumString] = None
    value: float = Field(..., ge=-1e15, le=1e15)  # Prevent infinity
    tags: Optional[dict[str, str]] = Field(default=None, max_length=10)
    
    @field_validator("metric_type", mode="before")
    @classmethod
    def coerce_metric_type(cls, v):
        """Allow string values for enum from JSON."""
        if isinstance(v, str):
            try:
                return MetricType(v)
            except ValueError:
                raise ValueError(f"invalid metric_type: {v}")
        return v
    
    @field_validator("name")
    @classmethod
    def validate_name_chars(cls, v: str) -> str:
        """Only allow ASCII alphanumeric + underscore in metric names."""
        # Use explicit ASCII check to prevent Unicode homoglyph attacks
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("name must be ASCII alphanumeric with underscores only")
        return v
    
    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: Optional[dict[str, str]]) -> Optional[dict[str, str]]:
        """Validate tag keys and values."""
        if v is None:
            return v
        for key, value in v.items():
            if len(key) > 32 or len(value) > 64:
                raise ValueError("tag key max 32 chars, value max 64 chars")
            if not key.replace("_", "").isalnum():
                raise ValueError("tag keys must be alphanumeric with underscores")
        return v


class MetricUpdateRequest(BaseModel):
    """Request to update an existing metric."""
    
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        str_strip_whitespace=True,
    )
    
    value: Optional[float] = Field(None, ge=-1e15, le=1e15)
    description: Optional[MediumString] = None
    tags: Optional[dict[str, str]] = Field(default=None, max_length=10)
    
    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: Optional[dict[str, str]]) -> Optional[dict[str, str]]:
        if v is None:
            return v
        for key, value in v.items():
            if len(key) > 32 or len(value) > 64:
                raise ValueError("tag key max 32 chars, value max 64 chars")
        return v


class UserUpdateRequest(BaseModel):
    """
    Request to update user attributes.
    Only admin scope can modify role.
    """
    
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        str_strip_whitespace=True,
    )
    
    display_name: Optional[ShortString] = None
    email: Optional[MediumString] = None
    role: Optional[UserRole] = None
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        """Email format validation with ASCII enforcement."""
        if v is None:
            return v
        # Reject non-ASCII characters (homoglyph attack prevention)
        if not v.isascii():
            raise ValueError("email must contain only ASCII characters")
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("invalid email format")
        return v.lower()


class RequestContext(BaseModel):
    """
    Internal context passed through request lifecycle.
    Not exposed to clients.
    """
    
    model_config = ConfigDict(strict=True)
    
    token_hash: str
    subject: str
    scopes: list[str]
    validation_failed: bool = False
    validation_error_count: int = 0
