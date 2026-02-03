"""
Tests for Pydantic validation layer.

Verifies:
- Strict mode rejects implicit type coercion
- Extra fields are rejected
- Length limits are enforced
- Enum constraints work
"""

import pytest
from pydantic import ValidationError

from src.models.requests import (
    MetricCreateRequest,
    MetricUpdateRequest,
    UserUpdateRequest,
    MetricType,
    UserRole,
)


class TestMetricCreateValidation:
    """Tests for MetricCreateRequest validation."""
    
    def test_valid_metric_accepted(self):
        """Valid input should pass validation."""
        metric = MetricCreateRequest(
            name="request_count",
            metric_type=MetricType.COUNTER,
            value=42.0,
            description="Total requests",
            tags={"env": "prod"},
        )
        assert metric.name == "request_count"
        assert metric.value == 42.0
    
    def test_strict_mode_rejects_string_number(self):
        """Strict mode should reject '123' where float expected."""
        with pytest.raises(ValidationError) as exc_info:
            MetricCreateRequest(
                name="test",
                metric_type=MetricType.COUNTER,
                value="123",  # Should fail
            )
        assert "value" in str(exc_info.value)
    
    def test_name_length_limit(self):
        """Names over 64 chars should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            MetricCreateRequest(
                name="a" * 65,
                metric_type=MetricType.COUNTER,
                value=1.0,
            )
        assert "64" in str(exc_info.value) or "max_length" in str(exc_info.value)
    
    def test_name_requires_alphanumeric(self):
        """Names with special chars should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            MetricCreateRequest(
                name="test-metric",  # Hyphen not allowed
                metric_type=MetricType.COUNTER,
                value=1.0,
            )
        assert "alphanumeric" in str(exc_info.value)
    
    def test_extra_fields_forbidden(self):
        """Unknown fields should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            MetricCreateRequest(
                name="test",
                metric_type=MetricType.COUNTER,
                value=1.0,
                unknown_field="test",  # Should fail
            )
        assert "extra" in str(exc_info.value).lower()
    
    def test_invalid_metric_type_rejected(self):
        """Invalid enum values should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            MetricCreateRequest(
                name="test",
                metric_type="invalid_type",
                value=1.0,
            )
        assert "metric_type" in str(exc_info.value)
    
    def test_value_bounds_enforced(self):
        """Values outside bounds should be rejected."""
        with pytest.raises(ValidationError):
            MetricCreateRequest(
                name="test",
                metric_type=MetricType.GAUGE,
                value=1e16,  # Exceeds 1e15 limit
            )
    
    def test_tags_limit_enforced(self):
        """More than 10 tags should be rejected."""
        with pytest.raises(ValidationError):
            MetricCreateRequest(
                name="test",
                metric_type=MetricType.COUNTER,
                value=1.0,
                tags={f"key{i}": f"value{i}" for i in range(11)},
            )


class TestUserUpdateValidation:
    """Tests for UserUpdateRequest validation."""
    
    def test_valid_update_accepted(self):
        """Valid update should pass."""
        update = UserUpdateRequest(
            display_name="Alice",
            email="alice@example.com",
            role=UserRole.EDITOR,
        )
        assert update.email == "alice@example.com"
    
    def test_email_validation(self):
        """Invalid email format should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            UserUpdateRequest(email="not_an_email")
        assert "email" in str(exc_info.value).lower()
    
    def test_invalid_role_rejected(self):
        """Invalid role should be rejected."""
        with pytest.raises(ValidationError):
            UserUpdateRequest(role="superadmin")
    
    def test_extra_fields_forbidden(self):
        """Unknown fields should be rejected."""
        with pytest.raises(ValidationError):
            UserUpdateRequest(
                display_name="Alice",
                password="secret",  # Should fail
            )
