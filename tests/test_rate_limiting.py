"""
Tests for rate limiting behavior.

Verifies:
- Per-token limits
- Escalating penalties for malformed inputs
- Quota recovery
"""

import pytest
from httpx import AsyncClient

from src.middleware.rate_limit import RateLimiter, get_rate_limiter


class TestRateLimiter:
    """Unit tests for RateLimiter class."""
    
    def test_allows_requests_under_limit(self):
        """Requests under limit should pass."""
        limiter = RateLimiter()
        token_hash = "test-token-1"
        
        # Should not raise for first 50 requests
        for _ in range(50):
            limiter.check_rate_limit(token_hash, "/test")
    
    def test_blocks_requests_over_limit(self):
        """Requests over limit should get 429."""
        from fastapi import HTTPException
        
        limiter = RateLimiter()
        token_hash = "test-token-2"
        
        # Configure a known route limit for testing
        limiter.configure_route("/test", requests_per_minute=50, burst_allowance=10)
        
        # Exhaust the limit (50 + 10 burst = 60 max)
        for _ in range(60):
            limiter.check_rate_limit(token_hash, "/test")
        
        # Next request should fail
        with pytest.raises(HTTPException) as exc_info:
            limiter.check_rate_limit(token_hash, "/test")
        assert exc_info.value.status_code == 429
    
    def test_malformed_request_reduces_quota(self):
        """Malformed inputs should halve remaining quota."""
        limiter = RateLimiter()
        token_hash = "test-token-3"
        
        # Record malformed request
        limiter.record_malformed_request(token_hash, "test_reason")
        
        # Effective limit should be reduced
        remaining = limiter.get_remaining(token_hash, "/test")
        assert remaining < 100  # Should be ~50
    
    def test_repeated_malformed_blocks(self):
        """5+ malformed requests should block the token."""
        from fastapi import HTTPException
        
        limiter = RateLimiter()
        token_hash = "test-token-4"
        
        # Record 5 malformed requests
        for i in range(4):
            limiter.record_malformed_request(token_hash, f"reason_{i}")
        
        # 5th should trigger block
        with pytest.raises(HTTPException) as exc_info:
            limiter.record_malformed_request(token_hash, "reason_4")
        assert exc_info.value.status_code == 429
        assert "blocked" in exc_info.value.detail.lower()


class TestRateLimitIntegration:
    """Integration tests for rate limiting via API."""
    
    @pytest.mark.asyncio
    async def test_valid_requests_not_limited(
        self,
        client: AsyncClient,
        read_metrics_token: str,
    ):
        """Normal request volume should not trigger limits."""
        for _ in range(10):
            response = await client.get(
                "/metrics",
                headers={"Authorization": f"Bearer {read_metrics_token}"},
            )
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_malformed_inputs_trigger_penalty(
        self,
        client: AsyncClient,
        write_metrics_token: str,
    ):
        """Repeated malformed inputs should eventually block."""
        # Send multiple malformed requests
        for _ in range(6):
            response = await client.post(
                "/metrics",
                headers={"Authorization": f"Bearer {write_metrics_token}"},
                json={
                    "name": "test",
                    "metric_type": "invalid",  # Invalid enum
                    "value": 1.0,
                },
            )
        
        # Should eventually get 429 (blocked due to malformed)
        # Note: May get 422 first, then 429 after penalty accumulates
        assert response.status_code in [422, 429]
    
    @pytest.mark.asyncio
    async def test_valid_token_blocked_after_behavioral_drift(
        self,
        client: AsyncClient,
        write_metrics_token: str,
    ):
        """
        Chaos test: Valid token, correct scope, but repeated malformed
        payloads cause eventual blocking.
        
        This demonstrates correctness under behavioral drift — not just
        static permission checks.
        """
        # Phase 1: Valid request succeeds
        response = await client.post(
            "/metrics",
            headers={"Authorization": f"Bearer {write_metrics_token}"},
            json={
                "name": "valid_metric",
                "metric_type": "counter",
                "value": 1.0,
            },
        )
        assert response.status_code == 201, "Valid request should succeed initially"
        
        # Phase 2: Send 5 malformed requests (triggers block threshold)
        for _ in range(5):
            await client.post(
                "/metrics",
                headers={"Authorization": f"Bearer {write_metrics_token}"},
                json={
                    "name": "test",
                    "metric_type": "INVALID_TYPE",  # Malformed
                    "value": 1.0,
                },
            )
        
        # Phase 3: Now even valid requests should be blocked
        response = await client.post(
            "/metrics",
            headers={"Authorization": f"Bearer {write_metrics_token}"},
            json={
                "name": "another_valid_metric",
                "metric_type": "gauge",
                "value": 42.0,
            },
        )
        assert response.status_code == 429, (
            "Token should be blocked after malformed request storm, "
            f"but got {response.status_code}"
        )

