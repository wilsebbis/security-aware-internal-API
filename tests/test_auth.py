"""
Tests for authentication and authorization.

Verifies:
- Token validation
- Scope enforcement
- No implicit privilege inheritance
"""

import pytest
from httpx import AsyncClient


class TestAuthentication:
    """Tests for JWT validation."""
    
    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self, client: AsyncClient):
        """Requests without auth should get 401."""
        response = await client.get("/metrics")
        assert response.status_code == 401
        assert "missing" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self, client: AsyncClient):
        """Invalid JWT should get 401."""
        response = await client.get(
            "/metrics",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_expired_token_returns_401(
        self,
        client: AsyncClient,
        expired_token: str,
    ):
        """Expired token should get 401."""
        response = await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_valid_token_accepted(
        self,
        client: AsyncClient,
        read_metrics_token: str,
    ):
        """Valid token with correct scope should succeed."""
        response = await client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {read_metrics_token}"},
        )
        assert response.status_code == 200


class TestScopeEnforcement:
    """Tests for scope-based authorization."""
    
    @pytest.mark.asyncio
    async def test_read_scope_cannot_write(
        self,
        client: AsyncClient,
        read_metrics_token: str,
    ):
        """read:metrics should not allow POST."""
        response = await client.post(
            "/metrics",
            headers={"Authorization": f"Bearer {read_metrics_token}"},
            json={
                "name": "test_metric",
                "metric_type": "counter",
                "value": 1.0,
            },
        )
        assert response.status_code == 403
        assert "scope" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_write_scope_can_write(
        self,
        client: AsyncClient,
        write_metrics_token: str,
    ):
        """write:metrics should allow POST."""
        response = await client.post(
            "/metrics",
            headers={"Authorization": f"Bearer {write_metrics_token}"},
            json={
                "name": "test_metric",
                "metric_type": "counter",
                "value": 1.0,
            },
        )
        assert response.status_code == 201
    
    @pytest.mark.asyncio
    async def test_no_cross_resource_access(
        self,
        client: AsyncClient,
        write_metrics_token: str,
    ):
        """write:metrics should not grant access to users."""
        response = await client.get(
            "/users",
            headers={"Authorization": f"Bearer {write_metrics_token}"},
        )
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_read_users_cannot_modify(
        self,
        client: AsyncClient,
        read_users_token: str,
    ):
        """read:users should not allow PUT."""
        response = await client.put(
            "/users/user-001",
            headers={"Authorization": f"Bearer {read_users_token}"},
            json={"display_name": "Hacked"},
        )
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_admin_users_can_modify(
        self,
        client: AsyncClient,
        admin_users_token: str,
    ):
        """admin:users should allow PUT."""
        response = await client.put(
            "/users/user-001",
            headers={"Authorization": f"Bearer {admin_users_token}"},
            json={"display_name": "Updated Name"},
        )
        assert response.status_code == 200
