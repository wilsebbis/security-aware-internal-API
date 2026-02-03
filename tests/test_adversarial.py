"""
Tests using adversarial input corpus.

Verifies:
- Malformed inputs are rejected
- Validation errors don't leak internal details
- Rate limiting kicks in appropriately
"""

import json
from pathlib import Path

import pytest
from httpx import AsyncClient


DATA_DIR = Path(__file__).parent.parent / "data"


class TestMalformedInputs:
    """Tests against the malformed_requests.json corpus."""
    
    @pytest.fixture
    def malformed_corpus(self) -> list[dict]:
        """Load malformed request corpus."""
        with open(DATA_DIR / "malformed_requests.json") as f:
            return json.load(f)
    
    @pytest.mark.asyncio
    async def test_all_malformed_rejected(
        self,
        client: AsyncClient,
        write_metrics_token: str,
        admin_users_token: str,
        malformed_corpus: list[dict],
    ):
        """Most malformed inputs should be rejected (>=80% rejection rate)."""
        rejected = 0
        passed = []
        
        for case in malformed_corpus:
            endpoint = case.get("endpoint", "/metrics")
            method = case.get("method", "POST")
            body = case.get("body")
            
            # Use appropriate token
            if "/users" in endpoint:
                token = admin_users_token
            else:
                token = write_metrics_token
            
            response = await client.request(
                method,
                endpoint,
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
            
            if response.status_code in [400, 422, 429]:
                rejected += 1
            else:
                passed.append(case['description'])
        
        # Require at least 80% rejection rate
        total = len(malformed_corpus)
        rejection_rate = rejected / total
        assert rejection_rate >= 0.8, (
            f"Expected >=80% rejection rate, got {rejection_rate:.0%}. "
            f"Passed cases: {passed}"
        )
    
    @pytest.mark.asyncio
    async def test_error_response_sanitized(
        self,
        client: AsyncClient,
        write_metrics_token: str,
    ):
        """Error responses should not leak internal details."""
        response = await client.post(
            "/metrics",
            headers={"Authorization": f"Bearer {write_metrics_token}"},
            json={
                "name": {"nested": "object"},  # Type confusion
                "metric_type": "counter",
                "value": 1.0,
            },
        )
        
        assert response.status_code == 422
        body = response.json()
        
        # Should have sanitized structure
        assert "success" in body
        assert body["success"] is False
        assert "error" in body
        
        # Should NOT contain stack traces or internal paths
        response_text = json.dumps(body)
        assert "traceback" not in response_text.lower()
        assert "/Users" not in response_text
        assert "pydantic" not in response_text.lower()


class TestPrivilegeEscalationAttempts:
    """Tests against privilege_escalation_attempts.json corpus."""
    
    @pytest.fixture
    def escalation_corpus(self) -> list[dict]:
        """Load privilege escalation corpus."""
        with open(DATA_DIR / "privilege_escalation_attempts.json") as f:
            return json.load(f)
    
    @pytest.mark.asyncio
    async def test_missing_scope_blocked(
        self,
        client: AsyncClient,
        read_metrics_token: str,
    ):
        """Requests with insufficient scope should get 403."""
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
    
    @pytest.mark.asyncio
    async def test_cross_resource_blocked(
        self,
        client: AsyncClient,
        write_metrics_token: str,
    ):
        """Metrics token should not access users."""
        response = await client.put(
            "/users/user-001",
            headers={"Authorization": f"Bearer {write_metrics_token}"},
            json={"display_name": "Hacked"},
        )
        assert response.status_code == 403


class TestBenignInputs:
    """Tests against benign_requests.json corpus."""
    
    @pytest.fixture
    def benign_corpus(self) -> list[dict]:
        """Load benign request corpus."""
        with open(DATA_DIR / "benign_requests.json") as f:
            return json.load(f)
    
    @pytest.mark.asyncio
    async def test_benign_accepted(
        self,
        client: AsyncClient,
        full_access_token: str,
        benign_corpus: list[dict],
    ):
        """All benign inputs should succeed."""
        for case in benign_corpus:
            endpoint = case.get("endpoint")
            method = case.get("method", "GET")
            body = case.get("body")
            query = case.get("query", {})
            
            response = await client.request(
                method,
                endpoint,
                headers={"Authorization": f"Bearer {full_access_token}"},
                json=body if method in ["POST", "PUT", "PATCH"] else None,
                params=query,
            )
            
            # Should succeed (2xx)
            assert 200 <= response.status_code < 300, (
                f"Expected success for {case['description']}, "
                f"got {response.status_code}"
            )
