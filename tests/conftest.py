"""
Pytest fixtures for Security-Aware Internal API tests.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from src.main import app
from src.auth.oauth import create_test_token
from src.auth.scopes import Scope
from src.middleware.rate_limit import reset_rate_limiter
from src.logging.security_logger import get_security_logger


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singleton state between tests for isolation."""
    reset_rate_limiter()
    # Clear any cached logger state
    get_security_logger.cache_clear()
    yield
    reset_rate_limiter()
    get_security_logger.cache_clear()


@pytest.fixture
def read_metrics_token() -> str:
    """Token with read:metrics scope only."""
    return create_test_token(
        sub="test-service-reader",
        scopes=[Scope.READ_METRICS.value],
    )


@pytest.fixture
def write_metrics_token() -> str:
    """Token with read and write metrics scopes."""
    return create_test_token(
        sub="test-service-writer",
        scopes=[Scope.READ_METRICS.value, Scope.WRITE_METRICS.value],
    )


@pytest.fixture
def read_users_token() -> str:
    """Token with read:users scope only."""
    return create_test_token(
        sub="test-service-user-reader",
        scopes=[Scope.READ_USERS.value],
    )


@pytest.fixture
def admin_users_token() -> str:
    """Token with admin:users scope."""
    return create_test_token(
        sub="test-service-admin",
        scopes=[Scope.READ_USERS.value, Scope.ADMIN_USERS.value],
    )


@pytest.fixture
def full_access_token() -> str:
    """Token with all scopes (for testing only)."""
    return create_test_token(
        sub="test-service-full",
        scopes=[s.value for s in Scope],
    )


@pytest.fixture
def expired_token() -> str:
    """Expired token for testing auth failures."""
    return create_test_token(
        sub="test-service-expired",
        scopes=[Scope.READ_METRICS.value],
        exp_minutes=-1,  # Already expired
    )


@pytest.fixture
async def client() -> AsyncClient:
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
