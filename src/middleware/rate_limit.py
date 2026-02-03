"""
Hierarchical, abuse-aware rate limiting.

Design principles:
- Per-token limits: Track abuse per caller
- Per-route limits: Protect expensive endpoints
- Escalating penalties: Malformed inputs reduce quota
- In-memory store with optional Redis backend
"""

import functools
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

from src.logging.security_logger import get_security_logger


@dataclass
class RateLimitState:
    """Tracks rate limit state for a single token."""
    requests: list[float] = field(default_factory=list)
    penalty_multiplier: float = 1.0
    malformed_count: int = 0
    last_reset: float = field(default_factory=time.time)


@dataclass
class RouteConfig:
    """Per-route rate limit configuration."""
    requests_per_minute: int = 60
    burst_allowance: int = 10  # Extra requests allowed in short bursts


class RateLimiter:
    """
    Hierarchical rate limiter with abuse detection.
    
    Features:
    - Per-token tracking
    - Per-route configuration
    - Escalating penalties for malformed inputs
    - Automatic quota reset
    """
    
    # Default limits
    DEFAULT_REQUESTS_PER_MINUTE = 100
    DEFAULT_WINDOW_SECONDS = 60
    
    # Penalty escalation
    MALFORMED_PENALTY_FACTOR = 0.5  # Halve remaining quota
    MAX_MALFORMED_BEFORE_BLOCK = 5
    PENALTY_DECAY_MINUTES = 10
    
    def __init__(self) -> None:
        self._token_state: dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._route_config: dict[str, RouteConfig] = {}
        self._logger = get_security_logger()
    
    def configure_route(
        self,
        route: str,
        requests_per_minute: int = 60,
        burst_allowance: int = 10,
    ) -> None:
        """Configure rate limits for a specific route."""
        self._route_config[route] = RouteConfig(
            requests_per_minute=requests_per_minute,
            burst_allowance=burst_allowance,
        )
    
    def _get_effective_limit(
        self,
        token_hash: str,
        route: str,
    ) -> int:
        """
        Calculate effective rate limit after penalties.
        
        Malformed input count reduces available quota.
        """
        state = self._token_state[token_hash]
        route_config = self._route_config.get(route, RouteConfig())
        
        base_limit = min(
            self.DEFAULT_REQUESTS_PER_MINUTE,
            route_config.requests_per_minute + route_config.burst_allowance,
        )
        
        # Apply penalty
        effective = int(base_limit * state.penalty_multiplier)
        return max(1, effective)  # Always allow at least 1 request
    
    def _clean_old_requests(self, state: RateLimitState) -> None:
        """Remove requests older than the window."""
        cutoff = time.time() - self.DEFAULT_WINDOW_SECONDS
        state.requests = [t for t in state.requests if t > cutoff]
    
    def _maybe_decay_penalty(self, state: RateLimitState) -> None:
        """Gradually restore quota if behavior improves."""
        now = time.time()
        minutes_since_reset = (now - state.last_reset) / 60
        
        if minutes_since_reset >= self.PENALTY_DECAY_MINUTES:
            state.penalty_multiplier = min(1.0, state.penalty_multiplier + 0.25)
            state.malformed_count = max(0, state.malformed_count - 1)
            state.last_reset = now
    
    def check_rate_limit(
        self,
        token_hash: str,
        route: str,
    ) -> None:
        """
        Check if request should be rate limited.
        Raises HTTPException if limit exceeded.
        """
        state = self._token_state[token_hash]
        
        # Clean up and decay
        self._clean_old_requests(state)
        self._maybe_decay_penalty(state)
        
        effective_limit = self._get_effective_limit(token_hash, route)
        
        if len(state.requests) >= effective_limit:
            self._logger.log_rate_limit_exceeded(
                token_hash=token_hash,
                route=route,
                limit=effective_limit,
                window_seconds=self.DEFAULT_WINDOW_SECONDS,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={
                    "Retry-After": str(self.DEFAULT_WINDOW_SECONDS),
                    "X-RateLimit-Limit": str(effective_limit),
                    "X-RateLimit-Remaining": "0",
                },
            )
        
        # Record this request
        state.requests.append(time.time())
    
    def record_malformed_request(
        self,
        token_hash: str,
        reason: str,
    ) -> None:
        """
        Record a malformed request and apply penalty.
        
        Key insight: Malformed traffic is more suspicious than high volume.
        """
        state = self._token_state[token_hash]
        state.malformed_count += 1
        
        # Apply escalating penalty
        old_multiplier = state.penalty_multiplier
        state.penalty_multiplier *= self.MALFORMED_PENALTY_FACTOR
        state.penalty_multiplier = max(0.1, state.penalty_multiplier)  # Floor at 10%
        
        self._logger.log_rate_limit_penalty(
            token_hash=token_hash,
            reason=reason,
            penalty_multiplier=state.penalty_multiplier,
        )
        
        # Block if too many malformed requests
        if state.malformed_count >= self.MAX_MALFORMED_BEFORE_BLOCK:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Temporarily blocked due to repeated malformed requests",
                headers={"Retry-After": str(self.PENALTY_DECAY_MINUTES * 60)},
            )
    
    def get_remaining(self, token_hash: str, route: str) -> int:
        """Get remaining requests in current window."""
        state = self._token_state[token_hash]
        self._clean_old_requests(state)
        effective_limit = self._get_effective_limit(token_hash, route)
        return max(0, effective_limit - len(state.requests))


# Singleton
@functools.lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    """Get singleton rate limiter instance."""
    limiter = RateLimiter()
    
    # Configure route-specific limits
    limiter.configure_route("/metrics", requests_per_minute=120, burst_allowance=20)
    limiter.configure_route("/users", requests_per_minute=30, burst_allowance=5)
    
    return limiter


def reset_rate_limiter() -> None:
    """Reset rate limiter state. For testing only."""
    get_rate_limiter.cache_clear()

