"""
Forensic-grade structured security logging.

Design principles:
- Logs are forensic artifacts, not debug prints
- Never log: raw tokens, raw payloads, unsanitized strings
- Always log: token hash, scope, route, abuse classification
- Structured JSON format for automated analysis
"""

import functools
from enum import Enum
from typing import Any, Optional

import structlog


class AbuseClass(str, Enum):
    """Abuse classification for security events."""
    BENIGN = "BENIGN"
    MALFORMED = "MALFORMED"
    PROBING = "PROBING"
    ESCALATION_ATTEMPT = "ESCALATION_ATTEMPT"
    RATE_EXCEEDED = "RATE_EXCEEDED"
    REPLAY_SUSPECTED = "REPLAY_SUSPECTED"


def _sanitize_for_log(value: Any, max_length: int = 100) -> str:
    """
    Sanitize value for safe logging.
    Prevents log injection and limits size.
    """
    if value is None:
        return "<none>"
    
    # Convert to string and escape control characters
    s = str(value)
    # Remove newlines, tabs, and other control chars that could break log parsing
    s = "".join(c if c.isprintable() and c not in "\n\r\t" else "?" for c in s)
    
    if len(s) > max_length:
        return s[:max_length] + "...<truncated>"
    return s


class SecurityLogger:
    """
    Structured security logger for forensic analysis.
    
    All methods produce structured JSON logs suitable for:
    - SIEM ingestion
    - Anomaly detection
    - Post-incident forensics
    """
    
    def __init__(self) -> None:
        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
        self._logger = structlog.get_logger("security")
    
    def _log(
        self,
        level: str,
        event: str,
        abuse_class: AbuseClass = AbuseClass.BENIGN,
        **kwargs: Any,
    ) -> None:
        """Internal logging with abuse classification."""
        # Sanitize all string values
        sanitized = {
            k: _sanitize_for_log(v) if isinstance(v, str) else v
            for k, v in kwargs.items()
        }
        
        log_method = getattr(self._logger, level)
        log_method(
            event,
            abuse_class=abuse_class.value,
            **sanitized,
        )
    
    # ─── Authentication Events ───────────────────────────────────────────
    
    def log_authentication_success(
        self,
        token_hash: str,
        subject: str,
        scopes: list[str],
    ) -> None:
        """Log successful token validation."""
        self._log(
            "info",
            "auth.success",
            token_hash=token_hash,
            subject=subject,
            scope_count=len(scopes),
        )
    
    def log_authentication_failure(
        self,
        reason: str,
        token_hash: Optional[str] = None,
        error_type: Optional[str] = None,
    ) -> None:
        """Log failed authentication attempt."""
        self._log(
            "warning",
            "auth.failure",
            abuse_class=AbuseClass.PROBING,
            reason=reason,
            token_hash=token_hash or "<no-token>",
            error_type=error_type,
        )
    
    # ─── Authorization Events ────────────────────────────────────────────
    
    def log_authorization_success(
        self,
        token_hash: str,
        scopes_used: list[str],
    ) -> None:
        """Log successful scope check."""
        self._log(
            "info",
            "authz.success",
            token_hash=token_hash,
            scopes_used=scopes_used,
        )
    
    def log_authorization_failure(
        self,
        token_hash: str,
        required_scopes: list[str],
        provided_scopes: list[str],
        missing_scopes: list[str],
    ) -> None:
        """Log scope check failure — potential privilege escalation."""
        self._log(
            "warning",
            "authz.failure",
            abuse_class=AbuseClass.ESCALATION_ATTEMPT,
            token_hash=token_hash,
            required_scopes=required_scopes,
            provided_scopes=provided_scopes,
            missing_scopes=missing_scopes,
        )
    
    # ─── Validation Events ───────────────────────────────────────────────
    
    def log_validation_success(
        self,
        token_hash: str,
        route: str,
        model: str,
    ) -> None:
        """Log successful input validation."""
        self._log(
            "info",
            "validation.success",
            token_hash=token_hash,
            route=route,
            model=model,
        )
    
    def log_validation_failure(
        self,
        token_hash: Optional[str],
        route: str,
        error_count: int,
        error_fields: list[str],
    ) -> None:
        """Log validation failure — potential malformed input attack."""
        self._log(
            "warning",
            "validation.failure",
            abuse_class=AbuseClass.MALFORMED,
            token_hash=token_hash or "<no-token>",
            route=route,
            error_count=error_count,
            error_fields=error_fields,
        )
    
    # ─── Rate Limiting Events ────────────────────────────────────────────
    
    def log_rate_limit_exceeded(
        self,
        token_hash: str,
        route: str,
        limit: int,
        window_seconds: int,
    ) -> None:
        """Log rate limit breach."""
        self._log(
            "warning",
            "rate_limit.exceeded",
            abuse_class=AbuseClass.RATE_EXCEEDED,
            token_hash=token_hash,
            route=route,
            limit=limit,
            window_seconds=window_seconds,
        )
    
    def log_rate_limit_penalty(
        self,
        token_hash: str,
        reason: str,
        penalty_multiplier: float,
    ) -> None:
        """Log escalating penalty application."""
        self._log(
            "warning",
            "rate_limit.penalty",
            abuse_class=AbuseClass.MALFORMED,
            token_hash=token_hash,
            reason=reason,
            penalty_multiplier=penalty_multiplier,
        )
    
    # ─── Request Events ──────────────────────────────────────────────────
    
    def log_request(
        self,
        token_hash: str,
        method: str,
        route: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """Log completed request."""
        self._log(
            "info",
            "request.complete",
            token_hash=token_hash,
            method=method,
            route=route,
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
        )


# Singleton instance
@functools.lru_cache(maxsize=1)
def get_security_logger() -> SecurityLogger:
    """Get singleton security logger instance."""
    return SecurityLogger()
