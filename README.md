# Security-Aware Internal API

> Internal API designed under hostile-input assumptions, enforcing least privilege, scoped authorization, abuse-aware rate limiting, and forensic-grade logging.

## Why This Exists

Most internal APIs fail because of false trust assumptions:
- "Internal traffic is safe"
- "OAuth token = trusted caller"
- "Validation is for edge services"

This project explicitly rejects those assumptions. Internal callers are treated as potentially compromised, tokens as capabilities (not identities), and malformed input as intentional.

## Threat Model

| Threat | Example |
|--------|---------|
| Compromised service | Stolen OAuth token from logs |
| Privilege confusion | Service A calls with broader scope |
| Input abuse | Overlong payloads, type confusion |
| Automation abuse | High-rate retries probing edges |
| Log poisoning | Malicious input to corrupt logs |

## Quick Start

```bash
# Install dependencies
uv sync

# Run dev server
uv run uvicorn src.main:app --reload

# Run tests
uv run pytest tests/ -v
```

## Security Features

### 1. Scoped Authorization
```
read:metrics  ≠  write:metrics
read:users    ≠  admin:users
```
No implicit privilege inheritance. Each route requires explicit scope.

### 2. Strict Validation
- Pydantic `strict=True` — no implicit type coercion
- `extra="forbid"` — unknown fields rejected
- Length limits on all strings
- Enum constraints for categorical fields

### 3. Abuse-Aware Rate Limiting
- Per-token tracking
- Per-route configuration
- **Escalating penalties**: Malformed inputs halve remaining quota
- Block after 5 malformed requests

### 4. Forensic Logging
```json
{"event": "authz.failure", "abuse_class": "ESCALATION_ATTEMPT", "token_hash": "a1b2c3..."}
```
- Structured JSON for SIEM ingestion
- Token hash logged (never raw token)
- Abuse classification: `BENIGN`, `MALFORMED`, `PROBING`, `ESCALATION_ATTEMPT`

## API Endpoints

| Endpoint | Method | Scope Required |
|----------|--------|----------------|
| `/metrics` | GET | `read:metrics` |
| `/metrics` | POST | `write:metrics` |
| `/metrics/{id}` | PATCH | `write:metrics` |
| `/users` | GET | `read:users` |
| `/users/{id}` | GET | `read:users` |
| `/users/{id}` | PUT | `admin:users` |
| `/health` | GET | (none) |

## Adversarial Input Corpus

Test cases in `data/`:

| File | Contents |
|------|----------|
| `benign_requests.json` | Valid requests for baseline |
| `malformed_requests.json` | Type confusion, oversized, unicode attacks |
| `privilege_escalation_attempts.json` | Scope misuse, cross-resource access |
| `rate_limit_abuse.json` | Volume attacks, malformed storms |

## License

MIT
