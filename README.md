# Security-Aware Internal API

> Internal API designed under hostile-input assumptions, enforcing least privilege, scoped authorization, abuse-aware rate limiting, and forensic-grade logging.

## Why This Exists

Most internal APIs fail because of false trust assumptions:
- "Internal traffic is safe"
- "OAuth token = trusted caller"
- "Validation is for edge services"

This project explicitly rejects those assumptions. Internal callers are treated as potentially compromised, tokens as capabilities (not identities), and malformed input as intentional.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Request Flow                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Token ──▶ JWT Validator ──▶ Scope Guard ──▶ Rate Limiter         │
│                │                   │               │                │
│                ▼                   ▼               ▼                │
│          [token_hash]       [403 if missing]  [429 if exceeded]    │
│                                                    │                │
│                                                    ▼                │
│                              Route Handler ◀── Pydantic Validator  │
│                                   │               │                │
│                                   ▼               ▼                │
│                           Security Logger   [422 if malformed]     │
│                                   │          + penalty applied     │
│                                   ▼                                 │
│                          Structured JSON Log                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
uv sync

# Run dev server
uv run uvicorn src.main:app --reload

# Run tests (32/32 including adversarial corpora)
uv run pytest -q
```

## Security Guarantees

- **No privilege inheritance**: `read:users` does NOT grant `admin:users`
- **ASCII-only identifiers**: Metric names and emails reject Unicode (blocks homoglyph attacks)
- **Token hash only**: Raw tokens never appear in logs
- **Sanitized errors**: Validation failures return generic messages, no internal details
- **Escalating penalties**: Repeated malformed inputs reduce quota exponentially
- **Abuse classification**: Every log entry tagged with intent (`BENIGN`, `MALFORMED`, `ESCALATION_ATTEMPT`)

## Non-Goals

This is a **reference implementation**, not a drop-in solution:

- ❌ Production-grade persistence (in-memory stores only)
- ❌ Centralized policy engine (OPA, Cedar)
- ❌ ML-based anomaly detection
- ❌ Multi-tenant isolation
- ❌ mTLS or certificate-based auth

## Threat Model

| Threat | Example |
|--------|---------|
| Compromised service | Stolen OAuth token from logs |
| Privilege confusion | Service A calls with broader scope |
| Input abuse | Overlong payloads, type confusion |
| Automation abuse | High-rate retries probing edges |
| Log poisoning | Malicious input to corrupt logs |

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
- ASCII-only for identifiers (metric names, emails)
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

## Known Limitations

- **In-process rate limiting**: Not shared across replicas. Production would use Redis.
- **Code-level authorization**: No centralized policy engine (OPA). Scope guards are route dependencies.
- **Rule-based abuse detection**: No ML anomaly detection (intentionally out of scope).
- **No persistence**: In-memory stores reset on restart.

## License

MIT
