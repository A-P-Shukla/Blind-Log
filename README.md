# BlindLog v1.2.2

[![GitHub](https://img.shields.io/badge/GitHub-Repository-181717.svg?style=for-the-badge&logo=github)](https://github.com/A-P-Shukla/Blind-Log)

BlindLog is a **zero-dependency, production-ready Privacy-Preserving Observability SDK** for Python. 

It solves the fundamental conflict in backend engineering: Developers need visibility to debug systems, while privacy and compliance constraints (GDPR, HIPAA, SOC 2, PCI DSS) prohibit storing raw personal data in logs.

By replacing raw Personal Identifiable Information (PII) with consistent, structure-preserving deterministic pseudonyms, developers retain cross-service correlation and debugging capabilities without leaking real user identities.

---

## 💡 The "Why": Why Use BlindLog?

### The Problem with Traditional Redaction
Traditional redaction replaces sensitive values with static text like `*****` or `[REDACTED]`. The fatal flaw is **context destruction**:
```text
[REDACTED] failed to purchase item [REDACTED] on card [REDACTED]
[REDACTED] failed to purchase item [REDACTED] on card [REDACTED]
```
You cannot determine whether one user failed twice or two distinct users failed once.

### The BlindLog Solution: Deterministic Pseudonymization
BlindLog uses natively-keyed **BLAKE2b cryptography** to consistently map data:
- `user1@gmail.com` **always** maps to `blnd_ref_8a9df2c000001234...@masked.com`
- `user2@gmail.com` **always** maps to `blnd_ref_1c89f81ba0005678...@masked.com`

You immediately know when the *same* user encountered multiple errors across distributed microservices, while raw credentials and identities never enter log storage.

---

## 🚀 Installation

BlindLog requires **zero external dependencies** for core usage and supports Python 3.9+.

```bash
pip install blindlog
```

Optional framework integrations:
```bash
pip install "blindlog[fastapi]"   # FastAPI / Starlette middleware support
pip install "blindlog[structlog]" # structlog processor support
```

---

## 🛠️ Exactly How to Use It

### 1. Mandatory Security Configuration
BlindLog uses keyed BLAKE2b hashing. To prevent rainbow-table reversal, you must supply a cryptographic secret key in production.

Set the environment variables:
```bash
export BLINDLOG_SECRET="your-high-entropy-random-secret-key"
export BLINDLOG_SALT="optional-additional-salt"
export BLINDLOG_KEY_ID="v1" # Optional key rotation identifier
```

> [!WARNING]
> If `BLINDLOG_SECRET` is missing, BlindLog will raise a `ValueError` on startup in non-debug mode. For local unit testing, set `export BLINDLOG_DEBUG="true"` to bypass key validation.

---

### 2. Standard Python Logging

BlindLog provides a `logging.Formatter` that integrates seamlessly with Python's standard library `logging` module. It automatically intercepts log strings, dictionary arguments, and unhandled exception tracebacks.

```python
import logging
from blindlog.formatters import BlindLogFormatter

# 1. Initialize your logger
logger = logging.getLogger("my_app")
logger.setLevel(logging.INFO)

# 2. Attach BlindLogFormatter to your handler
handler = logging.StreamHandler()
handler.setFormatter(BlindLogFormatter())
logger.addHandler(handler)

# Free-text logging (scanned for regex patterns)
logger.info("Failed login for akhand@gmail.com on card 4111-2222-3333-4444")
# Output: Failed login for blnd_ref_8a9df2c000001234...@masked.com on card 4111-c918a210-f8b1c422-4444

# Structured dictionary arguments
logger.info("User created", {"email": "ceo@corp.com", "password": "super-secret"})
# Output: User created {'email': 'blnd_ref_9bf... masked', 'password': 'blind:838ab...'}

# Safe exception tracebacks
try:
    raise ValueError("User akhand@gmail.com exceeded API rate limits")
except ValueError:
    logger.exception("An application error occurred")
    # Output: Traceback is sanitized; akhand@gmail.com is masked within the stack trace
```

---

### 3. FastAPI & Starlette Middleware

The `BlindLogFastAPIMiddleware` operates at the raw ASGI layer, inspecting incoming request bodies, outgoing response bodies, and sensitive HTTP headers.

```python
from fastapi import FastAPI
from blindlog.integrations.fastapi import BlindLogFastAPIMiddleware

app = FastAPI()

# Attach middleware
app.add_middleware(BlindLogFastAPIMiddleware)

@app.post("/checkout")
async def checkout(payload: dict):
    return {"status": "success", "received": payload}
```

**Middleware Capabilities:**
- **Request & Response Body Masking:** Inspects and logs sanitized JSON payloads up to 5MB (with automatic OOM cutoff guards).
- **HTTP Header Protection:** Automatically redacts sensitive headers (such as `Authorization`, `Cookie`, `X-API-Key`) while maintaining list-of-tuples ordering and preserving duplicate headers.
- **Streaming Safety:** Handles WebSockets and Server-Sent Events without corrupting chunk streams.

---

### 4. Structlog Integration

BlindLog integrates directly into `structlog` processor chains:

```python
import structlog
from blindlog import BlindLogger
from blindlog.integrations.structlog import make_blindlog_processor

engine = BlindLogger(secret_key="my-secret-key")

structlog.configure(
    processors=[
        make_blindlog_processor(engine),
        structlog.processors.JSONRenderer(),
    ]
)

log = structlog.get_logger()
log.info("user_event", email="user@example.com", auth_token="sk-test-12345678901234567890")
```

---

### 5. Custom Configuration & Sensitive Keys

You can customize sensitive key detection and key rotation using `BlindLogConfig`:

```python
from blindlog.core import BlindLogger
from blindlog.config import BlindLogConfig

config = BlindLogConfig(
    secret_key="production-secret-key",
    key_id="v2",                                # Versioned prefix tag (blnd_v2_ref_...)
    sensitive_keys=frozenset({"customer_ssn", "auth_token", "email"}),
    debug_mode=False
)

logger = BlindLogger(config=config)
```

**Key Matching Strategy:**
- **Exact Match:** Matches registered keys like `"email"`, `"password"`.
- **Suffix Match:** Matches compound names with separators `_`, `-`, or `.` (e.g. `"old_password"`, `"user.auth_token"`, `"x-api-key"`).
- **Case Normalization:** Automatically converts camelCase (`apiKey`, `OAuth2Token`) and hyphenated keys to `snake_case`.

---

### 6. Custom Format Registration (Extending the Engine)

BlindLog's `RuleRegistry` allows registering custom regular expressions and masking callbacks:

```python
import re
from blindlog.core import BlindLogger

logger = BlindLogger(secret_key="my-secret-key")

# 1. Compile your custom pattern
internal_id_pattern = re.compile(r"EMP-\d{6}")

# 2. Register callback
def mask_employee_id(match_text: str) -> str:
    return f"{logger.tag('emp')}{logger.hash_text(match_text, length=16)}"

logger.registry.register(internal_id_pattern, mask_employee_id)

masked = logger.mask("Action performed by EMP-104928 on cluster")
# Output: "Action performed by blnd_emp_a8f9c102b4d83e1a on cluster"
```

---

## 🛡️ Default Out-Of-The-Box Protections

| Data Type | Detection Method | Format Output | Entropy |
|---|---|---|---|
| **Email Addresses** | `EMAIL_REGEX` & sensitive keys | `blnd_ref_<16 hex>...@masked.com` | 64-bit |
| **Credit Cards** | `CREDIT_CARD_REGEX` & sensitive keys | `4111-<8 hex>-<8 hex>-1234` | 64-bit |
| **API Keys & Secrets** | `API_KEY_REGEX` (OpenAI, Stripe, AWS, Slack, GitHub) | `blnd_key_<16 hex>` | 64-bit |
| **Phone Numbers** | `PHONE_REGEX` (International & NANP) | `blnd_ph_<16 hex>` | 64-bit |
| **SSN** | `SSN_REGEX` (US format) | `blnd_ssn_<16 hex>` | 64-bit |
| **IPv4 Addresses** | `IPV4_REGEX` (0-255 octet validated) | `blnd_ip_<16 hex>` | 64-bit |
| **Opaque Keys** | `DEFAULT_SENSITIVE_KEYS` matching | `blind:<16 hex>` | 64-bit |

### Exported `DEFAULT_SENSITIVE_KEYS`
```python
from blindlog import DEFAULT_SENSITIVE_KEYS

# frozenset({
#   "authorization", "authorization_code", "auth_code", "api_key",
#   "cookie", "set_cookie", "credentials", "credit_card", "cc_number",
#   "email", "encryption_key", "mobile", "password", "phone", "private_key",
#   "secret", "secret_key", "signing_key", "ssn", "ssn_number", "token"
# })
```

---

## 🔒 Security Model

### Cryptographic Foundation
- **Algorithm:** Keyed BLAKE2b (64-byte secret key derivation via standard library `hashlib`).
- **Collision Boundary:** 64-bit digest truncation provides 50% birthday collision resistance at ~4 billion distinct values.
- **Fail-Secure Architecture:** Fails closed; if masking fails during formatting, records are safely replaced with `[BLINDLOG MASKING FAILED - RECORD SUPPRESSED]` rather than leaking plaintext.
- **ReDoS Protection:** Free-text scanning terminates if string length exceeds 10,000 characters. Sensitive key values larger than 10,000 characters receive a keyed opaque hash without regex evaluation.
- **Idempotency:** Strict `MASKED_PATTERN` regex checks prevent double-hashing on multiple passes.

---

## ⚡ Performance Benchmarks

Measured on CPython 3.11/3.12 64-bit using Python standard library `hashlib`:

| Metric | Result |
|---|---|
| **Cryptographic PRF Throughput** | BLAKE2b executes **2x–4x faster** than HMAC-SHA256 |
| **Masking Throughput** | **> 2,400 payloads/second** per thread on mixed JSON |
| **P50 / P95 Latency** | **< 0.2ms** p50; **< 2.0ms** p95 per request |
| **Memory Footprint** | Peak memory under sustained 10,000 request load is **< 15 KB** |

---

## 📄 License & Security Reporting

- **License:** MIT License. See [LICENSE](./LICENSE).
- **Security Inquiries:** Please refer to [SECURITY.md](./SECURITY.md) for responsible disclosure procedures.
- **Architecture Deep-Dive:** See [ARCHITECTURE.md](./ARCHITECTURE.md) and [CHANGELOG.md](./CHANGELOG.md).
