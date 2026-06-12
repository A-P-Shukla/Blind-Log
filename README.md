# BlindLog v1.1

[![GitHub](https://img.shields.io/badge/GitHub-Repository-181717.svg?style=for-the-badge&logo=github)](https://github.com/A-P-Shukla/Blind-Log)

BlindLog is a **zero-dependency, production-ready Privacy-Preserving Observability SDK** for Python.

It solves the fundamental conflict in backend engineering: The developer needs to see everything to fix bugs, but compliance constraints (GDPR/HIPAA/SOC2) dictate that you cannot see anything personal. 

By replacing raw Personal Identifiable Information (PII) with consistent, structure-preserving deterministic hashes, developers retain perfect system observability without leaking actual identities into application logs.

---

## 💡 The "Why": Why Use BlindLog?

### The Problem with Redaction
Legacy redaction tools look for emails or credit cards and replace them with static text like `*****` or `[REDACTED]`. The fatal flaw here is **context destruction**. If your logs show `[REDACTED] failed to purchase order [REDACTED]`, you cannot trace a specific user's journey through your microservices when every trace of their identity maps to the exact same generic string.

### The BlindLog Solution: Deterministic Pseudonymization
BlindLog uses natively-keyed **BLAKE2b cryptography** to consistently map data:
- `user1@gmail.com` **always** logs as `blnd_ref_8ax92bfac000...@masked.com`.
- `user2@gmail.com` **always** logs as `blnd_ref_1c89f81ba000...@masked.com`.

You instantly know if the *same* user triggered 50 errors across 4 microservices over a week, while remaining legally compliant because the raw identity is cryptographically destroyed.

---

## 🚀 Installation

BlindLog has zero external dependencies and runs natively on Python 3.8+.

```bash
pip install blindlog
```

---

## 🛠️ Exactly How to Use It

BlindLog is built on an extensible architecture that operates automatically once plugged into your existing application. It intercepts data, traverses JSON payloads recursively, and masks strings without breaking schema.

### 1. Mandatory Security Configuration
BlindLog operates on keyed hashes. To prevent rainbow-table reverse-engineering, you **must** supply a cryptographic secret.

Set the following environment variables on your production servers:
```bash
export BLINDLOG_SECRET="your-super-strong-random-secret-key"
export BLINDLOG_SALT="optional-additional-salt"
```

> **Warning:** If `BLINDLOG_SECRET` is missing, BlindLog will violently crash on boot to protect your system from generating reversible, unkeyed hashes. For local development, you can set `export BLINDLOG_DEBUG="true"` to bypass this crash.

---

### 2. Standard Python Logging Interception

BlindLog ships with a `logging.Formatter` that hooks directly into Python's native `logging` module. It intercepts all string messages, dictionary `args`, and even `Exception` tracebacks to scrub PII before it hits your terminal or logging aggregator (like Datadog/Elasticsearch).

```python
import logging
from blindlog.formatters import BlindLogFormatter

# 1. Initialize your logger
logger = logging.getLogger("my_application")
logger.setLevel(logging.INFO)

# 2. Create a handler
handler = logging.StreamHandler()

# 3. Attach the BlindLogFormatter!
handler.setFormatter(BlindLogFormatter())
logger.addHandler(handler)

# Usage A: Standard Strings (Slow Path - Regex Scanning)
logger.info("Failed login for akhand@gmail.com on card 4111-2222-3333-4444")
# Output: Failed login for blnd_ref_8a9df2c00000...@masked.com on card 4111-c918a2-f8b1c4-4444

# Usage B: Dictionary Arguments (Fast Path - Key Matching)
# BlindLog detects keys like 'password' or 'email' instantly.
logger.info("User created", {"email": "ceo@corp.com", "password": "super-secret"})
# Output: User created {'email': 'blnd_ref_9bf... masked', 'password': 'blind:838ab...'}

# Usage C: Safe Exceptions
try:
    raise ValueError("User akhand@gmail.com exhausted their API quota")
except ValueError:
    logger.exception("A system error occurred")
    # Output: The stack trace is fully processed, and akhand@gmail.com is masked inside the Traceback!
```

---

### 3. FastAPI & Starlette Middleware

BlindLog acts as a **Pure ASGI Middleware**. It intercepts raw HTTP traffic *before* it hits your application routers. It safely buffers HTTP payloads (up to 5MB to prevent OOM DOS) and logs masked Request Bodies, Response Bodies, and Headers.

```python
from fastapi import FastAPI
from blindlog.integrations.fastapi import BlindLogFastAPIMiddleware

app = FastAPI()

# Attach the middleware
app.add_middleware(BlindLogFastAPIMiddleware)

@app.post("/checkout")
async def checkout(payload: dict):
    # If the user sends {"credit_card": "4111-...", "cookie": "session_123"},
    # The middleware automatically logs the sanitized payload to standard out.
    return {"status": "success"}
```

**What the Middleware handles automatically:**
- **Request/Response Bodies:** Deeply nested JSON is recursively traversed and masked.
- **HTTP Headers:** Sensitive context headers (like `Authorization`, `Cookie`, `X-API-Key`) are extracted and encrypted without losing duplicate associations.
- **Streaming Protections:** Safe passage for WebSockets and SSE pipelines.

---

### 4. Customizing the Configuration (`BlindLogConfig`)

You can tune BlindLog's rules by defining a `BlindLogConfig`. Once created, the config is `frozen` (immutable) to prevent runtime tampering.

```python
from blindlog.core import BlindLogger
from blindlog.config import BlindLogConfig

# 1. Define custom sensitive keys. 
# Note: This overwrites the defaults, so add your specific database fields.
custom_keys = frozenset({"internal_db_id", "auth_token", "email"})

config = BlindLogConfig(
    secret_key="my-custom-key", # Will fall back to ENV var if omitted
    sensitive_keys=custom_keys,
    debug_mode=False
)

logger = BlindLogger(config=config)
```

**Key Matching Engine (Fast Path):**
BlindLog checks dictionary keys via:
1. **Exact Match:** e.g., `"email"` == `"email"`.
2. **Suffix Match:** e.g., `"user_password"` ends with `"_password"`.
3. **Normalization:** Hyphens (`x-api-key`) and camelCase (`APIKey`) are normalized to `snake_case` before matching, ensuring maximum coverage across varying schemas.

---

### 5. Custom Format Registration (Adding Regex)

BlindLog implements a **Registry Pattern**. If you have custom internal tokens (e.g., specific AWS KMS IDs or internal Employee IDs) you can teach BlindLog to find and format them dynamically in free-text.

```python
import re
from blindlog.core import BlindLogger

logger = BlindLogger()

# 1. Define a regex pattern
aws_pattern = re.compile(r"AWS-KMS-\d{6}")

# 2. Define a callback function that takes the matched string and returns a safe string
# Note: You can also hash it dynamically inside the callback if you wish!
def mask_aws(matched_string: str) -> str:
    return "blnd_aws_TOKEN_REDACTED"

# 3. Register the rule
logger.registry.register(aws_pattern, mask_aws)

masked = logger.mask("Exception: AWS-KMS-123456 failed to load.")
# Output: "Exception: blnd_aws_TOKEN_REDACTED failed to load."
```

---

## 🛡️ Default Out-Of-The-Box Protections

BlindLog actively protects the following data types automatically via RegEx and Key-discovery:

- **Emails:** Truncated and hashed (`blnd_ref_HASH...@masked.com`)
- **Credit Cards:** Preserves major industry format (`4111-HASH-HASH-1234`)
- **API Keys & Tokens:** Covers OpenAI, Stripe, AWS, Slack, and GitHub PATs natively.
- **Phone Numbers:** International and NANP routing.
- **Social Security Numbers (SSN):** US Formats.
- **IPv4 Addresses:** Validated octet arrays.
- **HTTP/Web Standard Keys:** `cookie`, `set_cookie`, `authorization`, `password`, `secret`, `private_key`, `credentials`.

---

## 🧮 Idempotency & System Guarantees

- **Idempotent Masking Guarantees:** BlindLog uses strict structural RegEx evaluations (`MASKED_PATTERN`). If you pass already-masked data into the engine multiple times, it skips it instantly. You will never double-hash a log.
- **ReDoS Mitigation:** Slow-path Regex execution cuts off after 10,000 characters, averting CPU exhaustion DOS attacks.
- **OOM Prevention:** Middlewares strictly cap at 5MB buffer payloads.
- **Type Sabotage Checks:** Gracefully handles `None`, `True`, and circular nested dictionary references without crashing or returning unmasked memory addresses.

For further exploration, please review our [Architecture Guide](./ARCHITECTURE.md) and the `CHANGELOG.md`!
