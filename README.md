# BlindLog v1.1

BlindLog is a **zero-dependency, production-ready Privacy-Preserving Observability SDK** for Python. 

It solves the fundamental conflict in backend engineering: The developer needs to see everything to fix bugs, but compliance constraints (GDPR/HIPAA) say you cannot see anything personal. By replacing raw Personal Identifiable Information (PII) with consistent, structure-preserving deterministic hashes, developers retain perfect system observability without leaking actual identities into logs.

## Overview

Unlike legacy redaction that wipes out debugging context (e.g., `*****`), BlindLog uses natively-keyed **BLAKE2b cryptography** to consistently map data:
- `akhand@gmail.com` always logs as `blnd_ref_8ax92bfac000...@masked.com`. 
- You instantly know if the same user triggered 50 errors across microservices, while remaining legally compliant.

## Features

- **Blazing Fast Cryptography:** Fully migrated to `BLAKE2b` for maximum performance, eliminating the slow HMAC-SHA256 wrapping layer.
- **Pure ASGI Middleware:** Our FastAPI interceptor operates at the raw ASGI layer. It safely buffers HTTP limits (5MB cutoffs to prevent OOM DOS) without fracturing downstream WebSocket or Server-Sent Event pipelines.
- **Fail-Secure Key Strategy:** Demands actual `BLINDLOG_SECRET` injections in production, violently crashing on boot if absent to prevent secret-bypassing logic.
- **Extensible Rule Registry:** Easily build and attach custom dynamic regex formatters.
- **Abstract Standardized Contracts:** Formatted strictly against a `MaskingEngine` ABC, granting total freedom to swap backend crypto-engines (like AWS KMS) without refactoring the library.

## Quick Start

### Standard Python Logging

```python
import logging
from blindlog.formatters import BlindLogFormatter

logger = logging.getLogger("blindlog")
handler = logging.StreamHandler()
handler.setFormatter(BlindLogFormatter())
logger.addHandler(handler)

logger.info("Failed login for akhand@gmail.com on card 4111-2222-3333-4444")
# Output: Failed login for blnd_ref_8a9df2c00000...@masked.com on card 4111-c918a2-f8b1c4-4444
```

### FastAPI Middleware

```python
from fastapi import FastAPI
from blindlog.integrations.fastapi import BlindLogFastAPIMiddleware

app = FastAPI()
app.add_middleware(BlindLogFastAPIMiddleware)

@app.post("/login")
async def login(credentials: dict):
    return {"status": "processing"}
```

## Custom Format Registration

Because BlindLog v1.1 implements a Registry Pattern, you can add new maskers at runtime:

```python
import re
from blindlog.core import BlindLogger

# Ensure BLINDLOG_SECRET is set in environment, or pass secret_key directly
logger = BlindLogger(secret_key="my-secret-key")
logger.registry.register(re.compile(r"AWS-KMS-\d{6}"), lambda text: "MASKED_AWS_TOKEN")
```

## Security

Please review the [Architecture Guide](./ARCHITECTURE.md) for deeper knowledge into our truncation entropies, ReDoS mitigation mechanisms, and recursive Deep-Object casting safety.
