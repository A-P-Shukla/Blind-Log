# BlindLog v1.2.0 Architecture

**Repository:** [https://github.com/A-P-Shukla/Blind-Log](https://github.com/A-P-Shukla/Blind-Log)

Bridging the gap between "hiding text" and true **Privacy-Preserving Observability**.

## 1. The Core Philosophy: Deterministic Pseudonymization

**Redaction (The Old Way):** Replaces sensitive data with static text like `*****` or `[REDACTED]`. The fatal flaw here is context destruction. You cannot trace a specific user's journey through your system when every trace of their identity maps to the exact same redacted string. 

**Pseudonymization (The BlindLog Way):** Replaces sensitive data with a unique, consistent artificial identifier. `akhand@gmail.com` consistently maps to `blnd_ref_8a9df2c000001234...@masked.com`. You achieve full Traceability without exposing Identity.

## 2. The Cryptographic Engine: BLAKE2b

BlindLog utilizes **keyed BLAKE2b**:
- **Performance:** BLAKE2b executes considerably faster in software on 64-bit architectures compared to the SHA-2 family.
- **Native Keying:** Instead of relying on a clunky HMAC wrapper, BLAKE2b acts natively as an ultra-fast Pseudo-Random Function (PRF) by accepting a `key=` parameter.
- **Entropy & Truncation:** From v1.2, truncated digests are 16 hex characters (**64 bits**). A 50% birthday collision is ~4 billion distinct values. Historical v1.1 40–48 bit masks remain recognized and idempotent.
- **Key Rotation:** Optional `key_id` / `BLINDLOG_KEY_ID` embeds a version prefix (e.g. `blnd_v2_ref_...`, `blind_v2:...`) so rotating `BLINDLOG_SECRET` does not silently alias new hashes onto old ones.
- **Fail Secure:** BlindLog mandates the presence of `BLINDLOG_SECRET`. If it is missing outside of debug paths, the system throws a `ValueError` on initialization.

## 3. The Architectural Layers

BlindLog operates as an intercepting middleware across five distinct domains:

### Layer 1: The Contract Layer (Interface Abstraction)
All downstream plugins type-check against `MaskingEngine` (an Abstract Base Class), not `BlindLogger` concretely. This provides Dependency Injection (DI), allowing architecture teams to swap the local BLAKE2b engine with remote KMS or HSM logging logic seamlessly.

### Layer 2: The Discovery & Routing Layer (Rule Registry)
Rather than hardcoding ladders, BlindLog's engine executes on an extensible **Registry Pattern**. Consumers can bind new `re.Pattern` objects and custom callbacks directly via `logger.registry.register()`.

BlindLog's internal discovery executes via a **Hybrid Recursive DFS Strategy**:
- **Fast Path (Key-Based):** Uses **exact match + suffix match** to detect sensitive keys. A field is masked if its name matches a registered sensitive key or ends with `_<sensitive_key>`, `-<sensitive_key>`, or `.<sensitive_key>` after camelCase and hyphen normalization.
- **Slow Path (Value-Based):** Scans arbitrary string logs using registered regex rules. Capped at 10,000 characters to avert CPU-exhaustion (ReDoS) scaling attacks.
- **Idempotency:** `mask()` is safe to call multiple times on the same data. The discovery engine uses a strict mathematical regex (`MASKED_PATTERN`) to verify entropy. Values conforming to internal formats are skipped automatically without collision risk.

### Layer 3: The Transformation Layer (Structure-Preserving Masking)
Logging aggregators (Elasticsearch, Datadog) crash if strict schemas are compromised. BlindLog replaces target strings while preserving their data shape:
- **Email:** `akhand@gmail.com` -> `blnd_ref_<16 hex>...@masked.com` (or `blnd_v2_ref_...` with `key_id`)
- **Credit Card:** `4111-2222-3333-9821` -> `4111-<8 hex>-<8 hex>-9821` (64-bit 4-8-8-4)
- **Container Types:** Recursively maps nested dictionaries, lists, tuples, and sets/frozensets.

### Layer 4: The Deep Transport Layer (Pure ASGI Middleware)
The FastAPI / Starlette middleware implements a hardened **Pure ASGI Middleware** executing directly within the standard ASGI `__call__` interface:
1. Validates `Content-Length` headers, shedding massive payloads (> 5MB) dynamically to avert Out-Of-Memory (OOM) Denial of Service.
2. Ingests, inspects, and masks HTTP request bodies, response bodies, and sensitive HTTP headers.
3. Preserves duplicate headers (as list of tuples) and non-UTF8 header safety.

### Layer 5: Structured Logging Integrations
- **Python `logging`:** `BlindLogFormatter` sanitizes record strings, structured arguments, and exception stack traces (`exc_info`).
- **`structlog`:** `BlindLogStructlogProcessor` provides drop-in processor pipeline sanitization.
