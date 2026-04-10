# BlindLog v1.1 Architecture

Bridging the gap between "hiding text" and true **Privacy-Preserving Observability**.

## 1. The Core Philosophy: Deterministic Pseudonymization

**Redaction (The Old Way):** Replaces sensitive data with static text like `*****` or `[REDACTED]`. The fatal flaw here is context destruction. You cannot trace a specific user's journey through your system when every trace of their identity maps to the exact same redacted string. 

**Pseudonymization (The BlindLog Way) :** Replaces sensitive data with a unique, consistent artificial identifier. `akhand@gmail.com` consistently maps to `ref_8x92a`. You achieve full Traceability without exposing Identity.

## 2. The Cryptographic Engine: BLAKE2b (Upgraded in v1.1)

BlindLog originally utilized HMAC-SHA256 but has aggressively migrated to **BLAKE2b**. 
- **Performance:** BLAKE2b executes considerably faster in software on 64-bit architectures compared to the SHA-2 family.
- **Native Keying:** Instead of relying on a clunky HMAC wrapper, BLAKE2b acts natively as an ultra-fast Pseudo-Random Function (PRF) by accepting a `key=` parameter.
- **High Entropy Formulation:** BlindLog guarantees 48-bits of entropy collision-resistance (12 hex chars) to offset the Birthday Paradox during structured CC parsing.
- **Fail Secure:** BlindLog mandates the presence of the `BLINDLOG_SECRET`. If it is missing outside of debug paths, the system throws a `ValueError` rather than falling back to a hardcoded string, preventing catastrophic symmetric exposure.

## 3. The Architectural Layers

BlindLog operates fundamentally as an intercepting Middleware across four distinct domains:

### Layer 1: The Contract Layer (Interface Abstraction)
All downstream plugins type-check against `MaskingEngine` (an Abstract Base Class), not `BlindLogger` concretely. This provides Enterprise DI (Dependency Injection), allowing architecture teams to entirely swap the local BLAKE2b engine with remote KMS logging logic seamlessly.

### Layer 2: The Discovery & Routing Layer (Rule Registry)
Rather than hardcoding `if/else` ladders, BlindLog's engine executes on an extensible **Registry Pattern**. Consumers can arbitrarily bind new `re.Pattern` objects and Custom Callbacks directly into `logger.registry.register()`, providing infinite extensibility. 

BlindLog's internal discovery executes via a **Hybrid Recursive DFS Strategy**:
- **Fast Path (Key-Based):** Uses **exact match + suffix match** to detect sensitive keys. A field is masked if its name exactly matches a registered sensitive key (e.g. `"email"`, `"password"`) OR if it ends with `_<sensitive_key>` or `-<sensitive_key>` (e.g. `"refresh_token"`, `"old_password"`, `"x_api_key"`). This catches real-world compound OAuth2/auth field names while avoiding false positives on unrelated fields like `"token_count"` or `"email_verified"`.
- **Slow Path (Value-Based):** Scans arbitrary string logs using registered regex rules. Limit-locked to 10,000 characters to avert CPU-exhaustion (ReDoS) scaling attacks.
- **Idempotency:** `mask()` is safe to call multiple times on the same data. Values already carrying BlindLog sentinel prefixes (`ref_`, `blind:`, `ip_`, `key_`) are skipped automatically.

### Layer 3: The Transformation Layer (Structure-Preserving Masking)
Logging aggregators (Elasticsearch, Datadog) crash if strict schemas are compromised. If an `email` field receives a raw 64-char hash, ingestion pipelines break. BlindLog replaces the target strings physically preserving their structure:
- **Email:** `akhand@gmail.com` -> `ref_81ca7b82f012...@masked.com`
- **Credit Card:** `4111-xxxx-xxxx-9821` -> `4111-e129ba-10efc1-9821`

### Layer 4: The Deep Transport Layer (Pure ASGI Middleware)
While v1 scaffolded standard Starlette interception, v1.1 implements a hardened **Pure ASGI Middleware**.
By executing directly within the standard ASGI `__call__` interface, BlindLog isolates physical Byte streams perfectly:
1. Validates `Content-Length` headers, shedding massive payloads (> 5MB) dynamically to avert Out-Of-Memory (OOM) Denial of Service — on both request and response bodies.
2. Ingests and inspects the HTTP payloads securely.
3. Repackages ASGI signals perfectly preventing the tearing of underlying async topologies like WebSockets, Server-Sent Events, or native FastAPI generators.

> **Known Limitation:** For streaming responses (SSE, chunked transfer), PII values split across multiple body chunks cannot be detected by chunk-by-chunk regex inspection. For full coverage of streaming responses, consider buffering the entire response at the application level or using endpoint-specific masking.

