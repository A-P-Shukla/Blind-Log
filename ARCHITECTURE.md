# BlindLog Architecture

Bridging the gap between "hiding text" and true **Privacy-Preserving Observability**.

## 1. The Core Philosophy: Deterministic Pseudonymization

### Redaction (The Old Way) vs. Pseudonymization (The BlindLog Way)
Redaction replaces sensitive data with static text like `*****` or `[REDACTED]`. The fatal flaw here is context destruction. You cannot trace a specific user's journey through your system when every trace of their identity maps to the same redacted string. 

**BlindLog's Pseudonymization** replaces sensitive data with a unique, consistent artificial identifier.
`akhand@gmail.com` consistently maps to `ref_8x92a`. You achieve full Traceability without exposing Identity.

## 2. The Cryptographic Engine: HMAC-SHA256

BlindLog avoids predictable standard hashing (like pure SHA-256), which is vulnerable to Rainbow Table Attachs. Instead, it leverages a strict **Hash-Based Message Authentication Code (HMAC)**.

BlindLog requires a Secret Key, maintained strictly in the server's environment memory. 
Formula: `Hash(Data + Secret Key)`
Even if a malicious actor steals your logs, they cannot de-anonymize your users because they lack the Secret Key.

## 3. The Architectural Layers

BlindLog operates fundamentally as an intercepting Middleware across three domains:

### Layer 1: The Discovery Layer (Hybrid Strategy & Recursion)
BlindLog doesn't just evaluate top-level strings. It uses a **Hybrid Strategy** to recursively traverse massive, nested data structures (JSON, dictionaries inside lists):
- **Fast Path (Key-Based):** Checks dictionary keys. If a key is in our known `SENSITIVE_KEYS` list (e.g., `email`, `password`, `ssn`), the entire value is masked immediately.
- **Slow Path (Value-Based):** If the key is generic (like `message`, `log`, `error`), BlindLog runs low-latency Regex on the value to catch embedded PII (e.g., `"User akhand@gmail.com failed"`).

The recursive engine utilizes Depth-First Search (DFS) to traverse JSON trees and includes a **cycle-detection mechanism** to prevent infinite recursion in self-referencing objects.

### Layer 2: The Transformation Layer (Structure-Preserving Masking)
Logging aggregators (Elasticsearch, Datadog) crash if strict schemas are compromised. If an `email` field receives a raw hash, pipelines break.
BlindLog detects the input format and uses **Structure-Preserving Masking (Format-Aware Hashing)**. It is not encryption, but a deterministic replacement that maintains the visual shape of the data:
- **Email:** `akhand@gmail.com` -> `8x92a...@masked.com`
- **Credit Card:** `4111-xxxx-xxxx-9821` (Retains useful debug metadata, hashes the middle).

### Layer 3: The Transport Layer (Logging Handler)
Before data writes to disk or transits the network, BlindLog replaces the original data. This guarantees raw PII never leaks beyond volatile server memory.

## 4. Advanced Enterprise Targets

### A. Key Rotation (Ephemeral Identity)
In high-security environments, long-term user traceability isn't ideal. BlindLog natively supports Key Rotation.
**How it works:** BlindLog is stateless. Key rotation is achieved by changing the `BLINDLOG_SECRET` environment variable at the orchestration level (e.g., Kubernetes/Docker secrets). The key used to generate hashes changes naturally, segmenting logs by time epoch. Today's trace is dead tomorrow, preventing prolonged profiling by rogue operators. By-design Data Minimization.

### B. Collision Check Utility (Security Assurance)
Because BlindLog truncates hashes to keep log outputs readable and compliant, there is a theoretical, albeit astronomically small, risk of a collision (two different emails resulting in the same short hash). BlindLog's engine mathematically tracks and retains the full hash internally for collision verification if strict cryptographic auditing is required. 

### Roadmap v1.1: The "Emergency Break-Glass" Protocol
*Planned for v1.1.* For rare legal compliance situations, an AES-based configuration (Two-way) will allow Data Protection Officers to decrypt isolated entries with a private decryption key.

## The Proactive Cybersecurity Paradigm

By natively implementing BlindLog within standard Python streams, you are enabling **Proactive Security**. Data is secure essentially out of the gate, rendering it useless to anyone who might breach the logging server downstream. This is Data Minimization scaled democratically to the Python ecosystem.
