# Changelog

All notable changes

## [1.2.1] - 2026-09-09

### Fixed
- **Zero Core Dependencies**: Relocated `build` and `twine` out of runtime `dependencies` into `[project.optional-dependencies] dev` in `pyproject.toml`. Standard core installation now has zero external dependencies.
- **Formatter `extra=` Attribute Leak**: `BlindLogFormatter` now traverses `record.__dict__` non-reserved attributes to sanitize and mask custom metadata (`extra={"email": "..."}`) and custom format string keys (`%(email)s`).
- **Custom Prefix Idempotency**: Generalized `MASKED_PATTERN` regex to recognize custom registered tag prefixes (`blnd_{kid}[tag]_{hex}`), preventing double-masking rewrite to `blind:...` on dictionary force paths.
- **Key Derivation Domain Separation**: Introduced null-byte delimiter (`safe_secret || \x00 || safe_salt`) in `_derive_blake_key()` to prevent delimiter collisions between secret and salt.

### Added
- **Public Masking Interfaces**: Added public `hash_text()` and `tag()` helper methods on `BlindLogger`.
- **Expanded Security Model Documentation**: Added comprehensive Threat Model, GDPR Recital 26 pseudonymization vs anonymization guidance, and thread-safety details to `README.md`.
- **CI Test Workflow**: Updated `.github/workflows/test.yml` to install `.[fastapi,structlog,dev]`.

---

 to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-07-24

### Breaking Changes

> **Note on Upgrades:** These changes alter newly emitted mask widths. Historical v1.1 sentinels remain recognized (idempotent), but external parsers that assumed fixed 10/12 hex lengths or 4-6-6-4 credit card layouts must accept 16 hex and 4-8-8-4.

- **64-bit truncated digests:** Email, opaque (`blind:`), IP, API key, phone, and SSN hashes are 16 hex characters (was 10 or 12). Credit cards use `4111-<8 hex>-<8 hex>-1234` (was 4-6-6-4 / 48-bit). 50% birthday collision resistance is ~4 billion values.
- **PyPI metadata:** Package version is `1.2.0`; package metadata updated with author and repository details.

### Added

- **Security model documentation:** Documented threat boundaries, trust models, entropy metrics, and responsible vulnerability reporting in [SECURITY.md](./SECURITY.md).
- **Key rotation support (`key_id` / `BLINDLOG_KEY_ID`):** Optional rotation identifier prefixed in generated masks (e.g. `blnd_v2_ref_...`, `blind_v2:...`). Valid format is `^[A-Za-z][A-Za-z0-9_]{0,15}$`.
- **`structlog` processor integration:** Added `blindlog.integrations.structlog.make_blindlog_processor` for seamless inclusion in structlog processor pipelines (installable via `pip install "blindlog[structlog]"`).
- **Top-level `DEFAULT_SENSITIVE_KEYS` export:** Exported from top-level package for custom rule extension.
- **Thread safety:** Added `threading.RLock()` to `RuleRegistry` for concurrent `register()` and `process_*` calls across multi-threaded workers.
- **Performance benchmarks:** Added benchmark summary comparing BLAKE2b vs HMAC-SHA256 and throughput floors.

### Changed

- **`MASKED_PATTERN` multi-era support:** Accepts versioned prefixes as well as both 48-bit and 64-bit credit card structures to prevent double-masking across key migrations.

---

## [1.1.1] — 2026-07-24

### Fixed

- **Idempotency stability:** Credit card masks (`4111-<8 hex>-<8 hex>-1234`) are properly recognized by `MASKED_PATTERN`, ensuring repeat `mask()` passes do not rewrite them to opaque hashes.
- **Container recursion:** `tuple` and `set`/`frozenset` objects under sensitive keys are now recursively traversed and masked.
- **Type distinction:** `bool` values under sensitive keys are type-prefixed before hashing to prevent collision with integers (as `bool` subclasses `int` in Python).
- **Oversized sensitive values:** Values exceeding 10,000 characters under sensitive keys receive keyed opaque hashes rather than skipping masking.
- **Formatter error handling:** Formatter masking failures now suppress records (`[BLINDLOG MASKING FAILED - RECORD SUPPRESSED]`) rather than leaking plaintext data.

---

## [1.1.0] — 2026-06-12

### Breaking Changes

- **Mask prefix updates:** Email pseudonyms use `blnd_ref_` prefix. Values use `blnd_ip_`, `blnd_key_`, `blnd_ph_`, `blnd_ssn_` prefixes.
- **Key matching strategy:** Suffix matching with delimiters (`_`, `-`, `.`) and camelCase/hyphen normalization.
- **Immutable configuration:** `BlindLogConfig` is a frozen dataclass with a `frozenset` of `sensitive_keys`.

### Added

- Phone number masking (`PHONE_REGEX`).
- SSN masking (`SSN_REGEX`).
- Expanded API key regex (OpenAI, Stripe, AWS, Slack, GitHub).
- IPv4 octet range validation (0-255).
- Pure ASGI middleware for FastAPI / Starlette with request/response body and header protection.
- Traceback exception sanitization in `BlindLogFormatter`.

---

## [0.1.0] — 2026-04-08

### Added

- Initial release.
- BLAKE2b deterministic pseudonymization engine.
- Structure-preserving email and credit card masking.
- Recursive DFS walker with cycle detection.
