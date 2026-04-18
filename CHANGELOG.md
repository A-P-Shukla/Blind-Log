# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] — 2026-04-18

### Breaking Changes

> **IMPORTANT:** These changes alter masking behavior and output formats.
> Users upgrading from earlier versions should review their log parsing pipelines.

- **Masked output prefix changed:** Email pseudonyms now use `blnd_ref_` prefix instead of `ref_` (e.g. `blnd_ref_81ca7b82f012...@masked.com`). Other masked values use `blnd_ip_`, `blnd_key_`, `blnd_ph_`, `blnd_ssn_` prefixes respectively.
- **Key matching strategy changed:** From substring matching (v1.0) → exact + suffix matching (v1.1). Fields are masked if the key name exactly matches a sensitive key OR ends with `_<key>`, `-<key>`, or `.<key>`. camelCase keys like `refreshToken` are normalized to `refresh_token` before matching.
- **`sensitive_keys` is now a `frozenset`:** Cannot be mutated after config construction. Pass a custom `frozenset` at construction time to override.
- **`BlindLogConfig` is frozen:** All config fields are immutable after construction. Use `object.__setattr__` only in `__post_init__` for computed fields.

### Added

- **Phone number masking:** `PHONE_REGEX` detects NANP and international phone numbers. `phone` and `mobile` added to `DEFAULT_SENSITIVE_KEYS`.
- **SSN masking:** `SSN_REGEX` detects US Social Security Numbers. `ssn_number` added to `DEFAULT_SENSITIVE_KEYS`.
- **API key coverage expanded:** Stripe (`sk_live_`, `sk_test_`), AWS (`AKIA...`), Slack (`xox[bpas]-`), GitHub fine-grained PATs (`github_pat_`) now detected.
- **IPv4 validation:** Octet range validation (0-255) prevents false positives on version strings.
- **camelCase key normalization:** `refreshToken`, `APIKey`, `OAuth2Token` etc. are normalized to snake_case before matching.
- **Dot-separated key support:** `user.password`, `auth.token` detected via `.` separator.
- **Response body masking:** FastAPI middleware now intercepts and masks response bodies (with 5MB OOM guard).
- **Idempotent masking:** `mask()` safe to call multiple times — sentinel-prefixed values skipped.
- **Exception trace masking:** `BlindLogFormatter` masks `exc_info` stack traces to prevent PII leaks.
- **Dict-style log args:** `BlindLogFormatter` correctly handles `logging.info("%(name)s", {"name": "user@example.com"})`.
- **Lazy initialization:** Both `BlindLogFormatter` and `BlindLogFastAPIMiddleware` defer `BlindLogger()` construction — no crash if `BLINDLOG_SECRET` is absent at import time.
- **Key derivation caching:** `blake_key` computed once at config init, not per hash call.
- **Key normalization caching:** `normalize_key()` uses `lru_cache(2048)` for high-throughput scenarios.
- **Registry keyed fallback:** Callback failures in `process_text` now use a keyed BLAKE2b hash, not a rainbow-table-reversible unkeyed hash.
- **`MaskingEngine` and `BlindLogConfig` exported:** Available from top-level `from blindlog import MaskingEngine, BlindLogConfig`.
- **Duplicate HTTP headers preserved:** Middleware logs headers as list-of-tuples, not dict.
- **Non-UTF-8 header safety:** `errors='replace'` prevents `UnicodeDecodeError` crashes.
- **`http.disconnect` forwarding:** Middleware `receive_proxy` forwards real ASGI events after buffer is exhausted.

### Removed

- **`key` from `DEFAULT_SENSITIVE_KEYS`:** Too many false positives (`primary_key`, `foreign_key`, `cache_key`). Use `private_key`, `api_key`, `secret_key`, `signing_key`, `encryption_key` instead.
- **`cell` and `telephone` from `DEFAULT_SENSITIVE_KEYS`:** Too many false positives (`fuel_cell`). Phone detection relies on `phone`, `mobile` keys and `PHONE_REGEX` value scanning.

### Fixed

- `DEFAULT_SENSITIVE_KEYS` mutable singleton — each config gets its own `frozenset` copy
- Operator precedence bug: `None` under sensitive keys now properly masked
- Credit card test assertions updated to match actual hash-based format
- `print()` replaced with `logging.getLogger()` throughout middleware
- `BlindLogFormatter` masking failure now suppresses record instead of leaking PII
- `warnings.warn` stacklevel corrected to point at user call site
- Hardcoded Windows paths replaced with `os.path.dirname(__file__)`
- `pyproject.toml` `pythonpath` configured for pytest

## [0.1.0] — 2026-04-08

### Added

- Initial release
- BLAKE2b deterministic pseudonymization
- Structure-preserving email and credit card masking
- Recursive DFS walker with cycle detection
- FastAPI ASGI middleware
- `BlindLogFormatter` for standard library `logging`
- ReDoS protection (10,000 char limit)
- OOM protection (5MB buffer limit)
