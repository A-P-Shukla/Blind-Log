import hashlib
import logging
from typing import Optional
from blindlog.rules import (
    EMAIL_REGEX, CREDIT_CARD_REGEX, IPV4_REGEX, API_KEY_REGEX, PHONE_REGEX, SSN_REGEX,
    OPAQUE_HASH_LEN, EMAIL_HASH_LEN, CC_HASH_LEN,
)
from blindlog.utils import walk_and_mask
from blindlog.config import BlindLogConfig
from blindlog.registry import RuleRegistry
from blindlog.interfaces import MaskingEngine, Payload

_log = logging.getLogger("blindlog.core")

class BlindLogger(MaskingEngine):
    """
    Core engine for Deterministic Pseudonymization and Structure-Preserving Masking.

    Thread safety: ``mask()`` is safe for concurrent use from multiple threads
    (per-call local state only). ``registry.register()`` is serialized, but
    prefer registering rules at process start before serving traffic.
    """
    def __init__(
        self, 
        config: Optional[BlindLogConfig] = None,
        **kwargs
    ):
        self.config = config if config else BlindLogConfig(**kwargs)
        
        self.registry = RuleRegistry(keyed_hash_fn=self._opaque)
        self.registry.register(EMAIL_REGEX, self._mask_email)
        self.registry.register(CREDIT_CARD_REGEX, self._mask_cc)
        self.registry.register(IPV4_REGEX, lambda v: f"{self._tag('ip')}{self._hash(v, length=OPAQUE_HASH_LEN)}")
        self.registry.register(API_KEY_REGEX, lambda v: f"{self._tag('key')}{self._hash(v, length=OPAQUE_HASH_LEN)}")
        self.registry.register(PHONE_REGEX, lambda v: f"{self._tag('ph')}{self._hash(v, length=OPAQUE_HASH_LEN)}")
        self.registry.register(SSN_REGEX, lambda v: f"{self._tag('ssn')}{self._hash(v, length=OPAQUE_HASH_LEN)}")

    def _tag(self, kind: str) -> str:
        """Build a mask prefix, optionally versioned with config.key_id."""
        kid = self.config.key_id
        if kind == "blind":
            return f"blind_{kid}:" if kid else "blind:"
        if kid:
            return f"blnd_{kid}_{kind}_"
        return f"blnd_{kind}_"

    def _opaque(self, value: str) -> str:
        return f"{self._tag('blind')}{self._hash(value, length=OPAQUE_HASH_LEN)}"
        
    def _hash(self, value: str, length: int = EMAIL_HASH_LEN) -> str:
        if length < 1:
            raise ValueError(f"BlindLog: hash length must be >= 1, got {length}")

        if not isinstance(value, str):
            value = str(value)
            
        digest_bytes = max(1, (length + 1) // 2)
        h = hashlib.blake2b(value.encode('utf-8'), key=self.config.blake_key, digest_size=digest_bytes)
        
        return h.hexdigest()[:length]

    def _mask_email(self, email: str) -> str:
        """Structure-preserving mask for emails: blnd_ref_HASH...@masked.com"""
        try:
            _local, _domain = email.rsplit('@', 1)
            hash_val = self._hash(email, length=EMAIL_HASH_LEN)
            return f"{self._tag('ref')}{hash_val}...@masked.com"
        except ValueError:
            return f"{self._tag('ref')}{self._hash(email, length=EMAIL_HASH_LEN)}...@masked.com"

    def _mask_cc(self, cc: str) -> str:
        """Structure-preserving mask for credit cards: 4111-abcdefgh-ijklmnop-1234 (64-bit)."""
        clean_cc = cc.replace("-", "").replace(" ", "")
        if len(clean_cc) >= 12:
            first_4 = clean_cc[:4]
            last_4 = clean_cc[-4:]
            hash_val = self._hash(clean_cc, length=CC_HASH_LEN)
            return f"{first_4}-{hash_val[:8]}-{hash_val[8:16]}-{last_4}"
        return self._hash(cc, length=CC_HASH_LEN)

    def _mask_value(self, value: str) -> str:
        # Force-path / keyed values: skip regex on huge inputs (ReDoS), but still
        # emit a keyed hash so sensitive fields remain correlatable and never leak.
        if len(value) > 10000:
            return self._opaque(value)
            
        return self.registry.process_value(value, self._opaque)

    def _mask_slow_path(self, text: str) -> str:
        # Free-text path: hashing the entire block would destroy log context.
        # Refuse regex scanning above the ReDoS threshold instead.
        if len(text) > 10000:
            return "<Skipped due to length: ReDoS Protection>"
            
        return self.registry.process_text(text)

    def mask(self, payload: Payload) -> Payload:
        """Public endpoint to mask a payload."""
        if self.config.debug_mode:
            return payload
            
        return walk_and_mask(
            data=payload, 
            sensitive_keys=self.config.sensitive_keys,
            mask_value_fn=self._mask_value,
            mask_text_fn=self._mask_slow_path
        )
