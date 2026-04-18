import hashlib
import logging
from typing import Any, Dict, List, Optional
from blindlog.rules import EMAIL_REGEX, CREDIT_CARD_REGEX, IPV4_REGEX, API_KEY_REGEX, PHONE_REGEX, SSN_REGEX
from blindlog.utils import walk_and_mask
from blindlog.config import BlindLogConfig
from blindlog.registry import RuleRegistry
from blindlog.interfaces import MaskingEngine, Payload

_log = logging.getLogger("blindlog.core")

class BlindLogger(MaskingEngine):
    """
    Core engine for Deterministic Pseudonymization and Structure-Preserving Masking.
    """
    def __init__(
        self, 
        config: Optional[BlindLogConfig] = None,
        **kwargs
    ):
        self.config = config if config else BlindLogConfig(**kwargs)
        
        self.registry = RuleRegistry(keyed_hash_fn=lambda v: f"blind:{self._hash(v, length=10)}")
        self.registry.register(EMAIL_REGEX, self._mask_email)
        self.registry.register(CREDIT_CARD_REGEX, self._mask_cc)
        self.registry.register(IPV4_REGEX, lambda v: f"blnd_ip_{self._hash(v, length=10)}")
        self.registry.register(API_KEY_REGEX, lambda v: f"blnd_key_{self._hash(v, length=10)}")
        self.registry.register(PHONE_REGEX, lambda v: f"blnd_ph_{self._hash(v, length=10)}")
        self.registry.register(SSN_REGEX, lambda v: f"blnd_ssn_{self._hash(v, length=10)}")
        
    def _hash(self, value: str, length: int = 12) -> str:
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
            local, domain = email.rsplit('@', 1)
            hash_val = self._hash(email, length=12)
            return f"blnd_ref_{hash_val}...@masked.com"
        except ValueError:
            return f"blnd_ref_{self._hash(email)}...@masked.com"

    def _mask_cc(self, cc: str) -> str:
        """Structure-preserving mask for credit cards: 4111-abcdef-abcdef-1234"""
        clean_cc = cc.replace("-", "").replace(" ", "")
        if len(clean_cc) >= 12:
            first_4 = clean_cc[:4]
            last_4 = clean_cc[-4:]
            hash_val = self._hash(clean_cc, length=12)
            return f"{first_4}-{hash_val[:6]}-{hash_val[6:12]}-{last_4}"
        return self._hash(cc)

    def _mask_value(self, value: str) -> str:
        if len(value) > 10000:
            return "<Skipped due to length: ReDoS Protection>"
            
        fallback_hash = lambda v: f"blind:{self._hash(v, length=10)}"
        return self.registry.process_value(value, fallback_hash)

    def _mask_slow_path(self, text: str) -> str:
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
