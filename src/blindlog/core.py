import hashlib
import hmac
import re
import threading
from typing import Optional
from blindlog.rules import (
    EMAIL_REGEX, CREDIT_CARD_REGEX, IPV4_REGEX, API_KEY_REGEX, PHONE_REGEX, SSN_REGEX,
    EMAIL_HASH_LEN,
)
from blindlog.utils import walk_and_mask
from blindlog.config import BlindLogConfig
from blindlog.registry import RuleRegistry
from blindlog.interfaces import MaskingEngine, Payload

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
        self._authenticated_masks: set[str] = set()
        self._authenticated_masks_lock = threading.RLock()
        
        self.registry = RuleRegistry(
            keyed_hash_fn=self._opaque,
            masked_verifier=self._is_authenticated_mask,
            mask_recorder=self._remember_mask,
        )
        self.registry.register(EMAIL_REGEX, self._mask_email)
        self.registry.register(CREDIT_CARD_REGEX, self._mask_cc)
        self.registry.register(IPV4_REGEX, lambda v: f"{self._tag('ip')}{self._signed_hash(v, 'ip')}")
        self.registry.register(API_KEY_REGEX, lambda v: f"{self._tag('key')}{self._signed_hash(v, 'key')}")
        self.registry.register(PHONE_REGEX, lambda v: f"{self._tag('ph')}{self._signed_hash(v, 'ph')}")
        self.registry.register(SSN_REGEX, lambda v: f"{self._tag('ssn')}{self._signed_hash(v, 'ssn')}")

    def tag(self, kind: str) -> str:
        """Public helper to build a mask prefix, optionally versioned with config.key_id."""
        kid = self.config.key_id
        if kind == "blind":
            return f"blind_{kid}:" if kid else "blind:"
        if kid:
            return f"blnd_{kid}_{kind}_"
        return f"blnd_{kind}_"

    def _tag(self, kind: str) -> str:
        return self.tag(kind)

    def _auth_hex(self, material: str, length: int = 8) -> str:
        return hmac.new(
            self.config.blake_key,
            material.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:length]

    def _signed_hash(self, value: str, kind: str) -> str:
        payload_hash = self._hash(value, length=8)
        auth = self._auth_hex(f"{kind}\x00{payload_hash}", length=8)
        return payload_hash + auth

    def _remember_mask(self, value: str) -> None:
        with self._authenticated_masks_lock:
            self._authenticated_masks.add(value)

    def _verify_signed(self, value: str, prefix: str, kind: str) -> bool:
        if not value.startswith(prefix) or len(value) != len(prefix) + 16:
            return False
        payload = value[len(prefix):]
        if not re.fullmatch(r"[0-9a-f]{16}", payload):
            return False
        return hmac.compare_digest(
            payload[8:],
            self._auth_hex(f"{kind}\x00{payload[:8]}", length=8),
        )

    def _is_authenticated_mask(self, value: str) -> bool:
        if not isinstance(value, str):
            return False

        with self._authenticated_masks_lock:
            if value in self._authenticated_masks:
                return True

        if value.startswith(self._tag("blind")):
            return self._verify_signed(value, self._tag("blind"), "blind")

        email_match = re.fullmatch(
            re.escape(self._tag("ref")) + r"([0-9a-f]{16})\.\.\.@masked\.com",
            value,
        )
        if email_match:
            payload = email_match.group(1)
            return hmac.compare_digest(
                payload[8:],
                self._auth_hex(f"ref\x00{payload[:8]}", length=8),
            )

        cc_match = re.fullmatch(r"(\d{4})-([0-9a-f]{8})-([0-9a-f]{8})-(\d{4})", value)
        if cc_match:
            first, hash_part, auth_part, last = cc_match.groups()
            return hmac.compare_digest(
                auth_part,
                self._auth_hex(
                    f"cc\x00{first}\x00{hash_part}\x00{last}",
                    length=8,
                ),
            )

        generic_match = re.fullmatch(
            r"blnd(?:_[A-Za-z][A-Za-z0-9_]{0,15})?_([a-z0-9_]{1,16})_([0-9a-f]{16})",
            value,
        )
        if generic_match:
            kind, payload = generic_match.groups()
            return hmac.compare_digest(
                payload[8:],
                self._auth_hex(f"{kind}\x00{payload[:8]}", length=8),
            )

        return False

    def hash_text(self, value: str, length: int = EMAIL_HASH_LEN) -> str:
        """Public deterministic keyed BLAKE2b hashing method."""
        return self._hash(value, length=length)

    def _opaque(self, value: str) -> str:
        return f"{self._tag('blind')}{self._signed_hash(value, 'blind')}"
        
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
        hash_val = self._signed_hash(email, 'ref')
        return f"{self._tag('ref')}{hash_val}...@masked.com"

    def _mask_cc(self, cc: str) -> str:
        """Structure-preserving mask for credit cards: 4111-abcdefgh-ijklmnop-1234 (64-bit)."""
        clean_cc = cc.replace("-", "").replace(" ", "")
        if len(clean_cc) >= 12:
            first_4 = clean_cc[:4]
            last_4 = clean_cc[-4:]
            hash_part = self._hash(clean_cc, length=8)
            auth_part = self._auth_hex(
                f"cc\x00{first_4}\x00{hash_part}\x00{last_4}",
                length=8,
            )
            return f"{first_4}-{hash_part}-{auth_part}-{last_4}"
        hash_part = self._hash(cc, length=8)
        auth_part = self._auth_hex(
            f"cc\x00{cc[:4]}\x00{hash_part}\x00{cc[-4:]}",
            length=8,
        )
        return f"{cc[:4]}-{hash_part}-{auth_part}-{cc[-4:]}"

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
