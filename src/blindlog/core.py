import os
import hashlib
from typing import Any, Dict, List, Optional
from blindlog.rules import EMAIL_REGEX, CREDIT_CARD_REGEX, DEFAULT_SENSITIVE_KEYS
from blindlog.utils import walk_and_mask

class BlindLogger:
    """
    Core engine for Deterministic Pseudonymization and Structure-Preserving Masking.
    """
    def __init__(
        self, 
        secret_key: Optional[str] = None, 
        salt: Optional[str] = None,
        sensitive_keys: Optional[set] = None,
        debug_mode: bool = False
    ):
        # Load configuration, prioritizing passed args over environment variables
        self.secret_key = secret_key or os.environ.get("BLINDLOG_SECRET", "")
        self.salt = salt or os.environ.get("BLINDLOG_SALT", "")
        self.sensitive_keys = sensitive_keys or DEFAULT_SENSITIVE_KEYS
        
        # In debug mode, we bypass masking entirely
        env_debug = os.environ.get("BLINDLOG_DEBUG", "").lower() in ("true", "1", "yes")
        self.debug_mode = debug_mode or env_debug

        if not self.secret_key and not self.debug_mode:
            raise ValueError("BlindLog: BLINDLOG_SECRET is not set. Refusing to run in non-debug mode to prevent cryptographic bypass.")

        # BLAKE2b supports keys up to 64 bytes. We ensure our bytes fit within the bounds.
        self._blake_key = (self.secret_key + self.salt).encode('utf-8')[:64]
        
    def _hash(self, value: str, length: int = 12) -> str:
        """
        Generates a deterministic BLAKE2b hash.
        Utilizes native cryptographic length scaling (digest_size).
        """
        if not isinstance(value, str):
            value = str(value)
            
        digest_bytes = max(1, (length + 1) // 2)
        h = hashlib.blake2b(value.encode('utf-8'), key=self._blake_key, digest_size=digest_bytes)
        
        # Slicing is still applied in case 'length' requested is odd (e.g. 5 bytes -> 10 hex chars string, etc)
        return h.hexdigest()[:length]

    def _mask_email(self, email: str) -> str:
        """Structure-preserving mask for emails: ref_HASH...@masked.com"""
        try:
            local, domain = email.rsplit('@', 1)
            hash_val = self._hash(email, length=12)
            return f"ref_{hash_val}...@masked.com"
        except ValueError:
            return self._hash(email) # Fallback if not strictly an email

    def _mask_cc(self, cc: str) -> str:
        """Structure-preserving mask for credit cards: 4111-xxxx-xxxx-1234"""
        clean_cc = cc.replace("-", "").replace(" ", "")
        if len(clean_cc) >= 12:
            first_4 = clean_cc[:4]
            last_4 = clean_cc[-4:]
            hash_val = self._hash(clean_cc, length=12)
            # Use 12 hex digits in the middle to maintain high entropy: 4111-abcdef-abcdef-1234
            return f"{first_4}-{hash_val[:6]}-{hash_val[6:12]}-{last_4}"
        return self._hash(cc)

    def _mask_value(self, value: str) -> str:
        """
        The hybrid evaluation for a single string value.
        Determines the format, applies the relevant mask.
        """
        if EMAIL_REGEX.fullmatch(value):
            return self._mask_email(value)
        elif CREDIT_CARD_REGEX.fullmatch(value):
            return self._mask_cc(value)
        else:
            # Generic string fallback
            return f"blind:{self._hash(value, length=10)}"

    def _mask_slow_path(self, text: str) -> str:
        """
        Slow path: scans arbitrary text for embedded PII.
        E.g., "User akhand@gmail.com failed."
        Limits evaluation to 10,000 characters to prevent ReDoS.
        """
        if len(text) > 10000:
            return "<Skipped due to length: ReDoS Protection>"
            
        # Replace found emails
        text = EMAIL_REGEX.sub(lambda m: self._mask_email(m.group(0)), text)
        # Replace found CCs
        text = CREDIT_CARD_REGEX.sub(lambda m: self._mask_cc(m.group(0)), text)
        text = CREDIT_CARD_REGEX.sub(lambda m: self._mask_cc(m.group(0)), text)
        return text

    def mask(self, payload: Any) -> Any:
        """
        Public endpoint to mask a payload.
        """
        if self.debug_mode:
            return payload
            
        return walk_and_mask(
            data=payload, 
            sensitive_keys=self.sensitive_keys,
            mask_value_fn=self._mask_value,
            mask_text_fn=self._mask_slow_path
        )
