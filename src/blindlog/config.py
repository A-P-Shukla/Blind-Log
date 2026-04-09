import os
import warnings
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Set
from blindlog.rules import DEFAULT_SENSITIVE_KEYS

@dataclass
class BlindLogConfig:
    secret_key: Optional[str] = None
    salt: Optional[str] = None
    sensitive_keys: Set[str] = field(default_factory=lambda: set(DEFAULT_SENSITIVE_KEYS))  # Fix #1: copy, not reference
    debug_mode: bool = False

    def __post_init__(self):
        # Resolve from Env if not provided
        self.secret_key = self.secret_key or os.environ.get("BLINDLOG_SECRET", "")
        self.salt = self.salt or os.environ.get("BLINDLOG_SALT", "")
        
        env_debug = os.environ.get("BLINDLOG_DEBUG", "").lower() in ("true", "1", "yes")
        self.debug_mode = self.debug_mode or env_debug
        
        if not self.secret_key and not self.debug_mode:
            raise ValueError("BlindLog: BLINDLOG_SECRET is not set. Refusing to run in non-debug mode to prevent cryptographic bypass.")

    @property
    def blake_key(self) -> bytes:
        """
        BLAKE2b supports keys up to 64 bytes. 
        We ensure our concatenated bytes fit within standard structural bounds.
        """
        safe_secret = self.secret_key or ""
        safe_salt = self.salt or ""
        raw = (safe_secret + safe_salt).encode('utf-8')

        # Fix #12: Warn if key material is being silently truncated
        if len(raw) > 64:
            warnings.warn(
                f"BlindLog: Combined secret+salt is {len(raw)} bytes, exceeding BLAKE2b's 64-byte key limit. "
                "Key will be derived via BLAKE2b digest to avoid silent truncation. "
                "Consider using a shorter secret or removing the salt.",
                stacklevel=2
            )
            # Derive a fixed 64-byte key instead of raw truncation
            raw = hashlib.blake2b(raw, digest_size=64).digest()

        # Fix #14: Guard against empty key in non-debug mode
        if len(raw) == 0:
            warnings.warn(
                "BlindLog: blake_key is empty. Hashes will be unkeyed and trivially reversible. "
                "This should only occur in debug_mode.",
                stacklevel=2
            )

        return raw
