import os
import warnings
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Set
from blindlog.rules import DEFAULT_SENSITIVE_KEYS

# Fix #5 + #7: Frozen dataclass prevents mutation of debug_mode and stale blake_key cache
@dataclass(frozen=True)
class BlindLogConfig:
    secret_key: str = ""
    salt: str = ""
    sensitive_keys: Set[str] = field(default_factory=lambda: set(DEFAULT_SENSITIVE_KEYS))
    debug_mode: bool = False

    def __post_init__(self):
        # Resolve from Env if not provided (use object.__setattr__ because frozen)
        if not self.secret_key:
            object.__setattr__(self, 'secret_key', os.environ.get("BLINDLOG_SECRET", ""))
        if not self.salt:
            object.__setattr__(self, 'salt', os.environ.get("BLINDLOG_SALT", ""))
        
        env_debug = os.environ.get("BLINDLOG_DEBUG", "").lower() in ("true", "1", "yes")
        if env_debug and not self.debug_mode:
            object.__setattr__(self, 'debug_mode', True)
        
        if not self.secret_key and not self.debug_mode:
            raise ValueError("BlindLog: BLINDLOG_SECRET is not set. Refusing to run in non-debug mode to prevent cryptographic bypass.")

        # Compute and cache the blake key once at init
        object.__setattr__(self, '_blake_key_cache', self._derive_blake_key())

    def _derive_blake_key(self) -> bytes:
        """Derive the BLAKE2b key from secret+salt. Warns once at init."""
        safe_secret = self.secret_key or ""
        safe_salt = self.salt or ""
        raw = (safe_secret + safe_salt).encode('utf-8')

        if len(raw) > 64:
            # Fix #16: stacklevel=5 to point to user's call site
            warnings.warn(
                f"BlindLog: Combined secret+salt is {len(raw)} bytes, exceeding BLAKE2b's 64-byte key limit. "
                "Key will be derived via BLAKE2b digest to avoid silent truncation.",
                stacklevel=5
            )
            raw = hashlib.blake2b(raw, digest_size=64).digest()

        if len(raw) == 0:
            warnings.warn(
                "BlindLog: blake_key is empty. Hashes will be unkeyed and trivially reversible.",
                stacklevel=5
            )

        return raw

    @property
    def blake_key(self) -> bytes:
        """Returns the cached BLAKE2b key."""
        return self._blake_key_cache
