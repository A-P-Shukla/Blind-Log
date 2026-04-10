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
    sensitive_keys: Set[str] = field(default_factory=lambda: set(DEFAULT_SENSITIVE_KEYS))
    debug_mode: bool = False

    def __post_init__(self):
        # Resolve from Env if not provided
        self.secret_key = self.secret_key or os.environ.get("BLINDLOG_SECRET", "")
        self.salt = self.salt or os.environ.get("BLINDLOG_SALT", "")
        
        env_debug = os.environ.get("BLINDLOG_DEBUG", "").lower() in ("true", "1", "yes")
        self.debug_mode = self.debug_mode or env_debug
        
        if not self.secret_key and not self.debug_mode:
            raise ValueError("BlindLog: BLINDLOG_SECRET is not set. Refusing to run in non-debug mode to prevent cryptographic bypass.")

        # Fix #4: Cache the derived blake key at construction time, warn once
        self._blake_key_cache: Optional[bytes] = None
        self._compute_blake_key()

    def _compute_blake_key(self):
        """Derive and cache the BLAKE2b key. Warnings fire once at init, not per-hash."""
        safe_secret = self.secret_key or ""
        safe_salt = self.salt or ""
        raw = (safe_secret + safe_salt).encode('utf-8')

        if len(raw) > 64:
            warnings.warn(
                f"BlindLog: Combined secret+salt is {len(raw)} bytes, exceeding BLAKE2b's 64-byte key limit. "
                "Key will be derived via BLAKE2b digest to avoid silent truncation.",
                stacklevel=3
            )
            raw = hashlib.blake2b(raw, digest_size=64).digest()

        if len(raw) == 0:
            warnings.warn(
                "BlindLog: blake_key is empty. Hashes will be unkeyed and trivially reversible. "
                "This should only occur in debug_mode.",
                stacklevel=3
            )

        self._blake_key_cache = raw

    @property
    def blake_key(self) -> bytes:
        """Returns the cached BLAKE2b key."""
        return self._blake_key_cache
