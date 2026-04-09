import os
from dataclasses import dataclass, field
from typing import Optional, Set
from blindlog.rules import DEFAULT_SENSITIVE_KEYS

@dataclass
class BlindLogConfig:
    secret_key: Optional[str] = None
    salt: Optional[str] = None
    sensitive_keys: Set[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_KEYS)
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
        return (safe_secret + safe_salt).encode('utf-8')[:64]
