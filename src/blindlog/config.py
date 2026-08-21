import os
import re
import warnings
import hashlib
from dataclasses import dataclass, field
from typing import FrozenSet
from blindlog.rules import DEFAULT_SENSITIVE_KEYS

# key_id appears in mask prefixes (blnd_{key_id}_ref_...). Keep it short and
# structurally distinct from hex so MASKED_PATTERN can round-trip it.
_KEY_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,15}$")

# Fix #3: Use frozenset for sensitive_keys to prevent mutation.
# Fix #16: Note — `object.__setattr__` is used in __post_init__ to initialize
# computed fields on a frozen dataclass. This is a standard Python pattern.
# Any external code can also use `object.__setattr__` to bypass frozen protection —
# this is a Python language limitation, not a runtime-enforceable security boundary.
@dataclass(frozen=True)
class BlindLogConfig:
    secret_key: str = ""
    salt: str = ""
    sensitive_keys: FrozenSet[str] = field(default_factory=lambda: frozenset(DEFAULT_SENSITIVE_KEYS))
    debug_mode: bool = False
    # Optional rotation label embedded in mask prefixes (e.g. "v2" -> blnd_v2_ref_...).
    # Empty string keeps the unversioned v1.1 prefixes for backward compatibility.
    key_id: str = ""

    def __post_init__(self):
        if not self.secret_key:
            object.__setattr__(self, 'secret_key', os.environ.get("BLINDLOG_SECRET", ""))
        if not self.salt:
            object.__setattr__(self, 'salt', os.environ.get("BLINDLOG_SALT", ""))
        if not self.key_id:
            object.__setattr__(self, 'key_id', os.environ.get("BLINDLOG_KEY_ID", ""))

        if self.key_id and not _KEY_ID_RE.match(self.key_id):
            raise ValueError(
                "BlindLog: key_id must match ^[A-Za-z][A-Za-z0-9_]{0,15}$ "
                f"(got {self.key_id!r}). Example: 'v2'."
            )
        
        env_debug = os.environ.get("BLINDLOG_DEBUG", "").lower() in ("true", "1", "yes")
        if env_debug and not self.debug_mode:
            object.__setattr__(self, 'debug_mode', True)
        
        if not self.secret_key and not self.debug_mode:
            raise ValueError("BlindLog: BLINDLOG_SECRET is not set. Refusing to run in non-debug mode to prevent cryptographic bypass.")

        object.__setattr__(self, '_blake_key_cache', self._derive_blake_key())

    def _derive_blake_key(self) -> bytes:
        safe_secret = self.secret_key or ""
        safe_salt = self.salt or ""
        raw = (safe_secret + safe_salt).encode('utf-8')

        if len(raw) > 64:
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
        return self._blake_key_cache
