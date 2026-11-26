from typing import Callable, List, Tuple, Optional
import re
import logging
import threading

_log = logging.getLogger("blindlog.registry")

MaskCallback = Callable[[str], str]

class RuleRegistry:
    """
    Extensible configuration registry supporting mapping of deterministic 
    cryptographic functions to custom user-provided Regex patterns.

    ``register()`` and the process methods share a lock so concurrent
    ``mask()`` calls are safe. Prefer registering rules at startup.
    """
    def __init__(self, keyed_hash_fn: Optional[MaskCallback] = None):
        self._rules: List[Tuple[re.Pattern, MaskCallback]] = []
        self._keyed_hash_fn = keyed_hash_fn
        self._lock = threading.RLock()
        self._emitted_masks = set()
        
    def register(self, pattern: re.Pattern, callback: MaskCallback):
        """Registers a customized fallback regex structure."""
        with self._lock:
            self._rules.append((pattern, callback))

    def _is_already_masked(self, value: str) -> bool:
        """Check only masks emitted by this registry during the process."""
        with self._lock:
            return value in self._emitted_masks

    def _remember_mask(self, value: str) -> str:
        if isinstance(value, str):
            with self._lock:
                self._emitted_masks.add(value)
        return value

    def _secure_fallback(self, value: str) -> str:
        """Produce a keyed fallback hash."""
        if self._keyed_hash_fn:
            return self._remember_mask(self._keyed_hash_fn(value))
        import hashlib
        _log.warning("BlindLog: Using unkeyed fallback hash — keyed_hash_fn not configured.")
        return self._remember_mask(f"blind:{hashlib.blake2b(value.encode(), digest_size=8).hexdigest()}")
        
    def process_value(self, value: str, fallback_callback: MaskCallback) -> str:
        """
        Executes strict Format Preserving matching. Escapes early if matched.
        Wraps callbacks in try/except. Skips already-masked values.
        """
        # Fix #10: More precise idempotency check — require sentinel + hex pattern
        if self._is_already_masked(value):
            return value

        with self._lock:
            rules = tuple(self._rules)

        for pattern, callback in rules:
            if pattern.fullmatch(value):
                try:
                    return self._remember_mask(callback(value))
                except Exception as e:
                    _log.warning(f"BlindLog: Callback failed for pattern {pattern.pattern}: {e}. Using fallback.")
                    return self._remember_mask(fallback_callback(value))
        return self._remember_mask(fallback_callback(value))
        
    def process_text(self, text: str) -> str:
        """
        Cumulatively masks all recognized embedded objects within a standard string block.
        On callback failure, applies a keyed fallback hash.
        """
        with self._lock:
            rules = tuple(self._rules)

        for pattern, callback in rules:
            def safe_sub(match, cb=callback):
                matched = match.group(0)
                if self._is_already_masked(matched):
                    return matched
                try:
                    return self._remember_mask(cb(matched))
                except Exception as e:
                    _log.warning(f"BlindLog: Callback failed during text scan: {e}. Applying keyed fallback.")
                    return self._secure_fallback(matched)
            text = pattern.sub(safe_sub, text)
        return text
