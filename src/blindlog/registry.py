from typing import Callable, List, Tuple
import re
import hashlib
import logging

_log = logging.getLogger("blindlog.registry")

MaskCallback = Callable[[str], str]

class RuleRegistry:
    """
    Extensible configuration registry supporting mapping of deterministic 
    cryptographic functions to custom user-provided Regex patterns.
    """
    def __init__(self):
        self._rules: List[Tuple[re.Pattern, MaskCallback]] = []
        # Fix #7: Import sentinel prefixes for idempotency checks
        from blindlog.rules import MASKED_PREFIXES
        self._masked_prefixes = MASKED_PREFIXES
        
    def register(self, pattern: re.Pattern, callback: MaskCallback):
        """Registers a customized fallback regex structure."""
        self._rules.append((pattern, callback))

    def _is_already_masked(self, value: str) -> bool:
        """Fix #7: Check if a value has already been masked to ensure idempotency."""
        return any(value.startswith(prefix) for prefix in self._masked_prefixes)
        
    def process_value(self, value: str, fallback_callback: MaskCallback) -> str:
        """
        Executes strict Format Preserving matching. Escapes early if matched.
        Wraps callbacks in try/except. Skips already-masked values.
        """
        # Fix #7: Idempotency — skip already-masked values
        if self._is_already_masked(value):
            return value

        for pattern, callback in self._rules:
            if pattern.fullmatch(value):
                try:
                    return callback(value)
                except Exception as e:
                    _log.warning(f"BlindLog: Callback failed for pattern {pattern.pattern}: {e}. Using fallback.")
                    return fallback_callback(value)
        return fallback_callback(value)
        
    def process_text(self, text: str) -> str:
        """
        Cumulatively masks all recognized embedded objects within a standard string block.
        Fix #5: On callback failure, apply a fallback hash instead of returning original PII.
        Fix #7: Skip already-masked values.
        """
        for pattern, callback in self._rules:
            def safe_sub(match, cb=callback):
                matched = match.group(0)
                # Fix #7: Skip already-masked tokens
                if self._is_already_masked(matched):
                    return matched
                try:
                    return cb(matched)
                except Exception as e:
                    _log.warning(f"BlindLog: Callback failed during text scan: {e}. Applying fallback hash.")
                    # Fix #5: Fallback hash instead of returning original PII
                    return f"blind:{hashlib.blake2b(matched.encode(), digest_size=5).hexdigest()}"
            text = pattern.sub(safe_sub, text)
        return text
