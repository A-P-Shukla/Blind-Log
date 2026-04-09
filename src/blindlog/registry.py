from typing import Callable, List, Tuple
import re
import logging

logger = logging.getLogger("blindlog.registry")

MaskCallback = Callable[[str], str]

class RuleRegistry:
    """
    Extensible configuration registry supporting mapping of deterministic 
    cryptographic functions to custom user-provided Regex patterns.
    """
    def __init__(self):
        # We enforce a prioritized sequential list of format evaluators
        self._rules: List[Tuple[re.Pattern, MaskCallback]] = []
        
    def register(self, pattern: re.Pattern, callback: MaskCallback):
        """
        Registers a customized fallback regex structure.
        """
        self._rules.append((pattern, callback))
        
    def process_value(self, value: str, fallback_callback: MaskCallback) -> str:
        """
        Executes strict Format Preserving matching. Escapes early if matched.
        Fix #8: Wraps callback invocations in try/except to prevent crashes from bad user rules.
        """
        for pattern, callback in self._rules:
            if pattern.fullmatch(value):
                try:
                    return callback(value)
                except Exception as e:
                    logger.warning(f"BlindLog: Callback failed for pattern {pattern.pattern}: {e}. Using fallback.")
                    return fallback_callback(value)
        return fallback_callback(value)
        
    def process_text(self, text: str) -> str:
        """
        Cumulatively masks all recognized embedded objects within a standard string block.
        Fix #8: Wraps callback invocations in try/except.
        """
        for pattern, callback in self._rules:
            def safe_sub(match, cb=callback, fb_hash=None):
                try:
                    return cb(match.group(0))
                except Exception as e:
                    logger.warning(f"BlindLog: Callback failed during text scan: {e}. Leaving match intact.")
                    return match.group(0)
            text = pattern.sub(safe_sub, text)
        return text
