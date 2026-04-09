from typing import Callable, List, Tuple
import re

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
        """
        for pattern, callback in self._rules:
            if pattern.fullmatch(value):
                return callback(value)
        return fallback_callback(value)
        
    def process_text(self, text: str) -> str:
        """
        Cumulatively masks all recognized embedded objects within a standard string block.
        """
        for pattern, callback in self._rules:
            text = pattern.sub(lambda m: callback(m.group(0)), text)
        return text
