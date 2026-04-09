from abc import ABC, abstractmethod
from typing import Any, Union

# Fix #18: Use Union instead of constrained TypeVar for correct type semantics
Payload = Union[str, int, float, bool, None, dict, list]

class MaskingEngine(ABC):
    """
    Formal Interface contract for Privacy-Preserving Observability engines.
    Enforces standardized execution methods to allow developers to safely substitute
    the default deterministic hash engine with proprietary ones (like AWS KMS or HashiCorp Vault)
    without disrupting downstream middleware plugins.
    """
    
    @abstractmethod
    def mask(self, payload: Any) -> Any:
        """
        Recursively process a payload (String, Dictionary, or List)
        and securely blind all matched sensitive nodes.
        """
        pass
