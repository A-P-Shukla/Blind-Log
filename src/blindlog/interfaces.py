from abc import ABC, abstractmethod
from typing import Any, TypeVar

# TPayload loosely maps to JSON-serializable structures and primitives
TPayload = TypeVar('TPayload', str, int, float, bool, None, dict, list)

class MaskingEngine(ABC):
    """
    Formal Interface contract for Privacy-Preserving Observability engines.
    Enforces standardized execution methods to allow developers to safely substitute
    the default deterministic hash engine with proprietary ones (like AWS KMS or HashiCorp Vault)
    without disrupting downstream middleware plugins.
    """
    
    @abstractmethod
    def mask(self, payload: TPayload) -> TPayload:
        """
        Recursively process a payload (String, Dictionary, or List)
        and securely blind all matched sensitive nodes.
        """
        pass
