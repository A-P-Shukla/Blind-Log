__version__ = "1.2.1"
# Fix #15: Export all public-facing classes for clean DI
from blindlog.core import BlindLogger
from blindlog.config import BlindLogConfig
from blindlog.interfaces import MaskingEngine
from blindlog.rules import DEFAULT_SENSITIVE_KEYS

__all__ = ["__version__", "BlindLogger", "BlindLogConfig", "MaskingEngine", "DEFAULT_SENSITIVE_KEYS"]
