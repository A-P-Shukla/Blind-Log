import logging
import copy
from typing import Optional
from blindlog.interfaces import MaskingEngine

class BlindLogFormatter(logging.Formatter):
    """
    A custom logging formatter that intercepts and pseudonymizes sensitive data 
    before it is written to the log stream.
    """
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, style: str = '%', blind_logger: Optional[MaskingEngine] = None):
        super().__init__(fmt, datefmt, style)
        # Fix #9: Defer BlindLogger construction to avoid crashing if BLINDLOG_SECRET is not set at import time
        self._blind_logger = blind_logger
        self._initialized = blind_logger is not None

    @property
    def blind_logger(self):
        if not self._initialized:
            from blindlog.core import BlindLogger
            self._blind_logger = BlindLogger()
            self._initialized = True
        return self._blind_logger

    def format(self, record: logging.LogRecord) -> str:
        """
        Intercept the log record before formatting. Mask structural arguments and 
        the string payload if necessary. To prevent mutating shared objects, perform
        a copy before modification.
        """
        # Shallow copy the record so we don't accidentally mutate the global log record
        record_copy = copy.copy(record)
        
        try:
            # Check if msg is structural (dict/list) vs generic string
            if isinstance(record_copy.msg, (dict, list)):
                record_copy.msg = self.blind_logger.mask(copy.deepcopy(record_copy.msg))
            elif isinstance(record_copy.msg, str):
                record_copy.msg = self.blind_logger.mask(record_copy.msg)
                
            # Intercept args representing positional string interpolations
            if record_copy.args:
                args_copy = copy.deepcopy(record_copy.args)
                masked_args = tuple(self.blind_logger.mask(arg) if isinstance(arg, (str, dict, list)) else arg 
                                  for arg in args_copy)
                record_copy.args = masked_args
        except Exception:
            # Ensure the logging pipeline never breaks the application, even if masking fails
            pass
            
        return super().format(record_copy)
