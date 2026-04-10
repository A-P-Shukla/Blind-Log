import logging
import copy
from typing import Optional
from blindlog.interfaces import MaskingEngine

_log = logging.getLogger("blindlog.formatter")

class BlindLogFormatter(logging.Formatter):
    """
    A custom logging formatter that intercepts and pseudonymizes sensitive data 
    before it is written to the log stream.
    """
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, style: str = '%', blind_logger: Optional[MaskingEngine] = None):
        super().__init__(fmt, datefmt, style)
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
        record_copy = copy.copy(record)
        
        try:
            if isinstance(record_copy.msg, (dict, list)):
                record_copy.msg = self.blind_logger.mask(copy.deepcopy(record_copy.msg))
            elif isinstance(record_copy.msg, str):
                record_copy.msg = self.blind_logger.mask(record_copy.msg)
                
            if record_copy.args:
                args_copy = copy.deepcopy(record_copy.args)
                masked_args = tuple(self.blind_logger.mask(arg) if isinstance(arg, (str, dict, list)) else arg 
                                  for arg in args_copy)
                record_copy.args = masked_args
        except Exception as e:
            # Fix #3: Log an error instead of silently passing PII through
            _log.error(
                "BlindLog: Masking failed, log record emitted UNMASKED. Reason: %s", e
            )
            
        return super().format(record_copy)
