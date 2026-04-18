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
            # Mask the message body
            if isinstance(record_copy.msg, (dict, list)):
                record_copy.msg = self.blind_logger.mask(copy.deepcopy(record_copy.msg))
            elif isinstance(record_copy.msg, str):
                record_copy.msg = self.blind_logger.mask(record_copy.msg)
                
            # Fix #1: Handle both tuple and dict-style log args
            if record_copy.args:
                args_copy = copy.deepcopy(record_copy.args)
                if isinstance(args_copy, dict):
                    # Mapping style: logger.info("%(name)s logged in", {"name": "user@example.com"})
                    record_copy.args = {
                        k: self.blind_logger.mask(v) if isinstance(v, (str, dict, list)) else v
                        for k, v in args_copy.items()
                    }
                elif isinstance(args_copy, tuple):
                    # Positional style: logger.info("Hello %s", "user@example.com")
                    record_copy.args = tuple(
                        self.blind_logger.mask(arg) if isinstance(arg, (str, dict, list)) else arg
                        for arg in args_copy
                    )

            # Fix #2: Mask exception info to prevent PII leaks in stack traces
            if record_copy.exc_info and record_copy.exc_info[0] is not None:
                exc_text = self.formatException(record_copy.exc_info)
                record_copy.exc_text = self.blind_logger.mask(exc_text)
                record_copy.exc_info = None  # Prevent super() from re-formatting unmasked

        except Exception as e:
            _log.error("BlindLog: Masking failed. Reason: %s", e)
            record_copy.msg = "[BLINDLOG MASKING FAILED - RECORD SUPPRESSED]"
            record_copy.args = None
            record_copy.exc_info = None
            record_copy.exc_text = None
            
        return super().format(record_copy)
