import logging
import copy
from typing import Optional
from blindlog.core import BlindLogger

class BlindLogFormatter(logging.Formatter):
    """
    A custom logging formatter that intercepts and pseudonymizes sensitive data 
    before it is written to the log stream.
    """
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, style: str = '%', logger: Optional[BlindLogger] = None):
        super().__init__(fmt, datefmt, style)
        self.blind_logger = logger or BlindLogger()

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
                masked_args = tuple(self.blind_logger.mask(arg) if isinstance(arg, (str, dict, list)) else arg 
                                  for arg in record_copy.args)
                record_copy.args = masked_args
        except Exception:
            # Ensure the logging pipeline never breaks the application, even if masking fails
            pass
            
        return super().format(record_copy)
