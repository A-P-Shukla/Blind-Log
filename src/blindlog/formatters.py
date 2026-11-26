import logging
import copy
import re
import string
from typing import Optional
from blindlog.interfaces import MaskingEngine

_log = logging.getLogger("blindlog.formatter")

_RESERVED_RECORD_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime"
})

class BlindLogFormatter(logging.Formatter):
    """
    A custom logging formatter that intercepts and pseudonymizes sensitive data 
    before it is written to the log stream.
    """
    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None, style: str = '%', blind_logger: Optional[MaskingEngine] = None):
        super().__init__(fmt, datefmt, style)
        self._blind_logger = blind_logger
        self._initialized = blind_logger is not None
        self._blindlog_style = style

    @property
    def blind_logger(self):
        if not self._initialized:
            from blindlog.core import BlindLogger
            self._blind_logger = BlindLogger()
            self._initialized = True
        return self._blind_logger

    def _mask_with_key(self, key: str, value):
        masked = self.blind_logger.mask({key: value})
        if isinstance(masked, dict):
            return masked.get(key, value)
        return masked

    def _infer_positional_keys(self, message, args_count: int) -> dict:
        if not isinstance(message, str):
            return {}

        keys = {}

        if self._blindlog_style == '%':
            placeholder_re = re.compile(
                r'([A-Za-z_][A-Za-z0-9_.-]*)\s*(?:=|:)\s*'
                r'%(?:[#0 +\-]*\d*(?:\.\d+)?[diouxXeEfFgGcrsa])'
            )
            for index, match in enumerate(placeholder_re.finditer(message)):
                if index >= args_count:
                    break
                keys[index] = match.group(1)

        elif self._blindlog_style in ('{', '$'):
            try:
                positional_index = 0
                for _, field_name, _, _ in string.Formatter().parse(message):
                    if not field_name:
                        continue
                    if field_name.isdigit():
                        index = int(field_name)
                    else:
                        root_name = field_name.split('.')[0].split('[')[0]
                        index = positional_index
                        if index < args_count:
                            keys[index] = root_name
                    positional_index += 1
            except (KeyError, ValueError):
                pass

        return keys

    def format(self, record: logging.LogRecord) -> str:
        record_copy = copy.copy(record)
        
        try:
            # Mask the message body
            if isinstance(record_copy.msg, (dict, list)):
                record_copy.msg = self.blind_logger.mask(copy.deepcopy(record_copy.msg))
            elif isinstance(record_copy.msg, str):
                record_copy.msg = self.blind_logger.mask(record_copy.msg)
                
            # Handle both tuple and dict-style log args
            if record_copy.args:
                args_copy = copy.deepcopy(record_copy.args)
                if isinstance(args_copy, dict):
                    # Mapping style: logger.info("%(name)s logged in", {"name": "user@example.com"})
                    record_copy.args = {
                        k: self._mask_with_key(k, v)
                        for k, v in args_copy.items()
                    }
                elif isinstance(args_copy, tuple):
                    # Positional style: logger.info("Hello %s", "user@example.com")
                    positional_keys = self._infer_positional_keys(record_copy.msg, len(args_copy))
                    record_copy.args = tuple(
                        self._mask_with_key(positional_keys[index], arg)
                        if index in positional_keys
                        else self.blind_logger.mask(arg)
                        for index, arg in enumerate(args_copy)
                    )

            # Mask exception info to prevent PII leaks in stack traces
            if record_copy.exc_info and record_copy.exc_info[0] is not None:
                exc_text = self.formatException(record_copy.exc_info)
                record_copy.exc_text = self.blind_logger.mask(exc_text)
                record_copy.exc_info = None  # Prevent super() from re-formatting unmasked

            # Mask extra custom attributes in record_copy.__dict__
            for attr, val in list(record_copy.__dict__.items()):
                if attr not in _RESERVED_RECORD_ATTRS and not attr.startswith("_"):
                    record_copy.__dict__[attr] = self._mask_with_key(
                        attr,
                        copy.deepcopy(val) if isinstance(val, (dict, list, set, frozenset)) else val,
                    )

        except Exception as e:
            _log.error("BlindLog: Masking failed. Reason: %s", e)
            record_copy.msg = "[BLINDLOG MASKING FAILED - RECORD SUPPRESSED]"
            record_copy.args = None
            record_copy.exc_info = None
            record_copy.exc_text = None
            
        return super().format(record_copy)
