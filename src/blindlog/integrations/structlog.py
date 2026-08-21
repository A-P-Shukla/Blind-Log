"""Optional structlog processor — install with `pip install blindlog[structlog]`."""
from typing import Any, MutableMapping, Optional
from blindlog.interfaces import MaskingEngine


def make_blindlog_processor(blind_logger: Optional[MaskingEngine] = None):
    """
    Return a structlog processor that recursively masks the event dict.

    Usage::

        import structlog
        from blindlog import BlindLogger
        from blindlog.integrations.structlog import make_blindlog_processor

        log = BlindLogger(secret_key="...")
        structlog.configure(
            processors=[
                make_blindlog_processor(log),
                structlog.processors.JSONRenderer(),
            ]
        )
    """
    engine = blind_logger

    def processor(
        logger: Any,
        method_name: str,
        event_dict: MutableMapping[str, Any],
    ) -> MutableMapping[str, Any]:
        nonlocal engine
        if engine is None:
            from blindlog.core import BlindLogger
            engine = BlindLogger()
        masked = engine.mask(dict(event_dict))
        if isinstance(masked, dict):
            return masked
        return event_dict

    return processor


# Default processor with lazy BlindLogger init (requires BLINDLOG_SECRET).
blindlog_processor = make_blindlog_processor()
