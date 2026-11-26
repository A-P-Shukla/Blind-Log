import pytest
import os
from blindlog import BlindLogger
from blindlog.config import BlindLogConfig

def test_logger_initialization():
    logger = BlindLogger(secret_key="test-secret")
    assert logger.config.secret_key == "test-secret"
    
def test_deterministic_hashing():
    logger = BlindLogger(secret_key="my-super-secret-key")
    hash1 = logger._hash("akhand@gmail.com")
    hash2 = logger._hash("akhand@gmail.com")
    assert hash1 == hash2
    assert len(hash1) == 16
    
def test_structure_preserving_masking_email():
    logger = BlindLogger(secret_key="secret")
    masked_email = logger._mask_email("user@example.com")
    assert masked_email.startswith("blnd_ref_")
    assert masked_email.endswith("...@masked.com")
    
def test_structure_preserving_masking_cc():
    logger = BlindLogger(secret_key="secret")
    cc = "4111-2222-3333-4444"
    masked_cc = logger._mask_cc(cc)
    assert masked_cc.startswith("4111")
    assert masked_cc.endswith("4444")
    parts = masked_cc.split("-")
    assert len(parts) == 4
    assert len(parts[1]) == 8
    assert len(parts[2]) == 8
    assert parts[1] != "xxxx"
    assert parts[2] != "xxxx"

def test_full_payload_masking():
    logger = BlindLogger(secret_key="secret")
    payload = {
        "user_email": "hello@world.com",
        "credit_card": "4111-2222-3333-4444",
        "metadata": "No secrets here"
    }
    
    masked = logger.mask(payload)
    
    assert "hello@world.com" not in masked["user_email"]
    assert "blnd_ref_" in masked["user_email"]
    assert masked["credit_card"].startswith("4111")
    assert masked["credit_card"].endswith("4444")
    assert masked["metadata"] == "No secrets here"
    
def test_debug_mode():
    logger = BlindLogger(secret_key="secret", debug_mode=True)
    payload = {"email": "hello@world.com"}
    masked = logger.mask(payload)
    assert masked["email"] == "hello@world.com"

def test_explicit_debug_mode_false_overrides_environment(monkeypatch):
    monkeypatch.setenv("BLINDLOG_DEBUG", "true")
    logger = BlindLogger(secret_key="secret", debug_mode=False)
    payload = {"email": "hello@world.com", "password": "hunter2"}

    masked = logger.mask(payload)

    assert "hello@world.com" not in str(masked)
    assert "hunter2" not in str(masked)
    assert logger.config.debug_mode is False

def test_unset_debug_mode_still_uses_environment(monkeypatch):
    monkeypatch.setenv("BLINDLOG_DEBUG", "true")
    config = BlindLogConfig(secret_key="secret")

    assert config.debug_mode is True

def test_hash_length_guard():
    logger = BlindLogger(secret_key="secret")
    with pytest.raises(ValueError):
        logger._hash("test", length=0)

def test_email_fallback_consistency():
    logger = BlindLogger(secret_key="secret")
    result = logger._mask_email("notanemail")
    assert result.startswith("blnd_ref_")
    assert result.endswith("...@masked.com")
    # 16 hex chars between prefix and ellipsis
    inner = result[len("blnd_ref_"):].split("...")[0]
    assert len(inner) == 16

def test_formatter_masks_exceptions_and_args():
    import io
    import logging
    from blindlog.formatters import BlindLogFormatter

    logger = BlindLogger(secret_key="secret")
    fmt = BlindLogFormatter(blind_logger=logger)
    log = logging.getLogger("test_formatter_masks")
    log.handlers.clear()
    log.setLevel(logging.INFO)
    log.propagate = False
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(fmt)
    log.addHandler(handler)

    log.info("Hello %s", "user@example.com")
    log.info("%(name)s logged in", {"name": "ceo@corp.com"})
    try:
        raise ValueError("User akhand@gmail.com not found")
    except ValueError:
        log.exception("A system error occurred")

    out = buf.getvalue()
    assert "user@example.com" not in out
    assert "ceo@corp.com" not in out
    assert "akhand@gmail.com" not in out
    assert "blnd_ref_" in out

def test_formatter_fail_closed_on_masking_error():
    import io
    import logging
    from blindlog.formatters import BlindLogFormatter

    class BoomEngine:
        def mask(self, payload):
            raise RuntimeError("mask boom")

    fmt = BlindLogFormatter(blind_logger=BoomEngine())
    log = logging.getLogger("test_formatter_fail_closed")
    log.handlers.clear()
    log.setLevel(logging.INFO)
    log.propagate = False
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(fmt)
    log.addHandler(handler)

    log.info("secret user@example.com should not leak")
    out = buf.getvalue()
    assert "user@example.com" not in out
    assert "BLINDLOG MASKING FAILED" in out


def test_formatter_masks_extra_attributes():
    import logging
    from blindlog.formatters import BlindLogFormatter
    
    formatter = BlindLogFormatter("%(message)s email=%(email)s user=%(user)s", blind_logger=BlindLogger(secret_key="fmt-secret"))
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Login event",
        args=(),
        exc_info=None,
    )
    record.email = "target@example.com"
    record.user = {"sub": "admin", "phone": "+15551234567"}
    
    formatted = formatter.format(record)
    assert "target@example.com" not in formatted
    assert "+15551234567" not in formatted
    assert "blnd_ref_" in formatted
    assert "blnd_ph_" in formatted

def test_custom_rule_idempotency_force_path():
    import re
    logger = BlindLogger(secret_key="secret")
    emp_regex = re.compile(r'\bEMP-\d{6}\b')
    logger.registry.register(emp_regex, lambda text: f"{logger.tag('emp')}{logger.hash_text(text, length=16)}")
    
    # 1. Force path: dictionary matching sensitive key
    payload = {"password": "EMP-104928"}
    first_pass = logger.mask(payload)
    assert first_pass["password"].startswith("blnd_emp_")
    
    # 2. Re-masking must remain idempotent and NOT rewrite to blind:
    second_pass = logger.mask(first_pass)
    assert second_pass["password"] == first_pass["password"]

def test_secret_salt_domain_separation():
    # secret="ab", salt="c" vs secret="a", salt="bc"
    c1 = BlindLogger(secret_key="ab", salt="c")
    c2 = BlindLogger(secret_key="a", salt="bc")
    assert c1.config.blake_key != c2.config.blake_key
    assert c1.hash_text("test") != c2.hash_text("test")

def test_public_hash_text_and_tag():
    logger = BlindLogger(secret_key="secret", key_id="v2")
    h = logger.hash_text("sample")
    assert len(h) == 16
    assert logger.tag("custom") == "blnd_v2_custom_"
    assert logger.tag("blind") == "blind_v2:"
