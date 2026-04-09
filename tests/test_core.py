import pytest
import os
from blindlog import BlindLogger

def test_logger_initialization():
    logger = BlindLogger(secret_key="test-secret")
    assert logger.secret_key == "test-secret"
    
def test_deterministic_hashing():
    logger = BlindLogger(secret_key="my-super-secret-key")
    hash1 = logger._hash("akhand@gmail.com")
    hash2 = logger._hash("akhand@gmail.com")
    assert hash1 == hash2
    assert len(hash1) == 12  # default length
    
def test_structure_preserving_masking_email():
    logger = BlindLogger(secret_key="secret")
    masked_email = logger._mask_email("user@example.com")
    assert masked_email.startswith("ref_")
    assert masked_email.endswith("...@masked.com")
    
def test_structure_preserving_masking_cc():
    logger = BlindLogger(secret_key="secret")
    cc = "4111-2222-3333-4444"
    masked_cc = logger._mask_cc(cc)
    assert masked_cc.startswith("4111")
    assert masked_cc.endswith("4444")
    assert "xxxx-xxxx" in masked_cc

def test_full_payload_masking():
    logger = BlindLogger(secret_key="secret")
    payload = {
        "user_email": "hello@world.com",
        "credit_card": "4111-2222-3333-4444",
        "metadata": "No secrets here"
    }
    
    masked = logger.mask(payload)
    
    assert "hello@world.com" not in masked["user_email"]
    assert "ref_" in masked["user_email"]
    assert "4111-xxxx-xxxx-4444" in masked["credit_card"]
    assert masked["metadata"] == "No secrets here"
    
def test_debug_mode():
    logger = BlindLogger(secret_key="secret", debug_mode=True)
    payload = {"email": "hello@world.com"}
    masked = logger.mask(payload)
    assert masked["email"] == "hello@world.com"
