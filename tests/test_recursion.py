import pytest
from blindlog import BlindLogger

def test_deeply_nested_json():
    logger = BlindLogger(secret_key="secret")
    
    payload = {
        "event": "user_signup",
        "data": {
            "user": {
                "id": 123,
                "profile": {
                    "email": "test@test.com",
                    "ssn": "000-00-0000"
                }
            },
            "history": [
                {"action": "click", "cc_number": "1111-2222-3333-4444"}
            ]
        }
    }
    
    masked = logger.mask(payload)
    
    # Check that non-sensitive data is untouched
    assert masked["event"] == "user_signup"
    assert masked["data"]["user"]["id"] == 123
    
    # Check that sensitive keys are masked
    assert masked["data"]["user"]["profile"]["email"] != "test@test.com"
    assert "ref_" in masked["data"]["user"]["profile"]["email"]
    assert masked["data"]["user"]["profile"]["ssn"] != "000-00-0000"
    assert "blind:" in str(masked["data"]["user"]["profile"]["ssn"])
    
    # Fix #3: Check CC structure matches actual format (first4-hash-hash-last4)
    masked_cc = masked["data"]["history"][0]["cc_number"]
    assert masked_cc.startswith("1111")
    assert masked_cc.endswith("4444")
    assert len(masked_cc.split("-")) == 4

def test_circular_reference_protection():
    logger = BlindLogger(secret_key="secret")
    
    # Create a circular reference
    payload = {"key": "value"}
    payload["self"] = payload
    
    masked = logger.mask(payload)
    
    assert masked["key"] == "value"
    assert masked["self"] == "<CircularReference>"

def test_none_under_sensitive_key():
    """Fix #2: None values under sensitive keys must be masked, not leaked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"password": None})
    assert result["password"] != None  # Must not leak None
    assert "blind:" in str(result["password"])

def test_no_false_positive_substring_matching():
    """Fix #13: 'email_verified' should NOT be masked just because it contains 'email'."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"email_verified": True, "token_count": 42})
    assert result["email_verified"] == True
    assert result["token_count"] == 42

def test_mutable_singleton_isolation():
    """Fix #1: Each config should get its own copy of sensitive_keys."""
    from blindlog.config import BlindLogConfig
    from blindlog.rules import DEFAULT_SENSITIVE_KEYS
    
    cfg1 = BlindLogConfig(secret_key="s1")
    cfg2 = BlindLogConfig(secret_key="s2")
    
    # They should be separate objects
    assert cfg1.sensitive_keys is not cfg2.sensitive_keys
    assert cfg1.sensitive_keys is not DEFAULT_SENSITIVE_KEYS
    
    # Mutating one should not affect the other
    cfg1.sensitive_keys.add("custom_field")
    assert "custom_field" not in cfg2.sensitive_keys
    assert "custom_field" not in DEFAULT_SENSITIVE_KEYS

def test_suffix_matching_compound_keys():
    """Round 2 #1: Compound keys like refresh_token, old_password must be masked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "refresh_token": "eyJhbGciOiJIUzI1NiJ9",
        "access_token": "eyJhbGciOiJIUzI1NiJ9",
        "old_password": "plaintext123",
        "new_password": "newplaintext",
        "x_api_key": "some-key-value",
        "token_count": 42,
        "email_verified": True,
    })
    # Compound sensitive keys MUST be masked
    assert "eyJhbGciOiJIUzI1NiJ9" not in str(result["refresh_token"])
    assert "eyJhbGciOiJIUzI1NiJ9" not in str(result["access_token"])
    assert "plaintext123" not in str(result["old_password"])
    assert "newplaintext" not in str(result["new_password"])
    assert "some-key-value" not in str(result["x_api_key"])
    # Non-sensitive compound keys must NOT be masked
    assert result["token_count"] == 42
    assert result["email_verified"] == True

def test_idempotent_masking():
    """Round 2 #7: Calling mask() twice should produce the same result."""
    logger = BlindLogger(secret_key="secret")
    payload = {"message": "user@example.com logged in"}
    r1 = logger.mask(payload)
    r2 = logger.mask(r1)
    assert r1 == r2

