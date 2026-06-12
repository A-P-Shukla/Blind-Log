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
    
    assert masked["event"] == "user_signup"
    assert masked["data"]["user"]["id"] == 123
    
    assert masked["data"]["user"]["profile"]["email"] != "test@test.com"
    assert "blnd_ref_" in masked["data"]["user"]["profile"]["email"]
    assert masked["data"]["user"]["profile"]["ssn"] != "000-00-0000"
    assert masked["data"]["user"]["profile"]["ssn"] != "000-00-0000"
    
    masked_cc = masked["data"]["history"][0]["cc_number"]
    assert masked_cc.startswith("1111")
    assert masked_cc.endswith("4444")
    assert len(masked_cc.split("-")) == 4

def test_circular_reference_protection():
    logger = BlindLogger(secret_key="secret")
    
    payload = {"status": "active"}
    payload["self"] = payload
    
    masked = logger.mask(payload)
    
    assert masked["status"] == "active"
    assert masked["self"] == "<CircularReference>"

def test_none_under_sensitive_key():
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"password": None})
    assert result["password"] != None
    assert "blind:" in str(result["password"])

# Fix #15: Use string values to exercise key matching, not primitive passthrough
def test_no_false_positive_substring_matching():
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"email_verified": "confirmed", "token_count": "100"})
    assert result["email_verified"] == "confirmed"
    assert result["token_count"] == "100"

# Fix #18: Test frozenset immutability, not just isolation
def test_config_immutability():
    from blindlog.config import BlindLogConfig
    
    cfg = BlindLogConfig(secret_key="s1")
    
    # sensitive_keys is a frozenset — cannot be mutated
    assert isinstance(cfg.sensitive_keys, frozenset)
    with pytest.raises(AttributeError):
        cfg.sensitive_keys.add("custom_field")
    
    # Config itself is frozen — attributes cannot be reassigned
    with pytest.raises(Exception):
        cfg.debug_mode = True

def test_suffix_matching_compound_keys():
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
    assert "eyJhbGciOiJIUzI1NiJ9" not in str(result["refresh_token"])
    assert "eyJhbGciOiJIUzI1NiJ9" not in str(result["access_token"])
    assert "plaintext123" not in str(result["old_password"])
    assert "newplaintext" not in str(result["new_password"])
    assert "some-key-value" not in str(result["x_api_key"])
    assert result["token_count"] == 42
    assert result["email_verified"] == True

def test_idempotent_masking():
    logger = BlindLogger(secret_key="secret")
    payload = {"message": "user@example.com logged in"}
    r1 = logger.mask(payload)
    r2 = logger.mask(r1)
    assert r1 == r2

def test_camel_case_matching():
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "refreshToken": "eyJhbG",
        "accessToken": "eyJhbG",
        "oldPassword": "plaintext",
    })
    assert "eyJhbG" not in str(result["refreshToken"])
    assert "eyJhbG" not in str(result["accessToken"])
    assert "plaintext" not in str(result["oldPassword"])

def test_camel_case_acronyms():
    """Round 4 #4: Acronym camelCase like APIKey, OAuth2Token."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "APIKey": "sk-test-12345678901234567890",
        "OAuth2Token": "eyJhbGciOi",
    })
    assert "sk-test" not in str(result["APIKey"])
    assert "eyJhbGciOi" not in str(result["OAuth2Token"])

def test_dot_separated_matching():
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "user.password": "plaintext",
        "auth.token": "tok123",
    })
    assert "plaintext" not in str(result["user.password"])
    assert "tok123" not in str(result["auth.token"])

def test_phone_masking():
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"phone": "+1-555-123-4567", "mobile": "9876543210"})
    assert "+1-555-123-4567" not in str(result["phone"])
    assert "9876543210" not in str(result["mobile"])

def test_ssn_masking():
    """Round 4 #12: SSN values must be masked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"ssn_number": "123-45-6789"})
    assert "123-45-6789" not in str(result["ssn_number"])

def test_frozen_config():
    from blindlog.config import BlindLogConfig
    cfg = BlindLogConfig(secret_key="test")
    with pytest.raises(Exception):
        cfg.debug_mode = True

def test_no_key_false_positives():
    """Round 4 #7: primary_key, foreign_key etc. should NOT be masked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "primary_key": "user#123",
        "foreign_key": "order#456",
        "sort_key": "profile#789",
        "cache_key": "cache_123",
    })
    assert result["primary_key"] == "user#123"
    assert result["foreign_key"] == "order#456"
    assert result["sort_key"] == "profile#789"
    assert result["cache_key"] == "cache_123"

def test_idempotent_sentinel_bypass_fix():
    """Round 5 #3: Ensure prefix-only values like blind:my-secret are NOT bypassed."""
    logger = BlindLogger(secret_key="secret")
    
    # 1. Under a sensitive key (force masking)
    payload = {"api_key": "blind:my-secret-token"}
    result = logger.mask(payload)
    # The value should NOT be untouched. It must be masked into a proper valid mask.
    assert result["api_key"] != "blind:my-secret-token"
    
    # 2. As free text containing a regex match
    payload2 = {"message": "Email is blind:user@example.com"}
    result2 = logger.mask(payload2)
    # The email regex will match user@example.com and mask it, ignoring the 'blind:' part
    assert "user@example.com" not in result2["message"]
    assert "blind:blnd_ref_" in result2["message"]
