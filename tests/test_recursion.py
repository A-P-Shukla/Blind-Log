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
    assert "blind:" in str(masked["data"]["user"]["profile"]["ssn"])
    
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

# Fix #15: Use string values to actually exercise key matching, not primitive passthrough
def test_no_false_positive_substring_matching():
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"email_verified": "confirmed", "token_count": "100"})
    assert result["email_verified"] == "confirmed"
    assert result["token_count"] == "100"

def test_mutable_singleton_isolation():
    from blindlog.config import BlindLogConfig
    from blindlog.rules import DEFAULT_SENSITIVE_KEYS
    
    cfg1 = BlindLogConfig(secret_key="s1")
    cfg2 = BlindLogConfig(secret_key="s2")
    
    assert cfg1.sensitive_keys is not cfg2.sensitive_keys
    assert cfg1.sensitive_keys is not DEFAULT_SENSITIVE_KEYS

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
    """Round 3 #3: camelCase keys like refreshToken must be masked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "refreshToken": "eyJhbG",
        "accessToken": "eyJhbG",
        "oldPassword": "plaintext",
    })
    assert "eyJhbG" not in str(result["refreshToken"])
    assert "eyJhbG" not in str(result["accessToken"])
    assert "plaintext" not in str(result["oldPassword"])

def test_dot_separated_matching():
    """Round 3 #4: Dot-separated keys like user.password must be masked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({
        "user.password": "plaintext",
        "auth.token": "tok123",
    })
    assert "plaintext" not in str(result["user.password"])
    assert "tok123" not in str(result["auth.token"])

def test_phone_masking():
    """Round 3 #11: Phone numbers must be masked."""
    logger = BlindLogger(secret_key="secret")
    result = logger.mask({"phone": "+1-555-123-4567", "mobile": "9876543210"})
    assert "+1-555-123-4567" not in str(result["phone"])
    assert "9876543210" not in str(result["mobile"])

def test_frozen_config():
    """Round 3 #5: Config must be immutable after construction."""
    from blindlog.config import BlindLogConfig
    cfg = BlindLogConfig(secret_key="test")
    with pytest.raises(Exception):  # FrozenInstanceError
        cfg.debug_mode = True
