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
    
    # Check list iteration
    assert "1111-xxxx-xxxx-4444" in masked["data"]["history"][0]["cc_number"]

def test_circular_reference_protection():
    logger = BlindLogger(secret_key="secret")
    
    # Create a circular reference
    payload = {"key": "value"}
    payload["self"] = payload
    
    masked = logger.mask(payload)
    
    assert masked["key"] == "value"
    assert masked["self"] == "<CircularReference>"
