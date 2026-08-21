import pytest

structlog = pytest.importorskip("structlog")

from blindlog import BlindLogger
from blindlog.integrations.structlog import make_blindlog_processor


def test_structlog_processor_masks_event_dict():
    engine = BlindLogger(secret_key="secret")
    processor = make_blindlog_processor(engine)
    event = {
        "event": "login failed for user@example.com",
        "email": "user@example.com",
        "password": "hunter2",
        "request_id": "req_abc",
    }
    masked = processor(None, "info", event)
    assert "user@example.com" not in str(masked)
    assert masked["password"] != "hunter2"
    assert masked["password"].startswith("blind:")
    assert "blnd_ref_" in masked["email"]
    assert masked["request_id"] == "req_abc"
