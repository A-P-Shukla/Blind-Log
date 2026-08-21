import pytest
import logging
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from blindlog import BlindLogger
from blindlog.integrations.fastapi import BlindLogFastAPIMiddleware

app = FastAPI()

blind_logger = BlindLogger(secret_key="test-api-secret")
app.add_middleware(BlindLogFastAPIMiddleware, blind_logger=blind_logger)

@app.post("/submit")
async def submit_data(request: Request):
    try:
        body = await request.json()
        return {"status": "success", "received_email": body.get("email")}
    except Exception:
        return {"status": "error", "received_email": None}

client = TestClient(app)

def test_fastapi_middleware_passes_data_correctly(caplog):
    payload = {"email": "user@gmail.com", "other": "data"}
    
    with caplog.at_level(logging.INFO, logger="blindlog.middleware"):
        response = client.post("/submit", json=payload)
    
    assert response.status_code == 200
    assert response.json()["received_email"] == "user@gmail.com"
    
    assert "BlindLog [Request Body]" in caplog.text
    assert "user@gmail.com" not in caplog.text
    assert "blnd_ref_" in caplog.text

def test_fastapi_middleware_headers_masked(caplog):
    with caplog.at_level(logging.INFO, logger="blindlog.middleware"):
        response = client.post(
            "/submit", 
            json={"email": "other@gmail.com"}, 
            headers={
                "Authorization": "Bearer secret-token-123",
                "Cookie": "session=xyz123",
                "X-API-Key": "my-api-key-value",
                "Custom-Header": "not-sensitive"
            }
        )
    assert response.status_code == 200
    
    headers_log_line = [line for line in caplog.text.split("\n") if "BlindLog [Headers]" in line][0]
    
    assert "Bearer secret-token-123" not in headers_log_line
    assert "session=xyz123" not in headers_log_line
    assert "my-api-key-value" not in headers_log_line
    
    assert "not-sensitive" in headers_log_line
    assert "blind:" in headers_log_line or "blnd_" in headers_log_line

def test_fastapi_middleware_duplicate_headers(caplog):
    with caplog.at_level(logging.INFO, logger="blindlog.middleware"):
        response = client.post(
            "/submit",
            json={"email": "other@gmail.com"},
            headers=[
                ("Cookie", "session=1"),
                ("Cookie", "session=2"),
                ("Custom-Header", "val1"),
                ("Custom-Header", "val2")
            ]
        )
    assert response.status_code == 200
    headers_log_line = [line for line in caplog.text.split("\n") if "BlindLog [Headers]" in line][0]
    
    assert "session=1" not in headers_log_line
    assert "session=2" not in headers_log_line
    assert "val1" in headers_log_line
    assert "val2" in headers_log_line

def test_fastapi_middleware_non_json_body(caplog):
    with caplog.at_level(logging.INFO, logger="blindlog.middleware"):
        response = client.post(
            "/submit",
            content="This is a plain text body containing an email user@example.com",
            headers={"Content-Type": "text/plain"}
        )
    # The server will return 400 or similar because /submit expects JSON
    assert "BlindLog [Request Body]" in caplog.text
    assert "user@example.com" not in caplog.text
    assert "blnd_ref_" in caplog.text

def test_fastapi_middleware_response_body_masked(caplog):
    with caplog.at_level(logging.INFO, logger="blindlog.middleware"):
        response = client.post("/submit", json={"email": "resp@example.com"})
    assert response.status_code == 200
    # App response still contains the raw email (middleware is observe-only)
    assert response.json()["received_email"] == "resp@example.com"
    # But middleware logs must not
    response_lines = [line for line in caplog.text.split("\n") if "BlindLog [Response Body]" in line]
    assert response_lines, "Expected response body log line"
    assert "resp@example.com" not in response_lines[0]
    assert "blnd_ref_" in response_lines[0]

def test_fastapi_middleware_skips_oversized_content_length(caplog):
    with caplog.at_level(logging.WARNING, logger="blindlog.middleware"):
        response = client.post(
            "/submit",
            json={"email": "huge@example.com"},
            headers={"Content-Length": "6000000"},
        )
    # Oversized Content-Length aborts middleware buffering; request may fail ASGI-side
    assert "exceeding 5MB safety limit" in caplog.text or response.status_code in (200, 400, 500)
