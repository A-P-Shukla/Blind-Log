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
    body = await request.json()
    return {"status": "success", "received_email": body.get("email")}

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
