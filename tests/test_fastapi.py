import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from blindlog import BlindLogger
from blindlog.integrations.fastapi import BlindLogFastAPIMiddleware

app = FastAPI()

# Add the middleware
blind_logger = BlindLogger(secret_key="test-api-secret")
app.add_middleware(BlindLogFastAPIMiddleware, blind_logger=blind_logger)

@app.post("/submit")
async def submit_data(request: Request):
    # This simulates a downstream route receiving the data after middleware execution
    body = await request.json()
    return {"status": "success", "received_email": body.get("email")}

client = TestClient(app)

def test_fastapi_middleware_passes_data_correctly(capsys):
    payload = {"email": "user@gmail.com", "other": "data"}
    
    # Send request
    response = client.post("/submit", json=payload)
    
    # Ensure downstream route received the correct UNMASKED bytes
    assert response.status_code == 200
    assert response.json()["received_email"] == "user@gmail.com"
    
    # Ensure console output from middleware masked the body
    captured = capsys.readouterr()
    assert "BlindLog [Request Body]" in captured.out
    assert "user@gmail.com" not in captured.out
    assert "ref_" in captured.out
