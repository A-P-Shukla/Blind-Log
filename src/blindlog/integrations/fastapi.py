import json
from blindlog.core import BlindLogger

try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.requests import ClientDisconnect
except ImportError:
    raise ImportError("FastAPI/Starlette is required for this middleware. Run `pip install blindlog[fastapi]`")


class BlindLogFastAPIMiddleware(BaseHTTPMiddleware):
    """
    FastAPI Middleware to intercept and mask request bodies and metadata
    before they are processed or logged.
    """
    def __init__(self, app, blind_logger: BlindLogger = None):
        super().__init__(app)
        self.blind_logger = blind_logger or BlindLogger()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Check Content-Length for OOM Protection (Skip deep-mask on giant files)
        content_length = int(request.headers.get("content-length", 0))
        if content_length > 5_000_000:  # 5MB cutoff
            print("BlindLog [Alert]: Payload omitted from logging due to exceeding 5MB safety limit.")
            return await call_next(request)

        # 1. Intercept & Mask Request Body
        body_bytes = b""
        try:
            body_bytes = await request.body()
        except ClientDisconnect:
            pass

        if body_bytes:
            try:
                parsed_body = json.loads(body_bytes)
                masked_request_body = self.blind_logger.mask(parsed_body)
                print(f"BlindLog [Request Body]: {json.dumps(masked_request_body)}")
            except json.JSONDecodeError:
                # If it's x-www-form-urlencoded or plain text
                # We also check the true byte-length again just in case `content-length` was spoofed
                if len(body_bytes) < 5_000_000:
                    masked_string = self.blind_logger.mask(body_bytes.decode('utf-8', errors='ignore'))
                    print(f"BlindLog [Request Body]: {masked_string}")

        # FastAPI middleware consumes the stream when we read `request.body()`.
        # We must re-inject the bytes so the actual route handler can read them.
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive

        # Optional: Mask headers
        masked_headers = self.blind_logger.mask(dict(request.headers))
        print(f"BlindLog [Headers]: {json.dumps(masked_headers)}")

        # 2. Process downstream Request
        response = await call_next(request)

        # 3. Process Response
        # Note: Intercepting response bodies in Starlette requires fully evaluating the 
        # streaming response iterator. For v1, we focus on safe status-code logging.
        print(f"BlindLog [Response Status]: {response.status_code}")
        
        return response
