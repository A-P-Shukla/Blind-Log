import json
from blindlog.core import BlindLogger
from blindlog.interfaces import MaskingEngine

class BlindLogFastAPIMiddleware:
    """
    Pure ASGI Middleware to intercept and mask request bodies and metadata
    without violating or corrupting underlying asynchronous streams.
    """
    def __init__(self, app, blind_logger: MaskingEngine = None):
        self.app = app
        self.blind_logger = blind_logger or BlindLogger()

    async def __call__(self, scope, receive, send):
        # Pass through all non-HTTP connections (e.g. WebSockets) strictly untouched.
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
            
        # OOM Protection via initial header analysis (limit 5MB buffer size default)
        headers = dict(scope.get("headers", []))
        content_length_str = headers.get(b"content-length", b"0").decode("utf-8", errors="ignore")
        content_length = int(content_length_str) if content_length_str.isdigit() else 0
        
        if content_length > 5_000_000:
            print("BlindLog [Alert]: Payload omitted from logging due to exceeding 5MB safety limit.")
            return await self.app(scope, receive, send)

        body_bytes = b""
        more_body = True
        messages = []
        
        # Intercept output status via a synthetic send proxy
        async def send_proxy(message):
            if message["type"] == "http.response.start":
                print(f"BlindLog [Response Status]: {message['status']}")
            await send(message)

        # Ingest the payload into memory to execute our mask routines safely
        while more_body:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                body_bytes += message.get("body", b"")
                
                # OOM Protection for Malicious Chunked Streams
                if len(body_bytes) > 5_000_000:
                    print("BlindLog [Alert]: OOM Protection Tripped! Chunked stream exceeds 5MB. Logging aborted.")
                    body_bytes = b"" # Flush volatile buffer immediately
                    
                    # Yield a hybrid proxy: drains our cached chunks first, then native stream.
                    async def dynamic_receive_proxy():
                        if messages:
                            return messages.pop(0)
                        return await receive()
                        
                    return await self.app(scope, dynamic_receive_proxy, send_proxy)

                more_body = message.get("more_body", False)
            else:
                more_body = False

        # Execute Logger Masker on collected bytes
        if body_bytes:
            try:
                parsed_body = json.loads(body_bytes)
                masked_request_body = self.blind_logger.mask(parsed_body)
                print(f"BlindLog [Request Body]: {json.dumps(masked_request_body)}")
            except json.JSONDecodeError:
                if len(body_bytes) < 5_000_000:
                    masked_string = self.blind_logger.mask(body_bytes.decode('utf-8', errors='ignore'))
                    print(f"BlindLog [Request Body]: {masked_string}")

        # Inject safely unmasked core headers to terminal
        decoded_headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in headers.items()}
        print(f"BlindLog [Headers]: {json.dumps(self.blind_logger.mask(decoded_headers))}")

        # Construct a synthetic receive coroutine to pipe original buffer events sequentially into FastAPI internals.
        async def receive_proxy():
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        # Plumb the execution route
        await self.app(scope, receive_proxy, send_proxy)
