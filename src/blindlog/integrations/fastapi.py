import json
import logging
from blindlog.core import BlindLogger
from blindlog.interfaces import MaskingEngine

_log = logging.getLogger("blindlog.middleware")

class BlindLogFastAPIMiddleware:
    """
    Pure ASGI Middleware to intercept and mask request bodies and metadata
    without violating or corrupting underlying asynchronous streams.
    
    Known Limitation (#17): Streaming responses (SSE, chunked transfer) may have
    PII split across multiple body chunks. Chunk-by-chunk inspection cannot detect
    PII that spans chunk boundaries. For full coverage of streaming responses,
    consider buffering the entire response or using application-level masking.
    """
    # Fix #11: Lazy initialization — same pattern as BlindLogFormatter
    def __init__(self, app, blind_logger: MaskingEngine = None):
        self.app = app
        self._blind_logger = blind_logger
        self._initialized = blind_logger is not None

    @property
    def blind_logger(self):
        if not self._initialized:
            self._blind_logger = BlindLogger()
            self._initialized = True
        return self._blind_logger

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
            
        headers = dict(scope.get("headers", []))
        content_length_str = headers.get(b"content-length", b"0").decode("utf-8", errors="ignore")
        content_length = int(content_length_str) if content_length_str.isdigit() else 0
        
        if content_length > 5_000_000:
            _log.warning("BlindLog: Payload omitted from logging due to exceeding 5MB safety limit.")
            return await self.app(scope, receive, send)

        body_bytes = b""
        more_body = True
        messages = []
        
        async def send_proxy(message):
            if message["type"] == "http.response.start":
                _log.info(f"BlindLog [Response Status]: {message['status']}")
            elif message["type"] == "http.response.body":
                resp_body = message.get("body", b"")
                # Fix #10: OOM guard on response body
                if resp_body and len(resp_body) < 5_000_000:
                    try:
                        parsed_resp = json.loads(resp_body)
                        masked_resp = self.blind_logger.mask(parsed_resp)
                        _log.info(f"BlindLog [Response Body]: {json.dumps(masked_resp)}")
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        _log.debug("BlindLog [Response Body]: <non-JSON response, skipped>")
                elif resp_body:
                    _log.warning("BlindLog: Response body exceeds 5MB, skipping masking.")
            await send(message)

        while more_body:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                body_bytes += message.get("body", b"")
                
                if len(body_bytes) > 5_000_000:
                    _log.warning("BlindLog: OOM Protection Tripped! Chunked stream exceeds 5MB. Logging aborted.")
                    body_bytes = b""
                    
                    async def dynamic_receive_proxy():
                        if messages:
                            return messages.pop(0)
                        return await receive()
                        
                    return await self.app(scope, dynamic_receive_proxy, send_proxy)

                more_body = message.get("more_body", False)
            else:
                more_body = False

        if body_bytes:
            try:
                parsed_body = json.loads(body_bytes)
                masked_request_body = self.blind_logger.mask(parsed_body)
                _log.info(f"BlindLog [Request Body]: {json.dumps(masked_request_body)}")
            except json.JSONDecodeError:
                if len(body_bytes) < 5_000_000:
                    masked_string = self.blind_logger.mask(body_bytes.decode('utf-8', errors='ignore'))
                    _log.info(f"BlindLog [Request Body]: {masked_string}")

        decoded_headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in headers.items()}
        _log.info(f"BlindLog [Headers]: {json.dumps(self.blind_logger.mask(decoded_headers))}")

        async def receive_proxy():
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, receive_proxy, send_proxy)
