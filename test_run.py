import os
import sys

# Fix #19: Use script-relative path, not CWD-relative
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from blindlog import BlindLogger

logger = BlindLogger(secret_key="my-super-secret-key")

payload = {
    "user_email": "akhand@gmail.com",
    "credit_card": "4111-2222-3333-4444",
    "metadata": {"session_id": "sess_999", "ip": "192.168.1.1"}
}

print("Original:")
import json
print(json.dumps(payload, indent=2))

masked = logger.mask(payload)
print("\nMasked:")
print(json.dumps(masked, indent=2))
