import os
import sys

# Add src to python path for testing
sys.path.insert(0, os.path.abspath("src"))

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
