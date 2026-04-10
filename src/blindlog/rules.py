import re

# Optimized regular expressions for identifying PII within free-form text

# Fix #13: Email regex — removed pipe char bug in char class, removed TLD upper bound
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

# Credit Card: Standard 16 digit cards (Visa, Mastercard, Discover), optional separators
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

# Fix #8: IPv4 with proper octet range validation (0-255)
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Fix #9: Expanded API key regex covering major real-world formats
API_KEY_REGEX = re.compile(
    r'\b(?:'
    r'sk-[a-zA-Z0-9]{20,80}'            # OpenAI
    r'|sk_(?:live|test)_[a-zA-Z0-9]+'   # Stripe
    r'|ghp_[a-zA-Z0-9]{36}'             # GitHub PAT classic
    r'|github_pat_[a-zA-Z0-9_]{82}'     # GitHub fine-grained
    r'|AKIA[A-Z0-9]{16}'                # AWS Access Key ID
    r'|xox[bpas]-[a-zA-Z0-9-]+'         # Slack tokens
    r')\b'
)

# Fix #7 (idempotency): Sentinel prefix used by BlindLog masked outputs
MASKED_PREFIXES = ("ref_", "blind:", "ip_", "key_")

DEFAULT_SENSITIVE_KEYS = {
    "password", 
    "secret", 
    "token", 
    "api_key", 
    "ssn", 
    "credit_card", 
    "cc_number", 
    "email", 
    "authorization",
    "credentials"
}
