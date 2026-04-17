import re

# Optimized regular expressions for identifying PII within free-form text

# Email regex — no TLD upper bound, fixed character class
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

# Credit Card: Standard 16 digit cards (Visa, Mastercard, Discover), optional separators
# Note: Pure regex CC detection cannot perform Luhn validation. This will match any
# 16-digit number in groups of 4. For environments with heavy numeric IDs, consider
# disabling this rule or adding Luhn validation via a custom callback.
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

# IPv4 with proper octet range validation (0-255)
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Expanded API key regex covering major real-world formats
API_KEY_REGEX = re.compile(
    r'\b(?:'
    r'sk-[a-zA-Z0-9]{20,80}'            # OpenAI
    r'|sk_(?:live|test)_[a-zA-Z0-9]+'   # Stripe
    r'|ghp_[a-zA-Z0-9]{36}'             # GitHub PAT classic
    r'|github_pat_[a-zA-Z0-9_]{80,100}' # Fix #10: GitHub fine-grained — range not exact
    r'|AKIA[A-Z0-9]{16}'                # AWS Access Key ID
    r'|xox[bpas]-[a-zA-Z0-9-]{20,}'     # Fix #9: Slack tokens — minimum 20 chars
    r')\b'
)

# Fix #11: Phone number regex (NANP + international formats)
PHONE_REGEX = re.compile(
    r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    r'|'
    r'\+\d{1,3}[-.\s]?\d{4,14}\b'
)

# Fix #13: Collision-resistant sentinel prefixes for idempotency
MASKED_PREFIXES = ("blnd_ref_", "blind:", "blnd_ip_", "blnd_key_", "blnd_ph_")

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
    "credentials",
    # Fix #11: Phone-related keys
    "phone",
    "mobile",
    "telephone",
    "cell",
    # Fix #12: Additional security-critical keys
    "authorization_code",
    "private_key",
    "key",
}

# Fix #3: camelCase normalization utility
_CAMEL_RE = re.compile(r'([a-z])([A-Z])')

def normalize_key(k: str) -> str:
    """
    Normalize a key to snake_case for sensitive key matching.
    'refreshToken' -> 'refresh_token', 'user.password' -> 'user.password'
    """
    return _CAMEL_RE.sub(r'\1_\2', k).lower()
