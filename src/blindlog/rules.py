import re
from functools import lru_cache

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
    r'|github_pat_[a-zA-Z0-9_]{80,100}' # GitHub fine-grained
    r'|AKIA[A-Z0-9]{16}'                # AWS Access Key ID
    r'|xox[bpas]-[a-zA-Z0-9-]{20,}'     # Slack tokens (min 20 chars)
    r')\b'
)

# Fix #5 + #6 + #14: Phone regex with improved international support
# Uses lookbehind/lookahead instead of \b to properly capture the + prefix
# Note: 10-digit standalone numbers may false-positive (inherent regex limitation, documented)
PHONE_REGEX = re.compile(
    r'(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\w)'
    r'|'
    r'\+\d{1,3}(?:[-.\s]\d+){1,5}(?!\w)'
)

# Fix #12: SSN regex (US format)
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

# Collision-resistant sentinel prefixes for idempotency (unversioned / key_id="").
# Versioned forms (blnd_v2_ref_, blind_v2:, …) are accepted by MASKED_PATTERN.
MASKED_PREFIXES = ("blnd_ref_", "blind:", "blnd_ip_", "blnd_key_", "blnd_ph_", "blnd_ssn_")

# Optional key_id infix: letter + up to 15 alnum/underscore, always followed by `_`
# when used as blnd_{id}_ref_ / blnd_{id}_ip_ etc.
_KID = r'(?:[A-Za-z][A-Za-z0-9_]{0,15}_)?'
_KID_BLIND = r'(?:_[A-Za-z][A-Za-z0-9_]{0,15})?'

# Strict idempotency validation. Accepts:
# - unversioned and key_id-versioned prefixes
# - v1.1 hex widths (10/12) and v1.2 64-bit widths (16)
# - CC 4-6-6-4 (legacy 48-bit) and 4-8-8-4 (64-bit); real 4-4-4-4 PANs never match
MASKED_PATTERN = re.compile(
    r'^('
    rf'blnd_{_KID}ref_[0-9a-f]{{12,16}}\.\.\.@masked\.com'
    rf'|blind{_KID_BLIND}:[0-9a-f]{{10,16}}'
    rf'|blnd_{_KID}[a-z0-9_]{{1,16}}_[0-9a-f]{{10,16}}'
    r'|\d{4}-[0-9a-f]{8}-[0-9a-f]{8}-\d{4}'
    r'|\d{4}-[0-9a-f]{6}-[0-9a-f]{6}-\d{4}'
    r')$'
)

# Digest widths (hex chars). 16 hex = 64 bits of truncated BLAKE2b output.
# Birthday-paradox 50% collision ~ 2^32 ≈ 4e9 distinct values — sized for
# high-volume financial/identity logs. Legacy 10/12-char masks still match
# MASKED_PATTERN so historical logs remain idempotent.
OPAQUE_HASH_LEN = 16
EMAIL_HASH_LEN = 16
CC_HASH_LEN = 16

# Fix #7: Removed generic 'key' — replaced with specific sensitive key variants
# Fix #11: Removed 'cell' and 'telephone' — too many false positives (fuel_cell, etc.)
# Fix #15: Added 'auth_code' for OAuth2 coverage
DEFAULT_SENSITIVE_KEYS = frozenset({
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
    "phone",
    "mobile",
    "authorization_code",
    "auth_code",
    "private_key",
    "secret_key",
    "signing_key",
    "encryption_key",
    "ssn_number",
    "cookie",
    "set_cookie",
})

# Fix #4: Two-pass camelCase normalization for acronyms
_CAMEL_RE1 = re.compile(r'([A-Z]+)([A-Z][a-z])')   # XMLParser → XML_Parser
_CAMEL_RE2 = re.compile(r'([a-z\d])([A-Z])')         # camelCase → camel_Case

# Fix #13: Cache normalized keys for performance
@lru_cache(maxsize=2048)
def normalize_key(k: str) -> str:
    """
    Normalize a key to snake_case for sensitive key matching.
    'refreshToken' -> 'refresh_token'
    'APIKey' -> 'api_key'
    'OAuth2Token' -> 'oauth2_token'
    'user.password' -> 'user.password'
    """
    k = _CAMEL_RE1.sub(r'\1_\2', k)
    k = _CAMEL_RE2.sub(r'\1_\2', k)
    return k.replace('-', '_').lower()
