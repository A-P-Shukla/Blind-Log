import re

# Optimized regular expressions for identifying PII within free-form text

# Email: Reasonably robust regex to catch emails, avoiding overly complex edge cases
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')

# Credit Card: Standard 16 digit cards (Visa, Mastercard, Discover), optional separators
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

# IPv4
IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Secrets / API Keys (Common prefixes like sk-, ghp-, etc.)
# Catches sk-[a-zA-Z0-9], ghp_[a-zA-Z0-9]
API_KEY_REGEX = re.compile(r'\b(?:sk-[a-zA-Z0-9]{20,80}|ghp_[a-zA-Z0-9]{36})\b')

DEFAULT_SENSITIVE_KEYS = {
    "password", 
    "secret", 
    "token", 
    "api_key", 
    "ssn", 
    "credit_card", 
    "cc_number", 
    "email", 
    "authorization"
}
