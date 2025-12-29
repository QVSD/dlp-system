import re

# -------------------------
# Regex rules
# -------------------------

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

PHONE_REGEX = re.compile(
    r"\b(\+40|0)?7\d{8}\b"
)

CNP_REGEX = re.compile(
    r"(?:^|[^0-9])([1-8]\d{12})(?:[^0-9]|$)"
)

IBAN_REGEX = re.compile(
    r"RO\d{2}[A-Z]{4}\d{16}"
)

CARD_REGEX = re.compile(
    r"\b(?:\d[ -]*?){13,19}\b"
)

JWT_REGEX = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)

RULES = {
    "EMAIL": EMAIL_REGEX,
    "PHONE": PHONE_REGEX,
    "CNP": CNP_REGEX,
    "IBAN": IBAN_REGEX,
    "CARD": CARD_REGEX,
    "JWT": JWT_REGEX,
}

# -------------------------
# Severity mapping
# -------------------------

SEVERITY = {
    "EMAIL": "LOW",
    "PHONE": "MEDIUM",
    "IBAN": "HIGH",
    "CNP": "HIGH",
    "CARD": "CRITICAL",
    "JWT": "CRITICAL",
}
