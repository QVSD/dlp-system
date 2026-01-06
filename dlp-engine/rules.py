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

IBAN_REGEX = re.compile(r"\bRO\d{2}[A-Z]{4}[A-Z0-9]{16}\b")


CARD_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"
    r"5[1-5][0-9]{14}|"
    r"3[47][0-9]{13}|"
    r"6(?:011|5[0-9]{2})[0-9]{12})\b"
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
