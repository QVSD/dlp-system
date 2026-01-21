# Context awareness (to reduce the no of FP)

CONTEXT_KEYWORDS = {
    "IBAN": ["iban", "account", "cont", "payment", "transfer"],
    "CARD": ["card", "payment", "cc", "credit"],
    "CNP": ["cnp", "personal", "identity"],
    "JWT": ["token", "auth", "authorization"],
    "HIGH_ENTROPY": ["key", "secret", "token"]
}

def extract_context(source: str) -> str:
    if source.startswith("/auth"):
        return "AUTH"
    if source.startswith("/login"):
        return "AUTH"
    if source.startswith("/profile"):
        return "PROFILE"
    if source.startswith("/payment"):
        return "PAYMENT"
    return "UNKNOWN"


def context_score(dtype: str, line: str) -> int:
    keywords = CONTEXT_KEYWORDS.get(dtype, [])
    score = 0
    lower = line.lower()
    for kw in keywords:
        if kw in lower:
            score += 10
    return score  # max ~50

def extract_direction(source: str) -> str:
    if source.startswith("/login") or source.startswith("/auth"):
        return "INBOUND"

    if source.startswith("/profile"):
        return "OUTBOUND"

    return "UNKNOWN"

