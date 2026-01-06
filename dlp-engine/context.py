# Context awareness (to reduce the no of FP)

CONTEXT_KEYWORDS = {
    "IBAN": ["iban", "account", "cont", "payment", "transfer"],
    "CARD": ["card", "payment", "cc", "credit"],
    "CNP": ["cnp", "personal", "identity"],
    "JWT": ["token", "auth", "authorization"],
    "HIGH_ENTROPY": ["key", "secret", "token"]
}

def extract_context(line: str) -> str:
    if "endpoint=/login" in line:
        return "LOGIN"
    if "endpoint=/profile" in line:
        return "PROFILE"
    if "payment" in line.lower():
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
