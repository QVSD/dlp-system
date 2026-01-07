from dlp_engine.validators import validate_iban, validate_cnp, luhn_check
from dlp_engine.context import context_score

POLICY_THRESHOLDS = {
    "IGNORE": 30,
    "ALERT": 50,
    "BLOCK": 80
}

def compute_confidence(dtype: str, value: str, line: str, context: str) -> int:
    score = 30  # regex match

    if dtype == "IBAN" and validate_iban(value):
        score += 30
    elif dtype == "CARD" and luhn_check(value):
        score += 30
    elif dtype == "CNP" and validate_cnp(value):
        score += 30
    elif dtype in ("JWT", "HIGH_ENTROPY"):
        score += 30

    score += context_score(dtype, line)

    if context == "PROFILE":
        score += 20
    elif context == "PAYMENT":
        score += 30


    return min(score, 100)

def decide_action(confidence: int) -> str:
    if confidence >= POLICY_THRESHOLDS["BLOCK"]:
        return "BLOCK"
    if confidence >= POLICY_THRESHOLDS["ALERT"]:
        return "ALERT"
    return "IGNORE"
