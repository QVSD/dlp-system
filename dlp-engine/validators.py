import base64
import json

# -------------------------
# Card (Luhn)
# -------------------------
def luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False

    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

# -------------------------
# IBAN (MOD-97)
# -------------------------
def validate_iban(iban: str) -> bool:
    iban = iban.replace(" ", "")
    if len(iban) < 15 or not iban[:2].isalpha():
        return False

    rearranged = iban[4:] + iban[:4]
    numeric = ""
    for c in rearranged:
        numeric += str(ord(c) - 55) if c.isalpha() else c

    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False

# -------------------------
# CNP (checksum RO)
# -------------------------
def validate_cnp(cnp: str) -> bool:
    if len(cnp) != 13 or not cnp.isdigit():
        return False

    control = "279146358279"
    total = sum(int(cnp[i]) * int(control[i]) for i in range(12))
    return total % 11 % 10 == int(cnp[12])

# -------------------------
# JWT decode (without verify)
# -------------------------
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)

def decode_jwt(token: str):
    try:
        header_b64, payload_b64, _ = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        return {"header": header, "payload": payload}
    except Exception:
        return None
