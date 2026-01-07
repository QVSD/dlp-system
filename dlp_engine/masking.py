# Safe exposing as we are not re-leaking any data

def mask_value(dtype: str, value: str) -> str:
    if dtype == "EMAIL":
        name, domain = value.split("@", 1)
        return name[0] + "***@" + domain

    if dtype == "CARD":
        return "*" * (len(value) - 4) + value[-4:]

    if dtype == "CNP":
        return value[:4] + "*" * (len(value) - 4)

    if dtype == "IBAN":
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    if dtype == "PHONE":
        return value[:3] + "*" * (len(value) - 5) + value[-2:]

    if dtype == "JWT":
        return value[:10] + "...[REDACTED]"

    if dtype == "HIGH_ENTROPY":
        return value[:4] + "***" + value[-4:]

    return "[REDACTED]"
