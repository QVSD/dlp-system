import re

RULES = {
    "EMAIL": re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ),
    "CNP": re.compile(
        r"(?:^|[^0-9])([1-8]\d{12})(?:[^0-9]|$)"
    ),
    "IBAN": re.compile(
        r"(?:RO\d{2}[A-Z]{4}\d{16})"
    ),
}
