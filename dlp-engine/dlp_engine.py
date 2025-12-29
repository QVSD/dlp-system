import time
from rules import RULES, SEVERITY
from datetime import datetime

LOG_FILE = "../app.log"

def scan_line(line):
    findings = []
    for dtype, pattern in RULES.items():
        matches = pattern.findall(line)
        for match in matches:
            value = match if isinstance(match, str) else match[0]

            # Card validation
            if dtype == "CARD":
                if not luhn_check(value):
                    continue

            findings.append({
                "type": dtype,
                "value": value,
                "severity": SEVERITY.get(dtype, "UNKNOWN")
            })
    return findings

def extract_context(line):
    if "/login" in line:
        return "LOGIN"
    if "/profile" in line:
        return "PROFILE"
    return "UNKNOWN"

def luhn_check(card_number):
    digits = [int(d) for d in card_number if d.isdigit()]
    checksum = 0
    parity = len(digits) % 2

    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0

def main():
    print("DLP Engine started...")
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            context = extract_context(line)
            findings = scan_line(line)

            for finding in findings:
                masked = mask_value(finding["type"], finding["value"])

                print(
                    f"[{datetime.now()}] "
                    f"DLP ALERT | "
                    f"Type={finding['type']} | "
                    f"Severity={finding['severity']} | "
                    f"Context={context} | "
                    f"Value={masked}"
                )

                
def mask_value(dtype, value):
    if dtype == "EMAIL":
        name, domain = value.split("@")
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

    return "[REDACTED]"


if __name__ == "__main__":
    main()
