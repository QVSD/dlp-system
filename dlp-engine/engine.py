import time
from datetime import datetime

from rules import RULES, SEVERITY
from masking import mask_value
from scoring import compute_confidence, decide_action
from context import extract_context
from models import Finding
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "dlp-project", "demo-app", "app.log")


def scan_line(line: str):
    # print("SCAN LINE:", line.strip())

    findings = []
    context = extract_context(line)

    for dtype, pattern in RULES.items():
        matches = pattern.findall(line)
        # print(f"CHECK {dtype} → matches =", matches)

        for match in pattern.findall(line):
            value = match if isinstance(match, str) else match[0]

            confidence = compute_confidence(dtype, value, line, context)
            action = decide_action(confidence)

            # print(
            #     f"FOUND {dtype} | "
            #     f"confidence={confidence} | "
            #     f"action={action}"
            # )


            if action == "IGNORE":
                continue

            findings.append(Finding(
                dtype=dtype,
                value=value,
                masked_value=mask_value(dtype, value),
                severity=SEVERITY.get(dtype, "UNKNOWN"),
                confidence=confidence,
                action=action,
                context=context
            ))
    return findings

def main():
    print("DLP Engine started...")
    # print("LOG_FILE =", LOG_FILE)
    # print("EXISTS =", os.path.exists(LOG_FILE))


    last_size = 0

    while True:
        try:
            current_size = os.path.getsize(LOG_FILE)
            # print("FILE SIZE =", current_size, "LAST SIZE =", last_size)

            # dacă fișierul a fost recreat sau trunchiat
            if current_size < last_size:
                last_size = 0

            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_size)
                # print("SEEK TO =", last_size)

                for line in f:
                    for finding in scan_line(line):
                        # print("RAW LINE >>>", repr(line))

                        print(
                            f"[{datetime.now()}] "
                            f"DLP {finding.action} | "
                            f"Type={finding.dtype} | "
                            f"Severity={finding.severity} | "
                            f"Confidence={finding.confidence} | "
                            f"Context={finding.context} | "
                            f"Value={finding.masked_value}"
                        )
                last_size = f.tell()

            time.sleep(1)

        except FileNotFoundError:
            time.sleep(1)


if __name__ == "__main__":
    main()
