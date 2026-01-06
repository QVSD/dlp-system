import time
from datetime import datetime

from rules import RULES, SEVERITY
from masking import mask_value
from scoring import compute_confidence, decide_action
from context import extract_context
from models import Finding
import os
from policy import evaluate_policy
from context import extract_direction


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "dlp-project", "demo-app", "app.log")


def scan_line(line: str):
    findings = []
    context = extract_context(line)
    direction = extract_direction(line)

    for dtype, pattern in RULES.items():
        for match in pattern.findall(line):
            value = match if isinstance(match, str) else match[0]

            confidence = compute_confidence(dtype, value, line, context)

            finding = Finding(
                dtype=dtype,
                value=value,
                masked_value=mask_value(dtype, value),
                severity=SEVERITY.get(dtype),
                confidence=confidence,
                context=context,
                direction=direction
            )

            finding.action = evaluate_policy(finding)

            if finding.action == "IGNORE":
                continue

            findings.append(finding)

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

                        if finding.action == "BLOCK":
                            print(
                                f"[{datetime.now()}] 🚫 BLOCKED | "
                                f"Type={finding.dtype} | "
                                f"Context={finding.context} | "
                                f"Direction={finding.direction} | "
                                f"Value={finding.masked_value}"
                            )

                        elif finding.action == "MASK":
                            print(
                                f"[{datetime.now()}] 🟡 MASKED | "
                                f"Type={finding.dtype} | "
                                f"Context={finding.context} | "
                                f"Value={finding.masked_value}"
                            )

                        elif finding.action == "ALERT":
                            print(
                                f"[{datetime.now()}] ⚠️ ALERT | "
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
