import time
from datetime import datetime

from dlp_engine.rules import RULES, SEVERITY
from dlp_engine.masking import mask_value
from dlp_engine.scoring import compute_confidence
from dlp_engine.context import extract_context
from dlp_engine.alerting import send_alert
from dlp_engine.models import Finding
from dlp_engine.audit import write_audit
from dlp_engine.rbac import is_allowed_to_view, redact_finding_for_role
import os
from dlp_engine.context import extract_direction
from dlp_engine.policies.evaluator import evaluate_policy
from dlp_engine.policies.loader import get_mode


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "..", "dlp-project", "demo-app", "app.log")
MODE = get_mode()


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

            if finding.action in ("ALERT", "BLOCK", "MASK"):
                write_audit(finding, endpoint=None, mode=MODE)

            if finding.action == "IGNORE":
                continue

            findings.append(finding)

    return findings

def main():
    ROLE = os.getenv("DLP_ROLE", "DEFAULT")
    print(f"DLP Engine started in {MODE} mode (role={ROLE})")

    # print("LOG_FILE =", LOG_FILE)
    # print("EXISTS =", os.path.exists(LOG_FILE))


    last_size = 0

    while True:
        try:
            current_size = os.path.getsize(LOG_FILE)
            # print("FILE SIZE =", current_size, "LAST SIZE =", last_size)

            if current_size < last_size:
                last_size = 0

            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_size)
                # print("SEEK TO =", last_size)

                for line in f:
                    for finding in scan_line(line):
                        # RBAC check : allowed to see the event?
                        if not is_allowed_to_view(finding, ROLE):
                            continue

                        #  RBAC redaction : what field it sees?
                        safe = redact_finding_for_role(finding, ROLE)

                        if finding.action == "BLOCK":
                            print(
                                f"[{datetime.now()}] | BLOCKED | {safe}"
                            )

                        elif finding.action == "MASK":
                            print(
                                f"[{datetime.now()}] <> MASKED | {safe}"
                            )

                        elif finding.action == "ALERT":
                            send_alert(finding, endpoint=None)
                            print(
                                f"[{datetime.now()}] ! ALERT | {safe}"
                            )


                last_size = f.tell()

            time.sleep(1)

        except FileNotFoundError:
            time.sleep(1)


if __name__ == "__main__":
    main()
