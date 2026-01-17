import requests
from dlp_engine.rate_limit import should_send_alert

SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX/YYY/ZZZ"

def send_alert(finding, endpoint=None):
    send, suppressed = should_send_alert(finding, endpoint)

    if not send:
        print(
            f"[RATE-LIMIT] Alert SUPPRESSED | "
            f"Type={finding.dtype} | "
            f"Action={finding.action} | "
            f"Endpoint={endpoint}"
        )
        return

    msg = (
        f"! DLP ALERT | "
        f"Type={finding.dtype} | "
        f"Severity={finding.severity} | "
        f"Confidence={finding.confidence}% | "
        f"Action={finding.action} | "
        f"Endpoint={endpoint}"
    )

    if suppressed:
        msg += f" | suppressed_duplicates={suppressed}"

    print(msg)

