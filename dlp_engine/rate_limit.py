import time
from collections import defaultdict

# key => { last_sent, suppressed }
_rate_state = defaultdict(lambda: {"last_sent": 0, "suppressed": 0})

# configurable
ALERT_COOLDOWN = 60  # seconds


def should_send_alert(finding, endpoint=None):
    """
    Decide if an alert should be sent or suppressed
    """
    key = (
        finding.dtype,
        finding.action,
        endpoint or "UNKNOWN"
    )

    now = time.time()
    state = _rate_state[key]

    if now - state["last_sent"] >= ALERT_COOLDOWN:
        suppressed = state["suppressed"]
        state["last_sent"] = now
        state["suppressed"] = 0
        return True, suppressed

    # in cooldown => suppressing
    state["suppressed"] += 1
    return False, None
