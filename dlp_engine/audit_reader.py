import os
import json
from dlp_engine.rbac import (
    get_role_policy,
    redact_audit_event_for_role
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FILE = os.path.join(BASE_DIR, "dlp_audit.log")
ROLE = os.getenv("DLP_ROLE", "DEFAULT")

def tail_audit(n=50):
    if not os.path.exists(AUDIT_FILE):
        return []

    rp = get_role_policy(ROLE)

    # RBAC: role cannot read audit at all
    if not rp.can_read_audit:
        return []

    events = []

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-n:]

        for line in lines:
            if not line.strip():
                continue

            event = json.loads(line)

            redacted = redact_audit_event_for_role(event, ROLE)

            if redacted:
                events.append(redacted)

    return events
