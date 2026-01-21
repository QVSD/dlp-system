import json
from datetime import datetime
import uuid
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FILE = os.path.join(BASE_DIR, "dlp_audit.log")


def write_audit(finding, endpoint: str, request_id: str = None):
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": f"DLP_{finding.action}",
        "data_type": finding.dtype,
        "severity": finding.severity,
        "confidence": finding.confidence,

        "action": finding.action.name if hasattr(finding.action, "name") else str(finding.action),
        "original_action": getattr(finding, "original_action", None),

        "direction": finding.direction,
        "context": finding.context,
        "endpoint": endpoint,

        "masked_value": finding.masked_value,
        "mode": getattr(finding, "mode_used", "UNKNOWN"),
        "request_id": request_id or str(uuid.uuid4()),

        "policy": finding.policy.name if hasattr(finding.policy, "name") else str(finding.policy),
        "decision_reason": getattr(finding, "decision_reason", None),
    }

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def build_reason(finding):
    if finding.action == "BLOCK":
        return "Outbound sensitive data blocked by policy"
    if finding.action == "MASK":
        return "Sensitive data masked according to policy"
    if finding.action == "ALERT":
        return "Sensitive data detected (monitoring)"
    return "No action"
