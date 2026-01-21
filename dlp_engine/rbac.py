from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass(frozen=True)
class RolePolicy:
    allowed_severities: List[str]
    allowed_actions: List[str]
    see_raw_value: bool
    see_masked_value: bool
    can_change_mode: bool
    can_edit_policies: bool
    can_read_audit: bool


ROLE_POLICIES: Dict[str, RolePolicy] = {
    # SOC: sees alerts, but not raw values
    "SOC_ANALYST": RolePolicy(
        allowed_severities=["LOW", "MEDIUM", "HIGH"],
        allowed_actions=["ALERT", "MASK", "BLOCK"],
        see_raw_value=False,
        see_masked_value=True,
        can_change_mode=False,
        can_edit_policies=False,
        can_read_audit=True
    ),

    # Admin: sees everything, can change mode (MONITOR/ENFORCE)
    "SECURITY_ADMIN": RolePolicy(
        allowed_severities=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        allowed_actions=["ALERT", "MASK", "BLOCK"],
        see_raw_value=False,         
        see_masked_value=True,
        can_change_mode=True,
        can_edit_policies=True,
        can_read_audit=True
    ),

    # Auditor: sees HIGH/CRITICAL without values (only metadata)
    "AUDITOR": RolePolicy(
        allowed_severities=["HIGH", "CRITICAL"],
        allowed_actions=["ALERT", "MASK", "BLOCK"],
        see_raw_value=False,
        see_masked_value=False,
        can_change_mode=False,
        can_edit_policies=False,
        can_read_audit=True
    ),

    # Default / unknown
    "DEFAULT": RolePolicy(
        allowed_severities=[],
        allowed_actions=[],
        see_raw_value=False,
        see_masked_value=False,
        can_change_mode=False,
        can_edit_policies=False,
        can_read_audit=False
    )
}


def get_role_policy(role: Optional[str]) -> RolePolicy:
    if not role:
        return ROLE_POLICIES["DEFAULT"]
    return ROLE_POLICIES.get(role.upper(), ROLE_POLICIES["DEFAULT"])


def is_allowed_to_view(finding, role: str) -> bool:
    rp = get_role_policy(role)
    if finding.severity not in rp.allowed_severities:
        return False
    if finding.action not in rp.allowed_actions:
        return False
    return True


def redact_finding_for_role(finding, role: str) -> dict:
    """
    Returns an object safe-to-display as the role implies
    """
    rp = get_role_policy(role)

    data = {
        "dtype": finding.dtype,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "action": finding.action,
        "direction": finding.direction,
        "context": finding.context,
    }

    # Not recommended to show raw_value to admins

    if rp.see_raw_value:
        data["value"] = finding.value

    if rp.see_masked_value:
        data["masked_value"] = finding.masked_value

    return data

def redact_audit_event_for_role(event: dict, role: str) -> dict:
    rp = get_role_policy(role)

    if not rp.can_read_audit:
        return {}

    # FILTER
    if event.get("severity") not in rp.allowed_severities:
        return {}

    if event.get("action") not in rp.allowed_actions:
        return {}

    base = {
        "timestamp": event["timestamp"],
        "event_type": event["event_type"],
        "data_type": event["data_type"],
        "severity": event["severity"],
        "action": event["action"],
        "context": event["context"],
        "direction": event["direction"],
        "endpoint": event["endpoint"],
        "confidence": event["confidence"],
    }

    if rp.see_masked_value:
        base["masked_value"] = event.get("masked_value")

    # ADMIN EXTRA VISIBILITY
    if role == "SECURITY_ADMIN":
        base["mode"] = event.get("mode")
        base["policy"] = event.get("policy")
        base["decision_reason"] = event.get("decision_reason")

    return base
