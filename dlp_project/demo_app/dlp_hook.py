from dlp_engine.rules import RULES, SEVERITY
from dlp_engine.scoring import compute_confidence
from dlp_engine.policy import evaluate_policy
from dlp_engine.masking import mask_value
from dlp_engine.context import extract_context, extract_direction
from dlp_engine.models import Finding
from dlp_engine.audit import write_audit
from dlp_engine.quarantine import quarantine
from dlp_engine.alerting import send_alert
from dlp_engine.metrics import inc


import json


def check_dlp(payload: dict, endpoint: str):
    print("\n=== DLP CHECK START ===")
    print("Endpoint raw:", endpoint)
    print("Payload:", payload)

    serialized = json.dumps(payload)

    context = extract_context(endpoint)
    direction = extract_direction(endpoint)

    print("Extracted context:", context)
    print("Extracted direction:", direction)

    modified_payload = payload.copy()

    for dtype, pattern in RULES.items():
        for match in pattern.findall(serialized):
            value = match if isinstance(match, str) else match[0]

            confidence = compute_confidence(dtype, value, serialized, context)

            finding = Finding(
                dtype=dtype,
                value=value,
                masked_value=mask_value(dtype, value),
                severity=SEVERITY.get(dtype),
                confidence=confidence,
                context=context,
                direction=direction
            )
            print("\n--- Finding candidate ---")
            print("Type:", dtype)
            print("Value:", value)
            print("Severity:", SEVERITY.get(dtype))
            print("Confidence:", confidence)
            print("Context:", context)
            print("Direction:", direction)


            finding.action = evaluate_policy(finding)
            finding.action = evaluate_policy(finding)

            print("=> Policy decision:")
            print("   Action:", finding.action)
            print("   Matched policy:", getattr(finding, "policy", "N/A"))


            inc("dlp_events_total")
            inc("dlp_events_by_type", {"type": finding.dtype})
            inc("dlp_events_by_action", {"action": finding.action})

            if finding.action in ("ALERT", "MASK", "BLOCK"):
                send_alert(finding, endpoint=endpoint)

            if finding.action != "IGNORE":
                write_audit(finding, endpoint=endpoint)

            if finding.action == "BLOCK":
                inc("dlp_blocks_total")
                quarantine(payload)
                return False, finding, None

            if finding.action == "MASK":
                inc("dlp_masks_total")
                for k, v in modified_payload.items():
                    if v == value:
                        modified_payload[k] = finding.masked_value
                        
            if finding.action == "ALERT":
                inc("dlp_alerts_total")
                write_audit(finding, endpoint=endpoint)
    return True, None, modified_payload
