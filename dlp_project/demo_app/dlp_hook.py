from dlp_engine.rules import RULES, SEVERITY
from dlp_engine.scoring import compute_confidence
from dlp_engine.policy import evaluate_policy, MODE
from dlp_engine.masking import mask_value
from dlp_engine.context import extract_context, extract_direction
from dlp_engine.models import Finding
from dlp_engine.audit import write_audit
from dlp_engine.quarantine import quarantine

import json


def check_dlp(payload: dict, endpoint: str):
    serialized = json.dumps(payload)

    context = extract_context(endpoint)
    direction = "OUTBOUND"
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

            finding.action = evaluate_policy(finding)

            if finding.action != "IGNORE":
                write_audit(finding, endpoint=endpoint, mode=MODE)

            if finding.action == "BLOCK":
                quarantine(payload)
                return False, finding, None

            if finding.action == "MASK":
                for k, v in modified_payload.items():
                    if v == value:
                        modified_payload[k] = finding.masked_value

    return True, None, modified_payload
