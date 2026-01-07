from dlp_engine.rules import RULES, SEVERITY
from dlp_engine.scoring import compute_confidence
from dlp_engine.policy import evaluate_policy
from dlp_engine.masking import mask_value
from dlp_engine.context import extract_context, extract_direction
from dlp_engine.models import Finding

import json

def check_dlp(payload: dict, endpoint: str):
    """
    Rulează DLP înainte de a trimite response-ul
    """
    serialized = json.dumps(payload)

    context = "PROFILE" if endpoint == "/profile" else "UNKNOWN"
    direction = "OUTBOUND"

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

            if finding.action == "BLOCK":
                return False, finding

    return True, None
