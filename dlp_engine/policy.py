def evaluate_policy(finding):

    if finding.severity == "CRITICAL" and finding.direction == "OUTBOUND":
        return "BLOCK"

    if finding.severity == "HIGH" and finding.direction == "OUTBOUND":
        return "BLOCK"

    if finding.severity == "LOW" and finding.confidence >= 50:
        return "ALERT"

    return "IGNORE"

