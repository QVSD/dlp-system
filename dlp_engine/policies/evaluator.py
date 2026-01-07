from .loader import load_policy

def match_condition(finding, cond: dict):
    if "severity" in cond and finding.severity != cond["severity"]:
        return False

    if "direction" in cond and finding.direction != cond["direction"]:
        return False

    if "min_confidence" in cond and finding.confidence < cond["min_confidence"]:
        return False

    return True


def evaluate_policy(finding):
    policy = load_policy()

    mode = policy.get("mode", "MONITOR")

    policies = sorted(
        policy.get("policies", []),
        key=lambda p: p.get("priority", 0),
        reverse=True
    )

    for rule in policies:
        cond = rule.get("when", {})

        if not cond or match_condition(finding, cond):
            action = rule["action"]

            # MONITOR = not blocking anything
            if mode == "MONITOR" and action == "BLOCK":
                return "ALERT"

            return action

    return "IGNORE"
