import yaml
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.path.join(BASE_DIR, "policies", "policies.yaml")


def load_policies():
    with open(POLICY_FILE, "r") as f:
        return yaml.safe_load(f)["policies"]


POLICIES = load_policies()


def evaluate_policy(finding):
    for policy in POLICIES:
        conditions = policy["when"]

        if not _matches_conditions(finding, conditions):
            continue

        return policy["action"]

    return "IGNORE"


def _matches_conditions(finding, conditions):
    if "severity" in conditions and finding.severity != conditions["severity"]:
        return False

    if "direction" in conditions and finding.direction != conditions["direction"]:
        return False

    if "context" in conditions and finding.context != conditions["context"]:
        return False

    if "min_confidence" in conditions and finding.confidence < conditions["min_confidence"]:
        return False

    return True
