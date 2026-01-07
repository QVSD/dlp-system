import yaml
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.path.join(BASE_DIR, "policies", "policies.yaml")


def load_config():
    with open(POLICY_FILE, "r") as f:
        return yaml.safe_load(f)

def load_policies():
    with open(POLICY_FILE, "r") as f:
        return yaml.safe_load(f)["policies"]



CONFIG = load_config()
POLICIES = CONFIG["policies"]
MODE = CONFIG.get("mode", "MONITOR")


def evaluate_policy(finding):
    for policy in POLICIES:
        if not _matches_conditions(finding, policy["when"]):
            continue

        action = policy["action"]

        #  MONITOR : dont block anything / ENFORCE : full exec
        if MODE == "MONITOR" and action in ("BLOCK", "MASK"):
            return "ALERT"

        return action

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
