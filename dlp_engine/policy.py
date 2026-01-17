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
POLICIES = sorted(
    CONFIG["policies"],
    key=lambda p: p.get("priority", 0),
    reverse=True
)

MODE = CONFIG.get("mode", "MONITOR")


def evaluate_policy(finding):
    finding.mode_used = MODE

    for policy in POLICIES:
        if not _matches_conditions(finding, policy.get("when", {})):
            continue

        finding.policy = policy.get("name", "UNKNOWN_POLICY")

        original_action = policy["action"]
        finding.policy = policy["name"]

        if MODE == "MONITOR" and original_action in ("BLOCK", "MASK"):
            print(f"MODE=MONITOR → downgraded {original_action} to ALERT (policy={finding.policy})")
            finding.reason = f"Policy would {original_action} in ENFORCE mode"
            finding.action = "ALERT"
            return finding

        finding.decision_reason = f"Policy enforced: {policy['name']}"

        return original_action

    finding.policy = "DEFAULT"
    finding.original_action = "IGNORE"
    finding.reason = "No policy matched"
    return "IGNORE"



def _matches_conditions(finding, when: dict) -> bool:
    print("  Evaluating conditions:", when)
    if not when:
        print("  -> empty conditions = MATCH")
        return True

    if "data_type" in when and finding.dtype != when["data_type"]:
        print("  data_type check:", finding.dtype, "==", when["data_type"])
        return False

    if "severity" in when and finding.severity != when["severity"]:
        return False

    if "direction" in when and finding.direction != when["direction"]:
        return False

    if "context" in when and finding.context != when["context"]:
        return False

    if "min_confidence" in when and finding.confidence < when["min_confidence"]:
        return False

    return True


def set_mode(new_mode: str):
    global MODE
    MODE = new_mode
