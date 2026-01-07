import yaml
import os
import time

_POLICY_CACHE = None
_LAST_MTIME = 0

POLICY_FILE = os.path.join(
    os.path.dirname(__file__),
    "policy.yaml"
)

def load_policy():
    global _POLICY_CACHE, _LAST_MTIME

    mtime = os.path.getmtime(POLICY_FILE)

    # hot reload
    if _POLICY_CACHE and mtime == _LAST_MTIME:
        return _POLICY_CACHE

    with open(POLICY_FILE, "r") as f:
        _POLICY_CACHE = yaml.safe_load(f)
        _LAST_MTIME = mtime

    return _POLICY_CACHE
