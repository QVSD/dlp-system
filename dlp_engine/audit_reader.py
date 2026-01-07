import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FILE = os.path.join(BASE_DIR, "dlp_audit.log")

def tail_audit(n=50):
    if not os.path.exists(AUDIT_FILE):
        return []

    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-n:]
        return [json.loads(line) for line in lines if line.strip()]

