import json
from datetime import datetime

def quarantine(payload):
    with open("quarantine.log", "a") as f:
        f.write(json.dumps({
            "timestamp": str(datetime.now()),
            "payload": payload
        }) + "\n")
