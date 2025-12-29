import time
from rules import RULES

LOG_FILE = "../dlp-project/demo-app/app.log"

def scan_line(line):
    findings = []
    for name, pattern in RULES.items():
        matches = pattern.findall(line)
        for m in matches:
            findings.append((name, m))
    return findings

def main():
    print("DLP Engine started...")
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            print("LOG:", line.strip())  # DEBUG

            findings = scan_line(line)
            for f_type, value in findings:
                print(f" DLP ALERT [{f_type}] : {value}")


if __name__ == "__main__":
    main()
