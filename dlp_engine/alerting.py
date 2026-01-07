import requests

SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX/YYY/ZZZ"

def send_alert(finding):
    message = {
        "text": f"🚨 DLP ALERT\nType: {finding.dtype}\nSeverity: {finding.severity}\nContext: {finding.context}"
    }
    requests.post(SLACK_WEBHOOK, json=message)
