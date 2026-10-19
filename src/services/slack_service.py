import os
import httpx
from typing import Any, Dict, List

def send_slack_hitl_notification(thread_id: str, pr_id: int, repo_name: str, findings: List[Dict[str, Any]]) -> bool:
    """Dispatches an interactive HITL alert to Slack when critical security vulnerabilities are found."""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[Slack Service] No SLACK_WEBHOOK_URL set. Skipping notification.")
        return False

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "⚠️ Security Approval Required"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Repository:* `{repo_name}`\n*Pull Request:* `#{pr_id}`\n*Thread ID:* `{thread_id}`"
            }
        },
        {"type": "divider"}
    ]

    for finding in findings:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*[{finding.get('severity')}]* `{finding.get('rule_id')}`\n>{finding.get('description')}"
            }
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"To approve, submit POST to `/api/v1/review/approve` with thread_id: `{thread_id}`"}]
    })

    try:
        response = httpx.post(webhook_url, json={"blocks": blocks})
        return response.status_code == 200
    except Exception as e:
        print(f"[Slack Notification Error] {e}")
        return False
