"""Slack notification for the human-in-the-loop security gate."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import httpx

from config.settings import get_settings

logger = logging.getLogger(__name__)


def build_blocks(thread_id: str, pr_id: int, repo_name: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": "⚠️ Security approval required"}},
        {"type": "section", "text": {"type": "mrkdwn",
                                     "text": f"*Repository:* `{repo_name}`\n*Pull request:* #{pr_id}\n*Thread:* `{thread_id}`"}},
        {"type": "divider"},
    ]
    for f in findings[:10]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text":
                       f"*[{f.get('severity')}]* `{f.get('rule_id')}` {f.get('title')}\n"
                       f"`{f.get('file_path')}:{f.get('line_number')}` · {f.get('owasp_category')}"}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text":
                   f"Approve/reject: `POST /api/v1/reviews/{thread_id}/decision` "
                   "with `{\"approved\": true|false, \"feedback\": \"...\"}`"}]})
    return blocks


def send_slack_hitl_notification(thread_id: str, pr_id: int, repo_name: str, findings: List[Dict[str, Any]]) -> bool:
    url = get_settings().slack_webhook_url
    if not url:
        logger.info("[Slack] SLACK_WEBHOOK_URL not set; skipping notification for %s.", thread_id)
        return False
    try:
        resp = httpx.post(url, json={"blocks": build_blocks(thread_id, pr_id, repo_name, findings)}, timeout=10)
        return resp.status_code == 200
    except httpx.HTTPError as exc:
        logger.warning("[Slack] Notification failed: %s", exc)
        return False
