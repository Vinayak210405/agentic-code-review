import hmac
import hashlib
import os
from typing import Any, Dict, List

def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verifies that the incoming webhook payload was sent by GitHub using HMAC SHA256."""
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not webhook_secret:
        return True  # Bypass in local testing mode if secret is not set
    
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_signature = "sha256=" + hmac.new(
        webhook_secret.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature_header)


def parse_github_pr_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts state variables from a raw GitHub pull_request webhook payload."""
    pr_data = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})

    pr_id = pr_data.get("number", 0)
    repo_name = repo_data.get("full_name", "unknown/repo")
    commit_sha = pr_data.get("head", {}).get("sha", "head")
    author = pr_data.get("user", {}).get("login", "unknown_user")

    # Mock diff payload extraction if actual git patch array isn't populated in webhook body
    files_changed: List[Dict[str, str]] = []
    
    if "files" in payload:
        files_changed = payload["files"]
    else:
        # Standard default diff for incoming webhooks without full file expansion
        files_changed = [
            {
                "filename": "src/api/routes.py",
                "patch": "@@ -1,3 +1,5 @@\n+ user_input = request.args.get('id')\n+ query = f'SELECT * FROM users WHERE id={user_input}'\n",
                "status": "modified"
            }
        ]

    return {
        "pr_id": pr_id,
        "repo_name": repo_name,
        "commit_sha": commit_sha,
        "author": author,
        "files_changed": files_changed,
        "security_findings": [],
        "lint_findings": [],
        "generated_tests": [],
        "status": "INITIALIZED",
        "human_approved": None,
        "human_feedback": None
    }
