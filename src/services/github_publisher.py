import os
import requests
from typing import Dict, Any, List, Optional


def format_review_comment(
    security_findings: Optional[List[Any]] = None,
    lint_findings: Optional[List[Any]] = None,
    generated_tests: Optional[List[Any]] = None,
) -> str:
    """Formats findings and generated tests into a Markdown PR comment."""
    security_findings = security_findings or []
    lint_findings = lint_findings or []
    generated_tests = generated_tests or []

    comment_parts = ["## 🤖 Automated Agentic Code Review\n"]

    if security_findings:
        comment_parts.append("### 🛡️ Security Audit Findings\n")
        for item in security_findings:
            if isinstance(item, dict):
                comment_parts.append(
                    f"- **[{item.get('severity', 'INFO')}]**: {item.get('description', item.get('content', str(item)))}\n"
                )
            else:
                comment_parts.append(f"{item}\n")

    if lint_findings:
        comment_parts.append("\n### 🧹 Lint & Code Quality\n")
        for item in lint_findings:
            if isinstance(item, dict):
                comment_parts.append(f"- {item.get('description', item.get('content', str(item)))}\n")
            else:
                comment_parts.append(f"{item}\n")

    if generated_tests:
        comment_parts.append("\n### 🧪 Generated Pytest Unit Tests\n")
        for item in generated_tests:
            if isinstance(item, dict):
                comment_parts.append(f"```python\n{item.get('code', str(item))}\n```\n")
            else:
                comment_parts.append(f"{item}\n")

    # Clean null characters and guarantee non-empty body
    result = "\n".join(comment_parts).replace("\x00", "")
    if not result.strip():
        result = "## 🤖 Automated Agentic Code Review\n\nNo significant findings or issues detected."

    return result


def publish_review_to_github(
    state: Optional[Dict[str, Any]] = None,
    pr_id: Optional[int] = None,
    repo_name: Optional[str] = None,
    security_findings: Optional[List[Any]] = None,
    lint_findings: Optional[List[Any]] = None,
    generated_tests: Optional[List[Any]] = None,
    status: Optional[str] = "COMPLETED",
    **kwargs,
) -> Dict[str, Any]:
    """Posts the formatted review comment to GitHub PR comments via REST API."""
    if state and isinstance(state, dict):
        pr_id = pr_id or state.get("pr_id")
        repo_name = repo_name or state.get("repo_name")
        security_findings = security_findings if security_findings is not None else state.get("security_findings", [])
        lint_findings = lint_findings if lint_findings is not None else state.get("lint_findings", [])
        generated_tests = generated_tests if generated_tests is not None else state.get("generated_tests", [])

    token = os.getenv("GITHUB_TOKEN")

    print(f"\n[Action Layer] Publishing results to GitHub PR #{pr_id}...")

    if not token or token == "your_github_token":
        print(f"[GitHub Publisher] No GITHUB_TOKEN configured. Dry-run completed for PR #{pr_id}.")
        return {"status": "COMPLETED"}

    body = format_review_comment(
        security_findings=security_findings,
        lint_findings=lint_findings,
        generated_tests=generated_tests,
    )

    url = f"https://api.github.com/repos/{repo_name}/issues/{pr_id}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        response = requests.post(url, json={"body": body}, headers=headers)
        if response.status_code not in (200, 201):
            print(f"[GitHub Publisher API Details]: Status {response.status_code} - Response: {response.text}")
        response.raise_for_status()
        print(f"[GitHub Publisher] Successfully posted review comment to PR #{pr_id}!")
        return {"status": "COMPLETED"}
    except Exception as e:
        print(f"[GitHub Publisher Error] Failed to publish comment: {e}")
        return {"status": "PUBLISH_FAILED"}