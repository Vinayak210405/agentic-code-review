import os
from typing import Any, Dict, List
from github import Github

def publish_review_to_github(
    pr_id: int,
    repo_name: str,
    security_findings: List[Dict[str, Any]],
    lint_findings: List[Dict[str, Any]],
    generated_tests: List[Dict[str, Any]],
    status: str
) -> bool:
    """Posts compiled security, lint, and test suite findings directly to the GitHub PR as a comment."""
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print(f"[GitHub Publisher] No GITHUB_TOKEN configured. Dry-run completed for PR #{pr_id}.")
        return False

    try:
        g = Github(github_token)
        repo = g.get_repo(repo_name)
        pr = repo.get_pull(pr_id)

        comment_md = "## 🤖 Autonomous Agentic Code Review Report\n\n"
        comment_md += f"**Review Decision:** `{status}`\n\n"

        if security_findings:
            comment_md += "### 🛡️ Security Vulnerabilities\n"
            for sf in security_findings:
                comment_md += f"- **[{sf.get('severity')}]** `{sf.get('rule_id')}` in `{sf.get('file_path')}` (Line {sf.get('line_number')})\n"
                comment_md += f"  - **Issue:** {sf.get('description')}\n"
                comment_md += f"  - **Mitigation:** {sf.get('mitigation')}\n\n"

        if lint_findings:
            comment_md += "### 🧹 Code Quality & Style Analysis\n"
            for lf in lint_findings:
                comment_md += f"- `{lf.get('file_path')}` (Line {lf.get('line_number')}): {lf.get('issue')}\n"
                comment_md += f"  - **Suggestion:** {lf.get('suggestion')}\n\n"

        if generated_tests:
            comment_md += "### 🧪 Automated Unit Test Recommendations\n"
            for gt in generated_tests:
                comment_md += f"<details><summary>Click to view PyTest suite for <code>{gt.get('target_file')}</code></summary>\n\n"
                comment_md += f"```python\n{gt.get('test_code')}\n```\n</details>\n\n"

        pr.create_issue_comment(comment_md)
        print(f"[GitHub Publisher] Published review comment to {repo_name} PR #{pr_id}.")
        return True
    except Exception as e:
        print(f"[GitHub Publisher Error] Failed to publish comment: {str(e)}")
        return False
