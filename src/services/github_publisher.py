"""Publish results back to GitHub: a PR review with inline comments on the
offending lines, a summary comment, and a commit status that can be made a
required check (so blocking findings stop the merge/deploy)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from config.settings import get_settings

logger = logging.getLogger(__name__)
INLINE_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}


def commit_status_for(decision: str) -> str:
    return {"PASS": "success", "APPROVED_BY_HUMAN": "success", "NEEDS_HUMAN_REVIEW": "pending"}.get(decision, "failure")


def review_event_for(decision: str) -> str:
    return {"REJECTED_BY_HUMAN": "REQUEST_CHANGES", "PASS": "COMMENT", "APPROVED_BY_HUMAN": "COMMENT"}.get(decision, "COMMENT")


def inline_comments(state: Dict[str, Any], limit: int = 30) -> List[Dict[str, Any]]:
    comments = []
    for f in state.get("security_findings", []):
        if f["severity"] in INLINE_SEVERITIES and f.get("line_number"):
            refs = ", ".join(r["rule_id"] for r in f.get("standard_refs", []))
            comments.append({
                "path": f["file_path"], "line": int(f["line_number"]), "side": "RIGHT",
                "body": f"**[{f['severity']}] {f['title']}** ({f['owasp_category']}, {f['cwe']})\n\n"
                        f"{f['description']}\n\n**Fix:** {f['mitigation']}" + (f"\n\n_Standards: {refs}_" if refs else ""),
            })
    return comments[:limit]


def publish_review_to_github(state: Dict[str, Any], report_markdown: str) -> bool:
    token = get_settings().github_token
    repo_name, pr_id = state.get("repo_name", ""), state.get("pr_id", 0)
    if not token or "/" not in repo_name or not pr_id:
        logger.info("[GitHub] Dry run for %s#%s (no token or not a GitHub PR).", repo_name, pr_id)
        return False
    try:
        from github import Auth, Github

        gh = Github(auth=Auth.Token(token))
        repo = gh.get_repo(repo_name)
        pr = repo.get_pull(pr_id)
        decision = state.get("decision", "PASS")
        comments = inline_comments(state)
        try:
            pr.create_review(body=report_markdown, event=review_event_for(decision), comments=comments)
        except Exception as exc:  # inline positions can be rejected (e.g. outdated diff); fall back
            logger.warning("[GitHub] Inline review failed (%s); posting summary comment.", exc)
            pr.create_issue_comment(report_markdown)
        sha = state.get("commit_sha")
        if sha and sha not in {"head", "local"}:
            risk = state.get("risk", {})
            repo.get_commit(sha).create_status(
                state=commit_status_for(decision), context="agentic-code-review/security",
                description=f"{decision} · risk {risk.get('level', 'NONE')} · {risk.get('blocking_count', 0)} blocking"[:140],
            )
        logger.info("[GitHub] Published review to %s#%s", repo_name, pr_id)
        return True
    except Exception as exc:
        logger.error("[GitHub] Failed to publish review: %s", exc)
        return False
