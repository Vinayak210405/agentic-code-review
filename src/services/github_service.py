"""GitHub webhook verification and PR payload/file ingestion."""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any, Dict, List

from config.settings import get_settings

logger = logging.getLogger(__name__)
MAX_CONTENT_BYTES = 200_000


def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify GitHub's ``X-Hub-Signature-256`` HMAC.

    Unsigned requests are only accepted when no secret is configured AND the
    app runs in development mode; production always requires a valid signature.
    """
    settings = get_settings()
    secret = settings.github_webhook_secret
    if not secret:
        return settings.is_development
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def fetch_pr_files(repo_name: str, pr_number: int, head_sha: str) -> List[Dict[str, Any]]:
    """Fetch changed files (patch + full post-change content for code files) via the GitHub API."""
    token = get_settings().github_token
    if not token:
        return []
    from github import Auth, Github

    gh = Github(auth=Auth.Token(token))
    repo = gh.get_repo(repo_name)
    files: List[Dict[str, Any]] = []
    for f in repo.get_pull(pr_number).get_files():
        entry: Dict[str, Any] = {"filename": f.filename, "status": f.status, "patch": f.patch or ""}
        if f.status != "removed" and f.filename.endswith(".py") and (f.changes or 0) > 0:
            try:
                blob = repo.get_contents(f.filename, ref=head_sha)
                if not isinstance(blob, list) and (blob.size or 0) <= MAX_CONTENT_BYTES:
                    entry["content"] = blob.decoded_content.decode("utf-8", "replace")
            except Exception as exc:  # content is optional; the patch alone is still analysed
                logger.warning("Could not fetch %s@%s: %s", f.filename, head_sha, exc)
        files.append(entry)
    return files


def parse_github_pr_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    pr = payload.get("pull_request", {}) or {}
    repo = payload.get("repository", {}) or {}
    return {
        "pr_id": int(pr.get("number") or payload.get("number") or 0),
        "repo_name": repo.get("full_name", "unknown/repo"),
        "commit_sha": (pr.get("head") or {}).get("sha", "head"),
        "author": (pr.get("user") or {}).get("login", "unknown"),
        "title": pr.get("title", ""),
        "files": payload.get("files") or [],
    }
