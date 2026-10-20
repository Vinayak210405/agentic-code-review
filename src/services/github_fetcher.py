import os
import requests
from typing import Dict, Any


def fetch_pr_files_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Fetches changed files and diff patches from GitHub REST API."""
    pr_id = state.get("pr_id")
    repo_name = state.get("repo_name")
    token = os.getenv("GITHUB_TOKEN")

    print(f"\n[Action Layer] Fetching files changed for PR #{pr_id} in {repo_name}...")

    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_id}/files"
    headers = {
        "Accept": "application/vnd.github.v3+json",
    }
    if token and token != "your_github_token":
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        files_data = response.json()

        files_changed = []
        for f in files_data:
            files_changed.append({
                "filename": f.get("filename"),
                "status": f.get("status"),
                "patch": f.get("patch", ""),
            })

        print(f"[Action Layer] Successfully fetched {len(files_changed)} file(s).")
        return {"files_changed": files_changed}

    except Exception as e:
        print(f"[GitHub Fetcher Error] Failed to fetch PR files: {e}")
        return {"files_changed": []}