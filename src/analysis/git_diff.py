"""Split a multi-file ``git diff`` into per-file patches (GitHub API shape)."""
from __future__ import annotations

import re
from typing import Dict, List

_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")


def split_git_diff(diff_text: str) -> List[Dict[str, str]]:
    files: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    body: List[str] = []

    def flush() -> None:
        if current:
            current["patch"] = "\n".join(body).strip("\n") + ("\n" if body else "")
            files.append(dict(current))

    for line in diff_text.splitlines():
        m = _DIFF_HEADER.match(line)
        if m:
            flush()
            current.clear()
            current.update({"filename": m.group(2), "status": "modified"})
            body = []
            continue
        if not current:
            continue
        if line.startswith("new file mode"):
            current["status"] = "added"
        elif line.startswith("deleted file mode"):
            current["status"] = "removed"
        elif line.startswith("rename to "):
            current["filename"] = line[len("rename to "):]
            current["status"] = "renamed"
        elif line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
            current["filename"] = line[4:].removeprefix("b/")
        elif line.startswith(("--- ", "+++ ", "index ", "similarity ", "rename from", "old mode", "new mode", "Binary")):
            continue
        else:
            body.append(line)
    flush()
    return [f for f in files if f.get("patch") or f["status"] == "removed"]
