from typing import Dict, Any
from langchain_groq import ChatGroq

llm = ChatGroq(
    model_name="openai/gpt-oss-120b",
    temperature=0,
    max_retries=5,
)


def linter_node(state: Dict[str, Any]) -> Dict[str, Any]:
    files = state.get("files_changed", [])
    findings = list(state.get("lint_findings", []))

    if not files:
        findings.append("No file diffs provided for linting.")
        return {"lint_findings": findings}

    for file in files:
        filename = file.get("filename", "unknown")
        patch = file.get("patch", "")

        if not patch:
            continue

        prompt = f"""
You are a senior Code Quality Auditor and Linter.
Review the following code diff for software best practices, readability, code smells, missing docstrings, and potential performance bottlenecks.

File: {filename}

Diff Patch:
{patch}

Provide concise, bulleted feedback on code structure, styling, and logic improvements.
"""
        response = llm.invoke(prompt)
        findings.append(f"### Linting & Quality Review for `{filename}`\n{response.content}")

    return {"lint_findings": findings}