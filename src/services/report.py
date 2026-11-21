"""Render the consolidated review as GitHub-flavoured markdown."""
from __future__ import annotations

from typing import Any, Dict

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
DECISION_TEXT = {
    "PASS": "✅ Passed automated review",
    "NEEDS_HUMAN_REVIEW": "⏸️ Awaiting security sign-off",
    "APPROVED_BY_HUMAN": "✅ Approved by security reviewer (risk accepted)",
    "REJECTED_BY_HUMAN": "⛔ Changes requested by security reviewer",
}


def build_report_markdown(state: Dict[str, Any], max_items: int = 50) -> str:
    risk = state.get("risk", {})
    sec = state.get("security_findings", [])
    lint = state.get("lint_findings", [])
    tests = state.get("generated_tests", [])
    docs = state.get("documentation", {}) or {}
    metrics = state.get("metrics", {})
    decision = state.get("decision", "PASS")

    md = ["## 🤖 Agentic Code Review Report", ""]
    md.append(f"**Decision:** {DECISION_TEXT.get(decision, decision)}  ")
    md.append(f"**Risk:** {risk.get('level', 'NONE')} (score {risk.get('score', 0)})  ")
    if state.get("reviewer"):
        md.append(f"**Reviewer:** @{state['reviewer']} — {state.get('human_feedback') or ''}  ")
    counts = risk.get("severity_counts", {})
    md.append("**Findings:** " + " · ".join(f"{SEV_ICON[s]} {s.title()} {counts.get(s, 0)}" for s in SEV_ICON))
    md.append("")

    if sec:
        md += ["### 🛡️ Security (OWASP Top 10)", "",
               "| Sev | Rule | OWASP | Location | Issue | Standard |", "|---|---|---|---|---|---|"]
        for f in sec[:max_items]:
            refs = ", ".join(r["rule_id"] for r in f.get("standard_refs", [])) or "—"
            conf = f" (+{len(f['confirmed_by'])} engine)" if f.get("confirmed_by") else ""
            md.append(
                f"| {SEV_ICON.get(f['severity'], '')} {f['severity']} | `{f['rule_id']}` {f.get('cwe', '')}{conf} | "
                f"{f['owasp_id']} | `{f['file_path']}:{f.get('line_number')}` | {f['title']} | {refs} |"
            )
        md.append("")
        md.append("<details><summary>Mitigations</summary>\n")
        for f in sec[:max_items]:
            md.append(f"- **`{f['file_path']}:{f.get('line_number')}` {f['title']}** — {f['mitigation']}")
        md.append("\n</details>\n")

    if lint:
        md += ["### 🧹 Code quality", "", "| Severity | Rule | Location | Issue | Suggestion |", "|---|---|---|---|---|"]
        for f in lint[:max_items]:
            md.append(f"| {f['severity']} | `{f['rule_id']}` | `{f['file_path']}:{f.get('line_number')}` | "
                      f"{f['issue']} | {f['suggestion']} |")
        md.append("")

    if tests:
        md += ["### 🧪 Generated unit tests", ""]
        for t in tests:
            md.append(f"<details><summary><code>{t['test_file_path']}</code> — {t.get('test_count', 0)} test(s) for "
                      f"<code>{t['target_file']}</code></summary>\n\n```python\n{t['test_code']}\n```\n</details>\n")

    if docs.get("summary_markdown"):
        md += ["### 📝 Documentation", "", docs["summary_markdown"]]
        doc_items = [d for f in docs.get("files", []) for d in f.get("docstrings", [])]
        if doc_items:
            md.append(f"<details><summary>{len(doc_items)} suggested docstring(s)</summary>\n")
            for d in doc_items[:max_items]:
                md.append(f"`{d['file_path']}:{d['line_number']}` **{d['symbol']}**\n```python\n{d['docstring']}\n```")
            md.append("</details>\n")

    timings = {k: v["duration_ms"] for k, v in metrics.items() if isinstance(v, dict) and "duration_ms" in v}
    if timings:
        md.append("<sub>Agent timings (ms): " + ", ".join(f"{k} {v}" for k, v in timings.items())
                  + f" · analysis wall-clock {metrics.get('analysis_wall_clock_ms', '?')} ms</sub>")
    return "\n".join(md)
