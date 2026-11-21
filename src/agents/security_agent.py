"""Security Auditor agent: SAST (native OWASP rules + Bandit + SCA) grounded
with RAG-retrieved institutional standards, optionally extended by an LLM."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from config.settings import get_settings
from src.agents.base import run_per_file
from src.agents.llm import LLMSecurityReview, llm_enabled, numbered_diff, structured_call
from src.analysis.diff_parser import build_analysis_unit
from src.analysis.findings import OWASP_TOP_10, SEVERITY_ORDER, dedupe_findings, make_finding
from src.analysis.security_engine import analyze_unit
from src.rag.vector_store import retrieve_standards

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are an application security auditor. Review ONLY the added lines (marked '+') of the diff. "
    "Report vulnerabilities mapped to the OWASP Top 10 (2021) that the static findings below do not already "
    "cover, especially business-logic and access-control flaws. Use the line numbers shown in the diff. "
    "Cite the institutional rule ids from the provided standards in the mitigation. "
    "Return an empty list if there is nothing new. Do not speculate."
)


def attach_standards(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Ground a finding in institutional standards via vector retrieval."""
    query = f"{finding.get('title', '')}. {finding.get('description', '')}"
    hits = [h for h in retrieve_standards(query, 2) if h["score"] > 0.05]
    finding["standard_refs"] = [{"rule_id": h["rule_id"], "text": h["text"].split("\n", 1)[-1], "score": h["score"]}
                                for h in hits]
    return finding


def _llm_findings(file: Dict[str, Any], static: List[Dict[str, Any]], changed: set) -> List[Dict[str, Any]]:
    patch = file.get("patch", "")
    if not patch:
        return []
    context = "\n".join(h["text"] for h in retrieve_standards(patch[:1500], 5))
    known = "\n".join(f"- line {f['line_number']}: {f['rule_id']} {f['title']}" for f in static) or "(none)"
    review = structured_call(
        LLMSecurityReview, SYSTEM_PROMPT,
        f"Institutional standards:\n{context}\n\nStatic findings already reported:\n{known}\n\n"
        f"File: {file['filename']}\n```diff\n{numbered_diff(patch)}\n```",
    )
    if review is None:
        return []
    out = []
    for item in review.findings:
        owasp = item.owasp_id.strip().upper()[:3]
        severity = item.severity.strip().upper()
        # Hallucination guards: must reference a real added line and a valid category.
        if owasp not in OWASP_TOP_10 or severity not in SEVERITY_ORDER or item.line_number not in changed:
            continue
        out.append(make_finding(
            rule_id=f"LLM-{owasp}", owasp=owasp, cwe=item.cwe or "CWE-unknown", severity=severity,
            title=item.title, description=item.description, mitigation=item.mitigation,
            file_path=file["filename"], line_number=item.line_number, source="llm", confidence="MEDIUM",
        ))
    return out


def review_file(file: Dict[str, Any]) -> List[Dict[str, Any]]:
    settings = get_settings()
    unit = build_analysis_unit(file["filename"], file.get("patch", ""), file.get("content"))
    findings = analyze_unit(unit, enable_bandit=settings.enable_bandit)
    if llm_enabled():
        findings = dedupe_findings(findings + _llm_findings(file, findings, unit.changed_lines))
    return [attach_standards(f) for f in findings]


def security_auditor_node(state: Dict[str, Any]) -> Dict[str, Any]:
    results, metrics = run_per_file("security_auditor", state.get("files_changed", []), review_file)
    findings = dedupe_findings(f for per_file in results for f in per_file)
    return {"security_findings": findings, "metrics": metrics}
