"""Shared finding model and OWASP Top 10 (2021) taxonomy."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

OWASP_TOP_10: Dict[str, str] = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def make_finding(
    *,
    rule_id: str,
    owasp: str,
    cwe: str,
    severity: str,
    title: str,
    description: str,
    mitigation: str,
    file_path: str,
    line_number: Optional[int],
    snippet: str = "",
    source: str = "sast",
    confidence: str = "HIGH",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "owasp_category": OWASP_TOP_10[owasp],
        "owasp_id": owasp,
        "cwe": cwe,
        "severity": severity,
        "title": title,
        "description": description,
        "mitigation": mitigation,
        "file_path": file_path,
        "line_number": line_number,
        "snippet": snippet.strip()[:200],
        "source": source,
        "confidence": confidence,
        "confirmed_by": [],
        "standard_refs": [],
    }


def dedupe_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings that describe the same issue (same file, line, OWASP category).

    The higher-severity / native finding wins and records which other engines
    agreed with it in ``confirmed_by``.
    """
    merged: Dict[tuple, Dict[str, Any]] = {}
    for f in findings:
        key = (f["file_path"], f.get("line_number"), f.get("owasp_id"))
        if key not in merged:
            merged[key] = dict(f)
            merged[key]["confirmed_by"] = list(f.get("confirmed_by", []))
            continue
        existing = merged[key]
        keep, other = existing, f
        if SEVERITY_ORDER.get(f["severity"], 0) > SEVERITY_ORDER.get(existing["severity"], 0):
            keep, other = dict(f), existing
            keep["confirmed_by"] = list(existing.get("confirmed_by", []))
        tag = other.get("source", "sast") + ":" + other.get("rule_id", "")
        if tag not in keep["confirmed_by"]:
            keep["confirmed_by"].append(tag)
        merged[key] = keep
    return sorted(
        merged.values(),
        key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), x["file_path"], x.get("line_number") or 0),
    )
