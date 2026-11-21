"""Linter & Quality agent: AST lint rules mapped to institutional standards,
optionally extended with LLM review grounded by RAG."""
from __future__ import annotations

from typing import Any, Dict, List

from src.agents.base import run_per_file
from src.agents.llm import LLMLintReview, llm_enabled, numbered_diff, structured_call
from src.analysis.diff_parser import build_analysis_unit
from src.analysis.lint_rules import analyze_quality
from src.rag.vector_store import retrieve_standards

SYSTEM_PROMPT = (
    "You are a senior engineer reviewing code quality (readability, performance, error handling, "
    "maintainability). Only comment on added lines ('+'), use the shown line numbers, do not repeat issues "
    "already listed, and do not report security issues. Return an empty list if nothing new."
)


def review_file(file: Dict[str, Any]) -> List[Dict[str, Any]]:
    unit = build_analysis_unit(file["filename"], file.get("patch", ""), file.get("content"))
    findings = analyze_quality(unit)
    if llm_enabled() and file.get("patch"):
        standards = "\n".join(h["text"] for h in retrieve_standards("python coding standards " + file["patch"][:800], 5))
        known = "\n".join(f"- line {f['line_number']}: {f['issue']}" for f in findings) or "(none)"
        review = structured_call(
            LLMLintReview, SYSTEM_PROMPT,
            f"Coding standards:\n{standards}\n\nAlready reported:\n{known}\n\n"
            f"File: {file['filename']}\n```diff\n{numbered_diff(file['patch'])}\n```",
        )
        if review is not None:
            for item in review.findings:
                if item.line_number in unit.changed_lines:
                    findings.append({
                        "rule_id": "LLM-QUALITY", "file_path": file["filename"], "line_number": item.line_number,
                        "severity": item.severity if item.severity in {"error", "warning", "info"} else "warning",
                        "issue": item.issue, "suggestion": item.suggestion, "standard_refs": [], "source": "llm",
                    })
    return findings


def linter_node(state: Dict[str, Any]) -> Dict[str, Any]:
    results, metrics = run_per_file("linter", state.get("files_changed", []), review_file)
    return {"lint_findings": [f for per_file in results for f in per_file], "metrics": metrics}
