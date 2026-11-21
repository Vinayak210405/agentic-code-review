"""Documentation agent: docstrings for undocumented public symbols, an
endpoint reference for new routes, and a PR change summary."""
from __future__ import annotations

from typing import Any, Dict

from src.agents.base import run_per_file
from src.agents.llm import LLMDocSummary, llm_enabled, structured_call
from src.analysis.diff_parser import build_analysis_unit
from src.analysis.doc_synth import document_unit, pr_summary_markdown


def document_file(file: Dict[str, Any]) -> Dict[str, Any]:
    unit = build_analysis_unit(file["filename"], file.get("patch", ""), file.get("content"))
    if unit.language != "python":
        return {"file_path": file["filename"], "symbols_changed": [], "docstrings": [], "endpoints": []}
    return document_unit(unit)


def documentation_node(state: Dict[str, Any]) -> Dict[str, Any]:
    files = state.get("files_changed", [])
    per_file, metrics = run_per_file("documentation", files, document_file)
    llm_summary = None
    if llm_enabled() and files:
        diff = "\n\n".join(f"### {f['filename']}\n{(f.get('patch') or '')[:2000]}" for f in files[:10])
        result = structured_call(
            LLMDocSummary,
            "Summarise this pull request for a changelog in 2-4 sentences: what changed and why it matters.",
            diff,
        )
        llm_summary = result.summary if result and result.summary else None
    return {
        "documentation": {
            "files": per_file,
            "summary_markdown": pr_summary_markdown(files, per_file, llm_summary),
            "docstrings_generated": sum(len(d["docstrings"]) for d in per_file),
            "endpoints": [e for d in per_file for e in d["endpoints"]],
        },
        "metrics": metrics,
    }
