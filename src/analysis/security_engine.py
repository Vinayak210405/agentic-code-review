"""Entry point for deterministic security analysis of one changed file."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.analysis.bandit_runner import run_bandit
from src.analysis.diff_parser import AnalysisUnit, build_analysis_unit
from src.analysis.findings import dedupe_findings
from src.analysis.pattern_rules import analyze_patterns, analyze_requirements
from src.analysis.python_rules import analyze_python


def analyze_unit(unit: AnalysisUnit, enable_bandit: bool = True) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if unit.language == "requirements":
        findings += analyze_requirements(unit)
    if unit.language == "python":
        findings += analyze_python(unit)
        if enable_bandit:
            findings += run_bandit(unit)
    findings += analyze_patterns(unit, python_ast_ok=unit.tree is not None)
    return dedupe_findings(findings)


def analyze_file(
    filename: str,
    patch: str = "",
    content: Optional[str] = None,
    enable_bandit: bool = True,
) -> List[Dict[str, Any]]:
    unit = build_analysis_unit(filename, patch, content)
    return analyze_unit(unit, enable_bandit=enable_bandit)


def analyze_source(filename: str, source: str, enable_bandit: bool = True) -> List[Dict[str, Any]]:
    """Analyse a whole file as if every line were newly added."""
    return analyze_file(filename, content=source, enable_bandit=enable_bandit)
