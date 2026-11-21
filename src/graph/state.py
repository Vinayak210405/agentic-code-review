"""LangGraph state schema.

List fields use ``operator.add`` reducers and ``metrics`` uses a dict-merge
reducer so the four agents can run in parallel within one super-step and
write their results without conflicts.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict


def merge_dicts(left: Optional[Dict[str, Any]], right: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {**(left or {}), **(right or {})}


class SecurityFinding(TypedDict, total=False):
    rule_id: str
    owasp_category: str
    owasp_id: str
    cwe: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    mitigation: str
    file_path: str
    line_number: Optional[int]
    snippet: str
    source: str  # sast | bandit | pattern | sca | llm
    confidence: str
    confirmed_by: List[str]
    standard_refs: List[Dict[str, Any]]


class LintFinding(TypedDict, total=False):
    rule_id: str
    file_path: str
    line_number: Optional[int]
    severity: str  # error | warning | info
    issue: str
    suggestion: str
    standard_refs: List[str]
    source: str


class GeneratedTest(TypedDict, total=False):
    target_file: str
    test_file_path: str
    test_code: str
    functions_covered: List[str]
    test_count: int
    compiles: bool
    source: str


class CodeReviewState(TypedDict, total=False):
    thread_id: str
    pr_id: int
    repo_name: str
    commit_sha: str
    author: str
    title: str
    files_changed: List[Dict[str, Any]]

    security_findings: Annotated[List[SecurityFinding], operator.add]
    lint_findings: Annotated[List[LintFinding], operator.add]
    generated_tests: Annotated[List[GeneratedTest], operator.add]
    documentation: Dict[str, Any]
    metrics: Annotated[Dict[str, Any], merge_dicts]

    risk: Dict[str, Any]
    decision: str  # PASS | NEEDS_HUMAN_REVIEW | APPROVED_BY_HUMAN | REJECTED_BY_HUMAN
    status: str
    human_approved: Optional[bool]
    human_feedback: Optional[str]
    reviewer: Optional[str]
    report_markdown: str
    published: bool
    started_at: float


def initial_state(
    *, repo_name: str, pr_id: int, files: List[Dict[str, Any]], commit_sha: str = "local",
    author: str = "unknown", title: str = "", thread_id: str = "",
) -> CodeReviewState:
    return CodeReviewState(
        thread_id=thread_id, pr_id=pr_id, repo_name=repo_name, commit_sha=commit_sha, author=author,
        title=title, files_changed=files, security_findings=[], lint_findings=[], generated_tests=[],
        documentation={}, metrics={}, status="INITIALIZED", human_approved=None, human_feedback=None,
        reviewer=None,
    )
