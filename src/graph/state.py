import operator
from typing import Annotated, Dict, List, Optional, TypedDict


class SecurityFinding(TypedDict):
    rule_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str
    file_path: str
    line_number: Optional[int]
    mitigation: str


class LintFinding(TypedDict):
    file_path: str
    line_number: Optional[int]
    issue: str
    suggestion: str


class GeneratedTest(TypedDict):
    target_file: str
    test_file_path: str
    test_code: str


class CodeReviewState(TypedDict):
    pr_id: int
    repo_name: str
    commit_sha: str
    author: str
    files_changed: List[Dict[str, str]]
    
    # Cumulative lists using operator.add reducer
    security_findings: Annotated[List[SecurityFinding], operator.add]
    lint_findings: Annotated[List[LintFinding], operator.add]
    generated_tests: Annotated[List[GeneratedTest], operator.add]
    
    status: str
    human_approved: Optional[bool]
    human_feedback: Optional[str]