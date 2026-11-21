from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FileChange(BaseModel):
    filename: str
    patch: str = ""
    content: Optional[str] = Field(default=None, description="Full post-change file content (optional)")
    status: str = "modified"


class ReviewRequest(BaseModel):
    repo_name: str = "local/repo"
    pr_id: int = 0
    commit_sha: str = "local"
    author: str = "api"
    title: str = ""
    files: List[FileChange] = Field(min_length=1)
    wait: bool = Field(default=True, description="Run synchronously and return the result")


class DecisionRequest(BaseModel):
    approved: bool
    feedback: str = ""
    reviewer: str = "api"


class LegacyApprovalRequest(BaseModel):
    thread_id: str
    approved: bool
    feedback: Optional[str] = "Approved via API endpoint"


class AnalyzeRequest(BaseModel):
    filename: str
    patch: str = ""
    content: Optional[str] = None


class ReviewSummary(BaseModel):
    thread_id: str
    status: Optional[str]
    decision: Optional[str]
    awaiting_human: bool
    pending_interrupt: Optional[Dict[str, Any]] = None
    risk: Dict[str, Any] = {}
    security_findings: List[Dict[str, Any]] = []
    lint_findings: List[Dict[str, Any]] = []
    generated_tests: List[Dict[str, Any]] = []
    documentation: Dict[str, Any] = {}
    metrics: Dict[str, Any] = {}
    published: bool = False
