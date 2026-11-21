from unittest.mock import MagicMock, patch

from src.agents import security_agent
from src.agents.llm import LLMSecurityFinding, LLMSecurityReview
from src.services.github_publisher import (commit_status_for, inline_comments, publish_review_to_github,
                                           review_event_for)
from src.services.slack_service import build_blocks
from tests.conftest import SQLI_PATCH


def _finding(**kw):
    base = {"severity": "CRITICAL", "file_path": "pay.py", "line_number": 16, "title": "SQLi", "owasp_category": "A03",
            "cwe": "CWE-89", "description": "d", "mitigation": "m", "standard_refs": [{"rule_id": "SEC-09"}],
            "rule_id": "SQLI-001"}
    return {**base, **kw}


def test_inline_comments_target_changed_lines():
    comments = inline_comments({"security_findings": [_finding(), _finding(severity="LOW", line_number=3)]})
    assert len(comments) == 1 and comments[0]["line"] == 16 and comments[0]["side"] == "RIGHT"
    assert "SEC-09" in comments[0]["body"]


def test_status_and_event_mapping():
    assert commit_status_for("PASS") == "success"
    assert commit_status_for("NEEDS_HUMAN_REVIEW") == "pending"
    assert commit_status_for("REJECTED_BY_HUMAN") == "failure"
    assert review_event_for("REJECTED_BY_HUMAN") == "REQUEST_CHANGES"


def test_publish_dry_run_without_token():
    assert publish_review_to_github({"repo_name": "a/b", "pr_id": 1}, "report") is False


def test_publish_posts_review_and_commit_status(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    gh = MagicMock()
    with patch("github.Github", return_value=gh):
        ok = publish_review_to_github({"repo_name": "a/b", "pr_id": 9, "commit_sha": "deadbeef",
                                       "decision": "REJECTED_BY_HUMAN", "security_findings": [_finding()],
                                       "risk": {"level": "CRITICAL", "blocking_count": 1}}, "report")
    assert ok
    pr = gh.get_repo.return_value.get_pull.return_value
    kwargs = pr.create_review.call_args.kwargs
    assert kwargs["event"] == "REQUEST_CHANGES" and kwargs["comments"][0]["line"] == 16
    gh.get_repo.return_value.get_commit.return_value.create_status.assert_called_once()
    assert gh.get_repo.return_value.get_commit.return_value.create_status.call_args.kwargs["state"] == "failure"


def test_slack_blocks_include_decision_endpoint():
    blocks = build_blocks("t-1", 5, "a/b", [_finding()])
    assert "/api/v1/reviews/t-1/decision" in blocks[-1]["elements"][0]["text"]


def test_llm_findings_are_validated_against_changed_lines(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    fake = LLMSecurityReview(findings=[
        LLMSecurityFinding(owasp_id="A01", cwe="CWE-639", severity="HIGH", line_number=17, title="IDOR",
                           description="card looked up without ownership check", mitigation="check owner (SEC-02)"),
        LLMSecurityFinding(owasp_id="A01", cwe="CWE-639", severity="HIGH", line_number=999, title="hallucinated",
                           description="x", mitigation="y"),
        LLMSecurityFinding(owasp_id="Z99", cwe="CWE-1", severity="HIGH", line_number=16, title="bad category",
                           description="x", mitigation="y"),
    ])
    monkeypatch.setattr(security_agent, "structured_call", lambda *a, **k: fake)
    findings = security_agent.review_file({"filename": "pay.py", "patch": SQLI_PATCH})
    llm = [f for f in findings if f["source"] == "llm"]
    assert [f["title"] for f in llm] == ["IDOR"]
    assert any(f["rule_id"] == "SQLI-001" for f in findings)  # static results still present


def test_llm_failure_falls_back_to_static(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setattr(security_agent, "structured_call", lambda *a, **k: None)
    assert any(f["rule_id"] == "SQLI-001" for f in security_agent.review_file({"filename": "p.py", "patch": SQLI_PATCH}))
