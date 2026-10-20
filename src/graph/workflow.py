from typing import Dict, Any, TypedDict, List, Optional
from langgraph.graph import StateGraph, END
from src.agents.security_agent import security_auditor_node
from src.agents.linter_agent import linter_node
from src.agents.test_generator_agent import test_generator_node
from src.services.github_fetcher import fetch_pr_files_node
from src.services.github_publisher import publish_review_to_github


class ReviewState(TypedDict):
    pr_id: int
    repo_name: str
    files_changed: List[Dict[str, Any]]
    security_findings: List[Any]
    lint_findings: List[Any]
    generated_tests: List[Any]
    status: str
    human_approved: Optional[bool]
    human_feedback: Optional[str]


def human_review_node(state: ReviewState) -> Dict[str, Any]:
    print("\n[HITL Gate] Evaluating PR #1 for human intervention...")
    security_findings = state.get("security_findings", [])

    has_critical = False
    for f in security_findings:
        if isinstance(f, dict):
            if f.get("severity") in ["CRITICAL", "HIGH"]:
                has_critical = True
                break
        elif isinstance(f, str):
            f_upper = f.upper()
            if (
                "SEVERITY: CRITICAL" in f_upper
                or "SEVERITY: HIGH" in f_upper
                or "**CRITICAL**" in f_upper
                or "**HIGH**" in f_upper
            ):
                has_critical = True
                break

    if has_critical:
        print("[HITL Gate] ⚠️ Critical or High security findings detected. Requiring human review.")
        return {"status": "AWAITING_HUMAN_REVIEW"}

    print("[HITL Gate] ✅ Clean review or non-blocking findings. Auto-approving.")
    return {"status": "APPROVED"}


def github_publisher_node(state: ReviewState) -> Dict[str, Any]:
    return publish_review_to_github(
        pr_id=state.get("pr_id"),
        repo_name=state.get("repo_name"),
        security_findings=state.get("security_findings"),
        lint_findings=state.get("lint_findings"),
        generated_tests=state.get("generated_tests"),
        status=state.get("status", "COMPLETED"),
    )


def create_code_review_graph():
    builder = StateGraph(ReviewState)

    builder.add_node("github_fetcher", fetch_pr_files_node)
    builder.add_node("security_auditor", security_auditor_node)
    builder.add_node("linter", linter_node)
    builder.add_node("test_generator", test_generator_node)
    builder.add_node("human_review", human_review_node)
    builder.add_node("github_publisher", github_publisher_node)

    builder.set_entry_point("github_fetcher")
    builder.add_edge("github_fetcher", "security_auditor")
    builder.add_edge("security_auditor", "linter")
    builder.add_edge("linter", "test_generator")
    builder.add_edge("test_generator", "human_review")
    builder.add_edge("human_review", "github_publisher")
    builder.add_edge("github_publisher", END)

    return builder.compile()