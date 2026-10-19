from typing import Any, Dict, Literal
from langgraph.graph import END, START, StateGraph

from src.agents.linter_agent import linter_node
from src.agents.security_agent import security_auditor_node
from src.agents.test_generator_agent import test_generator_node
from src.graph.checkpoints import get_checkpointer
from src.graph.state import CodeReviewState
from src.services.github_publisher import publish_review_to_github
from src.services.slack_service import send_slack_hitl_notification


def human_review_node(state: CodeReviewState) -> Dict[str, Any]:
    print(f"\n[HITL Gate] Evaluating PR #{state['pr_id']} for human intervention...")
    
    if state.get("human_approved") is not None:
        approval_status = "APPROVED" if state["human_approved"] else "REJECTED"
        print(f"[HITL Gate] Human Decision Received: {approval_status}")
        return {
            "status": f"HUMAN_{approval_status}",
            "human_feedback": state.get("human_feedback", "Reviewed by engineer.")
        }
    
    critical_findings = [
        f for f in state.get("security_findings", []) 
        if f.get("severity") in ["CRITICAL", "HIGH"]
    ]
    
    if critical_findings:
        print(f"[HITL Gate] ⚠️ {len(critical_findings)} Critical/High vulnerabilities detected. Triggering Slack notification.")
        thread_id = f"{state.get('repo_name')}:{state.get('pr_id')}"
        send_slack_hitl_notification(thread_id, state["pr_id"], state["repo_name"], critical_findings)
        return {"status": "AWAITING_HUMAN_APPROVAL"}
    
    print("[HITL Gate] ✅ Clean review or non-blocking findings. Auto-approving.")
    return {"status": "AUTO_APPROVED", "human_approved": True}


def github_publisher_node(state: CodeReviewState) -> Dict[str, Any]:
    print(f"\n[Action Layer] Publishing results to GitHub PR #{state['pr_id']}...")
    
    publish_review_to_github(
        pr_id=state["pr_id"],
        repo_name=state["repo_name"],
        security_findings=state.get("security_findings", []),
        lint_findings=state.get("lint_findings", []),
        generated_tests=state.get("generated_tests", []),
        status=state.get("status", "COMPLETED")
    )
    
    return {"status": "COMPLETED"}


def route_after_human_review(state: CodeReviewState) -> Literal["github_publisher_node", "human_review_node"]:
    if state.get("status") == "AWAITING_HUMAN_APPROVAL" and state.get("human_approved") is None:
        return "human_review_node"
    return "github_publisher_node"


def create_code_review_graph():
    builder = StateGraph(CodeReviewState)

    builder.add_node("security_auditor", security_auditor_node)
    builder.add_node("linter", linter_node)
    builder.add_node("test_generator", test_generator_node)
    builder.add_node("human_review", human_review_node)
    builder.add_node("github_publisher", github_publisher_node)

    builder.add_edge(START, "security_auditor")
    builder.add_edge("security_auditor", "linter")
    builder.add_edge("linter", "test_generator")
    builder.add_edge("test_generator", "human_review")

    builder.add_conditional_edges(
        "human_review",
        route_after_human_review,
        {
            "human_review_node": "human_review",
            "github_publisher_node": "github_publisher"
        }
    )
    
    builder.add_edge("github_publisher", END)

    checkpointer = get_checkpointer()
    graph = builder.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_review"]
    )
    
    return graph
