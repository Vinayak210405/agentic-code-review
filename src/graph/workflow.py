"""LangGraph multi-agent review workflow.

                        ┌─► security_auditor ─┐
    START ─► ingest ────┼─► linter ───────────┼─► aggregate ─┬─► human_review ─► publish ─► END
                        ├─► test_generator ───┤              │   (interrupt)       ▲
                        └─► documentation ────┘              └─────────────────────┘ (no blocking findings)

``EXECUTION_MODE=sequential`` chains the agents one after another instead
(the baseline used by the latency benchmark).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Literal, Optional

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from config.settings import get_settings
from src.agents.base import reviewable
from src.agents.documentation_agent import documentation_node
from src.agents.linter_agent import linter_node
from src.agents.security_agent import security_auditor_node
from src.agents.test_generator_agent import test_generator_node
from src.analysis.findings import SEVERITY_ORDER
from src.graph.checkpoints import get_checkpointer
from src.graph.state import CodeReviewState
from src.services.github_publisher import publish_review_to_github
from src.services.report import build_report_markdown
from src.services.slack_service import send_slack_hitl_notification

logger = logging.getLogger(__name__)
AGENTS = ["security_auditor", "linter", "test_generator", "documentation"]
SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def ingest_node(state: CodeReviewState) -> Dict[str, Any]:
    files = state.get("files_changed", [])
    kept = [f for f in files if reviewable(f)]
    logger.info("[ingest] PR #%s: %d/%d files reviewable", state.get("pr_id"), len(kept), len(files))
    return {"files_changed": kept, "status": "IN_REVIEW", "started_at": time.time()}


def aggregate_node(state: CodeReviewState) -> Dict[str, Any]:
    settings = get_settings()
    sec = state.get("security_findings", [])
    lint = state.get("lint_findings", [])
    counts = {s: sum(1 for f in sec if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    owasp = sorted({f["owasp_category"] for f in sec})
    blocking = [f for f in sec if f["severity"] in settings.hitl_block_severities]
    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in sec) + sum(1 for f in lint if f.get("severity") == "error")
    risk = {
        "score": score,
        "level": "CRITICAL" if counts["CRITICAL"] else "HIGH" if counts["HIGH"] else
                 "MEDIUM" if counts["MEDIUM"] else "LOW" if counts["LOW"] else "NONE",
        "severity_counts": counts,
        "owasp_categories": owasp,
        "blocking_count": len(blocking),
        "lint_errors": sum(1 for f in lint if f.get("severity") == "error"),
        "tests_generated": sum(t.get("test_count", 0) for t in state.get("generated_tests", [])),
    }
    elapsed = round((time.time() - state.get("started_at", time.time())) * 1000, 2)
    decision = "NEEDS_HUMAN_REVIEW" if blocking else "PASS"
    if blocking:
        top = sorted(blocking, key=lambda f: -SEVERITY_ORDER[f["severity"]])
        send_slack_hitl_notification(state.get("thread_id", ""), state.get("pr_id", 0),
                                     state.get("repo_name", ""), top)
    logger.info("[aggregate] decision=%s risk=%s (%.0f ms)", decision, risk["level"], elapsed)
    return {
        "risk": risk,
        "decision": decision,
        "status": "AWAITING_HUMAN_APPROVAL" if blocking else "AUTO_APPROVED",
        "metrics": {"analysis_wall_clock_ms": elapsed},
    }


def route_after_aggregate(state: CodeReviewState) -> Literal["human_review", "publish"]:
    return "human_review" if state.get("decision") == "NEEDS_HUMAN_REVIEW" else "publish"


def human_review_node(state: CodeReviewState) -> Dict[str, Any]:
    """Pause the graph until a human approves or rejects (LangGraph ``interrupt``).

    The checkpoint is persisted, so the decision can arrive minutes or days
    later through the API, Slack or the CLI; the graph then resumes here.
    """
    blocking = [f for f in state.get("security_findings", [])
                if f["severity"] in get_settings().hitl_block_severities]
    decision = interrupt({
        "type": "security_approval",
        "thread_id": state.get("thread_id"),
        "repo_name": state.get("repo_name"),
        "pr_id": state.get("pr_id"),
        "risk": state.get("risk"),
        "blocking_findings": [
            {k: f.get(k) for k in ("rule_id", "severity", "owasp_category", "file_path", "line_number", "title")}
            for f in blocking
        ],
        "instructions": "Resume with {'approved': bool, 'feedback': str, 'reviewer': str}",
    })
    approved = bool(decision.get("approved")) if isinstance(decision, dict) else bool(decision)
    feedback = decision.get("feedback", "") if isinstance(decision, dict) else ""
    reviewer = decision.get("reviewer", "unknown") if isinstance(decision, dict) else "unknown"
    logger.info("[human_review] %s by %s", "APPROVED" if approved else "REJECTED", reviewer)
    return {
        "human_approved": approved,
        "human_feedback": feedback,
        "reviewer": reviewer,
        "decision": "APPROVED_BY_HUMAN" if approved else "REJECTED_BY_HUMAN",
        "status": "HUMAN_APPROVED" if approved else "HUMAN_REJECTED",
    }


def publish_node(state: CodeReviewState) -> Dict[str, Any]:
    report = build_report_markdown(state)
    published = publish_review_to_github(state, report)
    total_ms = round((time.time() - state.get("started_at", time.time())) * 1000, 2)
    return {
        "report_markdown": report,
        "published": published,
        "status": "COMPLETED" if state.get("decision") != "REJECTED_BY_HUMAN" else "CHANGES_REQUESTED",
        "metrics": {"total_wall_clock_ms": total_ms},
    }


NODE_FUNCS = {
    "security_auditor": security_auditor_node,
    "linter": linter_node,
    "test_generator": test_generator_node,
    "documentation": documentation_node,
}


def build_graph(mode: Optional[str] = None) -> StateGraph:
    mode = (mode or get_settings().execution_mode).lower()
    builder = StateGraph(CodeReviewState)
    builder.add_node("ingest", ingest_node)
    for name in AGENTS:
        builder.add_node(name, NODE_FUNCS[name])
    builder.add_node("aggregate", aggregate_node)
    builder.add_node("human_review", human_review_node)
    builder.add_node("publish", publish_node)

    builder.add_edge(START, "ingest")
    if mode == "sequential":
        chain = ["ingest", *AGENTS, "aggregate"]
        for a, b in zip(chain, chain[1:]):
            builder.add_edge(a, b)
    else:
        for name in AGENTS:  # fan-out: all four agents run in the same super-step
            builder.add_edge("ingest", name)
        builder.add_edge(AGENTS, "aggregate")  # fan-in: waits for every agent
    builder.add_conditional_edges("aggregate", route_after_aggregate, {"human_review": "human_review", "publish": "publish"})
    builder.add_edge("human_review", "publish")
    builder.add_edge("publish", END)
    return builder


def create_code_review_graph(mode: Optional[str] = None, checkpointer: Optional[BaseCheckpointSaver] = None):
    return build_graph(mode).compile(checkpointer=checkpointer or get_checkpointer())
