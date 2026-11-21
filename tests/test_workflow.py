import sqlite3
import time

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from src.agents.base import CACHE_STATS
from src.graph.runner import get_review, resume_review, run_review
from src.graph.state import initial_state
from src.graph.workflow import AGENTS, build_graph, create_code_review_graph
from tests.conftest import CLEAN_PATCH, SQLI_PATCH


def _files(patch, name="svc/pay.py"):
    return [{"filename": name, "status": "modified", "patch": patch}]


def test_graph_fans_out_to_all_agents_and_fans_in():
    g = build_graph("parallel").compile().get_graph()
    edges = {(e.source, e.target) for e in g.edges}
    for agent in AGENTS:
        assert ("ingest", agent) in edges and (agent, "aggregate") in edges
    assert ("aggregate", "human_review") in edges and ("aggregate", "publish") in edges


def test_sequential_mode_chains_agents():
    edges = {(e.source, e.target) for e in build_graph("sequential").compile().get_graph().edges}
    assert ("security_auditor", "linter") in edges and ("ingest", "linter") not in edges


def test_clean_pr_is_auto_approved_without_human():
    review = run_review(initial_state(repo_name="acme/api", pr_id=1, files=_files(CLEAN_PATCH, "utils/m.py")))
    assert review["status"] == "COMPLETED" and review["decision"] == "PASS"
    assert not review["awaiting_human"]
    v = review["values"]
    assert v["generated_tests"] and "Agentic Code Review Report" in v["report_markdown"]
    assert {"security_auditor", "linter", "test_generator", "documentation"} <= set(v["metrics"])


def test_critical_finding_pauses_at_hitl_gate_with_payload():
    review = run_review(initial_state(repo_name="acme/api", pr_id=2, files=_files(SQLI_PATCH)))
    assert review["awaiting_human"] and review["next_nodes"] == ["human_review"]
    assert review["status"] == "AWAITING_HUMAN_APPROVAL"
    payload = review["pending_interrupt"]
    assert payload["blocking_findings"][0]["rule_id"] == "SQLI-001"
    assert not review["values"].get("report_markdown")  # nothing published while paused


def test_human_approval_resumes_and_completes():
    review = run_review(initial_state(repo_name="acme/api", pr_id=3, files=_files(SQLI_PATCH)))
    done = resume_review(review["thread_id"], approved=True, feedback="Accepted: internal tool", reviewer="alice")
    assert done["status"] == "COMPLETED" and done["decision"] == "APPROVED_BY_HUMAN"
    assert done["values"]["reviewer"] == "alice" and "@alice" in done["values"]["report_markdown"]


def test_human_rejection_requests_changes():
    review = run_review(initial_state(repo_name="acme/api", pr_id=4, files=_files(SQLI_PATCH)))
    done = resume_review(review["thread_id"], approved=False, feedback="Parameterise the query")
    assert done["status"] == "CHANGES_REQUESTED" and done["decision"] == "REJECTED_BY_HUMAN"


def test_cannot_resume_a_review_that_is_not_paused():
    review = run_review(initial_state(repo_name="acme/api", pr_id=5, files=_files(CLEAN_PATCH, "u.py")))
    with pytest.raises(ValueError):
        resume_review(review["thread_id"], approved=True)
    with pytest.raises(KeyError):
        resume_review("does-not-exist", approved=True)


def test_hitl_state_survives_process_restart_with_sqlite(tmp_path):
    db = tmp_path / "ckpt.sqlite"
    graph_a = create_code_review_graph("parallel", SqliteSaver(sqlite3.connect(db, check_same_thread=False)))
    cfg = {"configurable": {"thread_id": "durable-1"}}
    graph_a.invoke(initial_state(repo_name="acme/api", pr_id=6, files=_files(SQLI_PATCH)), cfg)
    # A brand-new graph + connection (simulating a restarted server) sees the paused review.
    from langgraph.types import Command

    graph_b = create_code_review_graph("parallel", SqliteSaver(sqlite3.connect(db, check_same_thread=False)))
    assert graph_b.get_state(cfg).next == ("human_review",)
    graph_b.invoke(Command(resume={"approved": True, "reviewer": "bob"}), cfg)
    assert graph_b.get_state(cfg).values["status"] == "COMPLETED"


def test_parallel_execution_is_faster_than_sequential(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "simulated")
    monkeypatch.setenv("SIMULATED_LLM_LATENCY_S", "0.25")
    monkeypatch.setenv("LLM_MAX_CONCURRENCY", "8")
    monkeypatch.setenv("ENABLE_RESULT_CACHE", "false")
    monkeypatch.setenv("HITL_BLOCK_SEVERITIES", "NONE")
    files = _files(CLEAN_PATCH, "utils/m.py")

    def timed(mode, tid):
        t = time.perf_counter()
        assert run_review(initial_state(repo_name="r/r", pr_id=7, files=files), thread_id=tid, mode=mode)["status"] == "COMPLETED"
        return time.perf_counter() - t

    seq = timed("sequential", "seq")
    par = timed("parallel", "par")
    # 3 per-file LLM calls + 1 summary: sequential ~1.0s, parallel ~0.5s.
    assert par < seq * 0.7, (seq, par)


def test_unchanged_files_are_served_from_cache_on_rereview():
    files = _files(CLEAN_PATCH, "utils/m.py")
    run_review(initial_state(repo_name="r/r", pr_id=8, files=files, commit_sha="aaa"))
    hits_before = CACHE_STATS["hits"]
    run_review(initial_state(repo_name="r/r", pr_id=8, files=files, commit_sha="bbb"))
    assert CACHE_STATS["hits"] - hits_before == 4  # one per agent


def test_get_review_unknown_thread_returns_none():
    assert get_review("nope") is None
