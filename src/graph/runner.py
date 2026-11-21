"""High-level API around the compiled graph: start, inspect and resume reviews."""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, Optional

from langgraph.types import Command

from config.settings import get_settings
from src.graph.state import CodeReviewState
from src.graph.workflow import create_code_review_graph

_graphs: Dict[str, Any] = {}
_lock = threading.Lock()


def get_graph(mode: Optional[str] = None):
    mode = (mode or get_settings().execution_mode).lower()
    with _lock:
        if mode not in _graphs:
            _graphs[mode] = create_code_review_graph(mode)
        return _graphs[mode]


def reset_graphs() -> None:
    with _lock:
        _graphs.clear()


def make_thread_id(repo_name: str, pr_id: int, commit_sha: str = "") -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]", "__", repo_name)
    sha = re.sub(r"[^A-Za-z0-9]", "", commit_sha or "")[:12]
    return f"{slug}-pr{pr_id}" + (f"-{sha}" if sha else "")


def _config(thread_id: str) -> Dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}}


def run_review(state: CodeReviewState, thread_id: Optional[str] = None, mode: Optional[str] = None) -> Dict[str, Any]:
    thread_id = thread_id or state.get("thread_id") or make_thread_id(
        state.get("repo_name", "local"), state.get("pr_id", 0), state.get("commit_sha", ""))
    state = {**state, "thread_id": thread_id}
    get_graph(mode).invoke(state, _config(thread_id))
    return get_review(thread_id, mode)


def resume_review(thread_id: str, approved: bool, feedback: str = "", reviewer: str = "api",
                  mode: Optional[str] = None) -> Dict[str, Any]:
    review = get_review(thread_id, mode)
    if review is None:
        raise KeyError(thread_id)
    if not review["awaiting_human"]:
        raise ValueError(f"Thread '{thread_id}' is not awaiting a human decision (status={review['status']}).")
    get_graph(mode).invoke(
        Command(resume={"approved": approved, "feedback": feedback, "reviewer": reviewer}), _config(thread_id)
    )
    return get_review(thread_id, mode)


def get_review(thread_id: str, mode: Optional[str] = None) -> Optional[Dict[str, Any]]:
    snapshot = get_graph(mode).get_state(_config(thread_id))
    if not snapshot or not snapshot.values:
        return None
    interrupts = [i.value for t in snapshot.tasks for i in getattr(t, "interrupts", ())]
    values = dict(snapshot.values)
    return {
        "thread_id": thread_id,
        "status": values.get("status"),
        "decision": values.get("decision"),
        "awaiting_human": bool(interrupts),
        "pending_interrupt": interrupts[0] if interrupts else None,
        "next_nodes": list(snapshot.next),
        "values": values,
    }
