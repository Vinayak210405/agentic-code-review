"""HTTP API: GitHub webhook ingestion, review submission, HITL decisions, RAG search."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from src.analysis.security_engine import analyze_file
from src.api.schemas import (AnalyzeRequest, DecisionRequest, LegacyApprovalRequest, ReviewRequest,
                             ReviewSummary)
from src.api.security import require_api_key
from src.graph.runner import get_review, make_thread_id, resume_review, run_review
from src.graph.state import initial_state
from src.rag.vector_store import retrieve_standards
from src.services.github_service import fetch_pr_files, parse_github_pr_payload, verify_github_signature

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Code Review"])
PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


def summarize(review: Dict[str, Any]) -> ReviewSummary:
    v = review["values"]
    return ReviewSummary(
        thread_id=review["thread_id"], status=review["status"], decision=review["decision"],
        awaiting_human=review["awaiting_human"], pending_interrupt=review["pending_interrupt"],
        risk=v.get("risk", {}), security_findings=v.get("security_findings", []),
        lint_findings=v.get("lint_findings", []), generated_tests=v.get("generated_tests", []),
        documentation=v.get("documentation", {}), metrics=v.get("metrics", {}), published=v.get("published", False),
    )


def _run_in_background(state: Dict[str, Any], thread_id: str) -> None:
    try:
        run_review(state, thread_id)
    except Exception:  # background task: log, never crash the worker
        logger.exception("Review pipeline failed for %s", thread_id)


@router.post("/webhooks/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_event: Optional[str] = Header(default="pull_request"),
) -> Dict[str, Any]:
    """Receive GitHub `pull_request` webhooks (HMAC-verified) and start a review."""
    body = await request.body()
    if not verify_github_signature(body, x_hub_signature_256 or ""):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid webhook signature.")
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Body is not valid JSON.")
    if x_github_event == "ping":
        return {"status": "PONG"}
    action = payload.get("action", "")
    if x_github_event != "pull_request" or action not in PR_ACTIONS:
        return {"status": "IGNORED", "message": f"Ignored event '{x_github_event}' action '{action}'"}

    meta = parse_github_pr_payload(payload)
    files = meta["files"] or fetch_pr_files(meta["repo_name"], meta["pr_id"], meta["commit_sha"])
    if not files:
        raise HTTPException(422,
                            "No changed files: configure GITHUB_TOKEN so the diff can be fetched.")
    thread_id = make_thread_id(meta["repo_name"], meta["pr_id"], meta["commit_sha"])
    state = initial_state(repo_name=meta["repo_name"], pr_id=meta["pr_id"], files=files,
                          commit_sha=meta["commit_sha"], author=meta["author"], title=meta["title"],
                          thread_id=thread_id)
    background_tasks.add_task(_run_in_background, state, thread_id)
    return {"status": "ACCEPTED", "thread_id": thread_id, "files": len(files),
            "message": f"Review started for {meta['repo_name']}#{meta['pr_id']}"}


@router.post("/reviews", response_model=ReviewSummary, responses={202: {"description": "Accepted (wait=false)"}})
def submit_review(req: ReviewRequest, background_tasks: BackgroundTasks,
                  _auth: str = Depends(require_api_key)) -> Any:
    """Submit a diff directly (CI, CLI, Swagger UI). With `wait=true` returns the full result."""
    thread_id = make_thread_id(req.repo_name, req.pr_id, req.commit_sha)
    state = initial_state(repo_name=req.repo_name, pr_id=req.pr_id, commit_sha=req.commit_sha, author=req.author,
                          title=req.title, files=[f.model_dump() for f in req.files], thread_id=thread_id)
    if not req.wait:
        background_tasks.add_task(_run_in_background, state, thread_id)
        return JSONResponse({"status": "ACCEPTED", "thread_id": thread_id}, status_code=202)
    return summarize(run_review(state, thread_id))


@router.get("/reviews/{thread_id}", response_model=ReviewSummary)
def read_review(thread_id: str, _auth: str = Depends(require_api_key)) -> ReviewSummary:
    review = get_review(thread_id)
    if review is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Review '{thread_id}' not found.")
    return summarize(review)


@router.get("/reviews/{thread_id}/report", response_class=PlainTextResponse)
def read_report(thread_id: str, _auth: str = Depends(require_api_key)) -> str:
    review = get_review(thread_id)
    if review is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Review '{thread_id}' not found.")
    if not review["values"].get("report_markdown"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Report not available yet (review in progress or awaiting human).")
    return review["values"]["report_markdown"]


def _decide(thread_id: str, approved: bool, feedback: str, reviewer: str) -> ReviewSummary:
    try:
        return summarize(resume_review(thread_id, approved, feedback, reviewer))
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Thread '{thread_id}' not found.")
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))


@router.post("/reviews/{thread_id}/decision", response_model=ReviewSummary)
def decide(thread_id: str, req: DecisionRequest, _auth: str = Depends(require_api_key)) -> ReviewSummary:
    """Human-in-the-loop: approve (accept risk) or reject a review paused at the security gate."""
    return _decide(thread_id, req.approved, req.feedback, req.reviewer)


@router.post("/review/approve", response_model=ReviewSummary, include_in_schema=False)
def legacy_approve(req: LegacyApprovalRequest, _auth: str = Depends(require_api_key)) -> ReviewSummary:
    return _decide(req.thread_id, req.approved, req.feedback or "", "api")


@router.post("/analyze/security")
def analyze_security(req: AnalyzeRequest, _auth: str = Depends(require_api_key)) -> Dict[str, Any]:
    """Run only the deterministic OWASP SAST engine on one file (no graph, no LLM)."""
    if not req.patch and req.content is None:
        raise HTTPException(422, "Provide `patch` or `content`.")
    findings = analyze_file(req.filename, req.patch, req.content)
    return {"filename": req.filename, "count": len(findings), "findings": findings}


@router.get("/standards/search")
def search_standards(q: str = Query(min_length=2), k: int = Query(default=3, ge=1, le=10),
                     _auth: str = Depends(require_api_key)) -> Dict[str, Any]:
    """Vector search over institutional coding & security standards (LlamaIndex)."""
    return {"query": q, "results": retrieve_standards(q, k)}
