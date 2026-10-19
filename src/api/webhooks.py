from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status
from pydantic import BaseModel
from typing import Optional

from src.graph.workflow import create_code_review_graph
from src.services.github_service import parse_github_pr_payload, verify_github_signature

router = APIRouter(prefix="/api/v1", tags=["Webhooks & Reviews"])
graph_app = create_code_review_graph()


class HumanApprovalRequest(BaseModel):
    thread_id: str
    approved: bool
    feedback: Optional[str] = "Approved via API Endpoint"


def run_pipeline_task(initial_state: dict, thread_config: dict):
    """Background task function to stream state graph execution without blocking HTTP responses."""
    print(f"\n[Async Pipeline] Starting review thread: {thread_config['configurable']['thread_id']}")
    for event in graph_app.stream(initial_state, thread_config):
        for node_name, output in event.items():
            print(f"[Async Pipeline] Completed Node: '{node_name}'")


@router.post("/webhooks/github")
async def github_webhook_listener(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None)
):
    """Receives incoming GitHub pull request webhooks and triggers the LangGraph review pipeline."""
    body_bytes = await request.body()

    # Step 1: Verify HMAC Security Header
    if not verify_github_signature(body_bytes, x_hub_signature_256 or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HMAC signature."
        )

    payload = await request.json()
    action = payload.get("action", "")

    # Process pull request events ('opened', 'synchronize', or test trigger)
    if action in ["opened", "synchronize", "reopened", "test"]:
        state_payload = parse_github_pr_payload(payload)
        thread_id = f"{state_payload['repo_name']}:{state_payload['pr_id']}"
        thread_config = {"configurable": {"thread_id": thread_id}}

        # Run pipeline asynchronously in background
        background_tasks.add_task(run_pipeline_task, state_payload, thread_config)

        return {
            "status": "ACCEPTED",
            "message": f"Code review pipeline initiated for PR #{state_payload['pr_id']}",
            "thread_id": thread_id
        }

    return {"status": "IGNORED", "message": f"Ignored action '{action}'"}


@router.post("/review/approve")
async def approve_code_review(approval: HumanApprovalRequest, background_tasks: BackgroundTasks):
    """Resumes a paused review thread post-human intervention."""
    thread_config = {"configurable": {"thread_id": approval.thread_id}}

    # Verify existing checkpoint thread
    current_state = graph_app.get_state(thread_config)
    if not current_state.values:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Thread '{approval.thread_id}' not found."
        )

    # Step 1: Update graph state with human approval decision
    graph_app.update_state(
        thread_config,
        {
            "human_approved": approval.approved,
            "human_feedback": approval.feedback
        }
    )

    # Step 2: Resume graph execution in background
    background_tasks.add_task(run_pipeline_task, None, thread_config)

    return {
        "status": "RESUMED",
        "message": f"Review thread '{approval.thread_id}' updated and resumed.",
        "decision": "APPROVED" if approval.approved else "REJECTED"
    }
