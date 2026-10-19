import os
import hmac
import hashlib
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from src.graph.workflow import create_code_review_graph

router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])

def verify_github_signature(payload_body: bytes, secret: str, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_hash = hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected_hash}", signature_header)

async def run_review_graph_background(initial_state: dict):
    try:
        graph = create_code_review_graph()
        thread_id = f"{initial_state['repo_name']}:{initial_state['pr_id']}"
        config = {"configurable": {"thread_id": thread_id}}
        graph.invoke(initial_state, config=config)
    except Exception as e:
        print(f"[Graph Execution Error] {e}")

@router.post("/github")
async def handle_github_webhook(request: Request, background_tasks: BackgroundTasks):
    body_bytes = await request.body()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    signature = request.headers.get("x-hub-signature-256")

    if secret and not verify_github_signature(body_bytes, secret, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook HMAC signature")

    event_type = request.headers.get("x-github-event", "ping")
    
    # Respond 200 OK to GitHub setup ping
    if event_type == "ping":
        return {"msg": "pong", "status": "active"}

    payload = await request.json()

    if event_type == "pull_request":
        action = payload.get("action")
        if action in ["opened", "synchronize", "reopened"]:
            pr = payload.get("pull_request", {})
            repo = payload.get("repository", {})

            initial_state = {
                "pr_id": pr.get("number"),
                "repo_name": repo.get("full_name"),
                "files_changed": [],
                "security_findings": [],
                "lint_findings": [],
                "generated_tests": [],
                "status": "PROCESSING",
                "human_approved": None,
                "human_feedback": None
            }

            background_tasks.add_task(run_review_graph_background, initial_state)
            return {"status": "ACCEPTED", "message": f"Review initiated for PR #{pr.get('number')}"}

    return {"status": "IGNORED", "message": f"Event '{event_type}' action '{payload.get('action')}' skipped."}
