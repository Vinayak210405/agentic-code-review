from src.graph.workflow import create_code_review_graph
from src.graph.state import CodeReviewState

def run_workflow_demo():
    print("==================================================")
    print("  RUNNING AGENTIC CODE REVIEW WORKFLOW (LANGGRAPH) ")
    print("==================================================")

    app = create_code_review_graph()
    
    # Thread configuration for checkpoint persistence
    thread_config = {"configurable": {"thread_id": "PR_101_EXECUTION_THREAD"}}

    # Initial state payload
    initial_state: CodeReviewState = {
        "pr_id": 101,
        "repo_name": "enterprise/payment-service",
        "commit_sha": "9f8e7d6c",
        "author": "dev_alex",
        "files_changed": [
            {
                "filename": "controllers/payment_controller.py",
                "patch": (
                    "@@ -15,3 +15,5 @@\n"
                    "+ query = f\"SELECT * FROM cards WHERE number='{card_num}'\"\n"
                    "+ db.execute(query)\n"
                ),
                "status": "modified"
            }
        ],
        "security_findings": [],
        "lint_findings": [],
        "generated_tests": [],
        "status": "INITIALIZED",
        "human_approved": None,
        "human_feedback": None
    }

    # Step 1: Execute graph until it hits the interrupt gate
    print("\n[Phase 1] Launching Multi-Agent Pipeline...")
    for event in app.stream(initial_state, thread_config):
        for node_name, output in event.items():
            print(f"--> Completed Node: '{node_name}'")

    # Inspect paused graph state at thread checkpoint
    current_state = app.get_state(thread_config)
    print("\n--------------------------------------------------")
    print(f"Pipeline Paused at Node : {current_state.next}")
    print(f"Current State Status    : {current_state.values.get('status')}")
    print(f"Security Vulnerabilities: {len(current_state.values.get('security_findings', []))}")
    print("--------------------------------------------------")

    # Step 2: Simulate Human Reviewer Sign-Off (Approval Webhook)
    print("\n[Phase 2] Approving PR via Human Sign-Off Webhook...")
    app.update_state(
        thread_config,
        {"human_approved": True, "human_feedback": "Approved with mitigation note. Proceed with merge."}
    )

    # Step 3: Resume graph execution from saved checkpoint
    print("\n[Phase 3] Resuming Execution Post-Approval...")
    for event in app.stream(None, thread_config):
        for node_name, output in event.items():
            print(f"--> Completed Node: '{node_name}'")

    final_state = app.get_state(thread_config)
    print("\n==================================================")
    print(f"Workflow Finished Successfully! Final Status: {final_state.values.get('status')}")
    print("==================================================")

if __name__ == "__main__":
    run_workflow_demo()
