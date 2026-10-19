from src.agents.security_agent import security_auditor_node
from src.agents.linter_agent import linter_node
from src.agents.test_generator_agent import test_generator_node
from src.graph.state import CodeReviewState

# Mock PR state with a SQL injection and N+1 query issue
mock_state: CodeReviewState = {
    "pr_id": 101,
    "repo_name": "enterprise/secure-api",
    "commit_sha": "a1b2c3d4",
    "author": "dev_alex",
    "files_changed": [
        {
            "filename": "auth/login.py",
            "patch": (
                "@@ -10,4 +10,6 @@\n"
                "+ query = f\"SELECT * FROM users WHERE user='{user}'\"\n"
                "+ db.execute(query)\n"
                "+ for role in roles:\n"
                "+     db.execute(f'SELECT * FROM permissions WHERE role={role}')\n"
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

if __name__ == "__main__":
    print("=== TESTING MULTI-AGENT NODES ===")
    
    sec_res = security_auditor_node(mock_state)
    mock_state["security_findings"].extend(sec_res["security_findings"])
    
    lint_res = linter_node(mock_state)
    mock_state["lint_findings"].extend(lint_res["lint_findings"])
    
    test_res = test_generator_node(mock_state)
    mock_state["generated_tests"].extend(test_res["generated_tests"])

    print("\n--- COMBINED MULTI-AGENT OUTPUTS ---")
    print(f"Security Findings Detected : {len(mock_state['security_findings'])}")
    print(f"Lint Warnings Detected     : {len(mock_state['lint_findings'])}")
    print(f"Unit Test Suites Created   : {len(mock_state['generated_tests'])}")
    
    if mock_state['security_findings']:
        print("\n[Security Finding Details]:", mock_state['security_findings'][0])
