import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "agentic-code-review-pipeline" in data["service"]

def test_github_webhook_ingestion():
    payload = {
        "action": "opened",
        "pull_request": {"number": 999, "user": {"login": "test_developer"}},
        "repository": {"full_name": "enterprise/test-repo"}
    }
    response = client.post("/api/v1/webhooks/github", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ACCEPTED"
    assert data["thread_id"] == "enterprise/test-repo:999"

def test_approve_nonexistent_thread_404():
    payload = {
        "thread_id": "nonexistent/repo:000",
        "approved": True,
        "feedback": "Test feedback"
    }
    response = client.post("/api/v1/review/approve", json=payload)
    assert response.status_code == 404
