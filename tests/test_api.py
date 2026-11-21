import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from main import app
from tests.conftest import CLEAN_PATCH, SQLI_PATCH


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _pr_payload(files, number=42, sha="abc123def"):
    return {"action": "opened", "number": number,
            "pull_request": {"number": number, "head": {"sha": sha}, "user": {"login": "dev"}, "title": "Add pay"},
            "repository": {"full_name": "acme/shop"}, "files": files}


def test_health(client):
    data = client.get("/health").json()
    assert data["status"] == "HEALTHY" and data["engine"].startswith("LangGraph")


def test_webhook_signed_request_starts_review(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    body = json.dumps(_pr_payload([{"filename": "pay.py", "patch": SQLI_PATCH, "status": "modified"}])).encode()
    sig = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    resp = client.post("/api/v1/webhooks/github", content=body,
                       headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "pull_request",
                                "Content-Type": "application/json"})
    assert resp.status_code == 202 and resp.json()["status"] == "ACCEPTED"
    thread_id = resp.json()["thread_id"]
    # TestClient runs background tasks before returning; the review is paused at the gate.
    review = client.get(f"/api/v1/reviews/{thread_id}").json()
    assert review["awaiting_human"] and review["risk"]["level"] == "CRITICAL"


def test_webhook_bad_signature_rejected(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "s3cret")
    resp = client.post("/api/v1/webhooks/github", json=_pr_payload([]), headers={"X-Hub-Signature-256": "sha256=bad"})
    assert resp.status_code == 401


def test_webhook_unsigned_rejected_in_production(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    resp = client.post("/api/v1/webhooks/github", json=_pr_payload([]))
    assert resp.status_code == 401


def test_webhook_without_files_or_token_is_422(client):
    resp = client.post("/api/v1/webhooks/github", json=_pr_payload([]), headers={"X-GitHub-Event": "pull_request"})
    assert resp.status_code == 422


def test_webhook_ignores_other_actions(client):
    payload = {**_pr_payload([]), "action": "closed"}
    assert client.post("/api/v1/webhooks/github", json=payload).json()["status"] == "IGNORED"


def test_submit_review_and_human_decision_flow(client):
    resp = client.post("/api/v1/reviews", json={"repo_name": "acme/shop", "pr_id": 7, "files": [
        {"filename": "pay.py", "patch": SQLI_PATCH}]})
    assert resp.status_code == 200
    review = resp.json()
    assert review["awaiting_human"] and review["security_findings"][0]["rule_id"] == "SQLI-001"
    tid = review["thread_id"]
    assert client.get(f"/api/v1/reviews/{tid}/report").status_code == 409

    decided = client.post(f"/api/v1/reviews/{tid}/decision", json={"approved": False, "feedback": "fix", "reviewer": "sec"})
    assert decided.status_code == 200 and decided.json()["decision"] == "REJECTED_BY_HUMAN"
    report = client.get(f"/api/v1/reviews/{tid}/report")
    assert report.status_code == 200 and "Changes requested" in report.text
    # Already decided -> conflict
    assert client.post(f"/api/v1/reviews/{tid}/decision", json={"approved": True}).status_code == 409


def test_clean_review_auto_passes(client):
    review = client.post("/api/v1/reviews", json={"files": [{"filename": "m.py", "patch": CLEAN_PATCH}]}).json()
    assert review["decision"] == "PASS" and review["status"] == "COMPLETED"


def test_decision_on_unknown_thread_404(client):
    assert client.post("/api/v1/reviews/missing/decision", json={"approved": True}).status_code == 404
    assert client.post("/api/v1/review/approve", json={"thread_id": "missing", "approved": True}).status_code == 404


def test_api_key_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("REVIEW_API_KEY", "k-123")
    body = {"files": [{"filename": "m.py", "patch": CLEAN_PATCH}]}
    assert client.post("/api/v1/reviews", json=body).status_code == 401
    assert client.post("/api/v1/reviews", json=body, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/v1/reviews", json=body, headers={"X-API-Key": "k-123"}).status_code == 200


def test_operator_endpoints_closed_in_production_without_key(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    assert client.get("/api/v1/standards/search?q=sql").status_code == 503


def test_standards_search_and_quick_scan(client):
    hits = client.get("/api/v1/standards/search", params={"q": "SQL injection", "k": 2}).json()["results"]
    assert hits[0]["rule_id"] == "SEC-09"
    scan = client.post("/api/v1/analyze/security", json={"filename": "x.py", "content": "import os\nos.system(cmd)\n"}).json()
    assert scan["findings"][0]["owasp_id"] == "A03"
