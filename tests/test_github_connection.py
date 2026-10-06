"""GitHub discovery and verified installation ownership regression tests."""
from unittest.mock import AsyncMock
import hashlib
import hmac
import json

from dashboard.api import orgs
from dashboard.db.models import Organization, Repository
from dashboard.db.session import SessionLocal
from tests.test_dashboard_audits import hosted


def test_discovery_requires_session_and_returns_only_metadata(hosted, monkeypatch):
    client, org_id, _ = hosted
    path = f"/api/v1/orgs/{org_id}/github-repos"
    assert client.get(path).status_code == 401
    client.get("/_test/login")
    mock = AsyncMock(return_value=[{"full_name": "owner/repo", "private": True,
        "default_branch": "main", "permissions": {"push": True}, "token": "never-return"}])
    monkeypatch.setattr(orgs, "_github_get", mock)
    response = client.get(path + "?page=2")
    assert response.status_code == 200
    assert response.json()["items"][0]["full_name"] == "owner/repo"
    assert "never-return" not in response.text
    assert "page=2" in mock.call_args.args[1]


def test_installation_owner_is_verified_before_binding(hosted, monkeypatch):
    client, org_id, _ = hosted
    client.get("/_test/login")
    mock = AsyncMock(return_value={"account": {"id": 999, "login": "other", "type": "User"}})
    monkeypatch.setattr(orgs, "installation_details", mock)
    path = f"/api/v1/orgs/{org_id}/github-installation"
    assert client.post(path, json={"installation_id": 42}).status_code == 403
    with SessionLocal() as db:
        assert db.get(Organization, org_id).github_installation_id is None
    mock.return_value = {"account": {"id": 123, "login": "owner", "type": "User"}}
    assert client.post(path, json={"installation_id": 42}).status_code == 200
    assert client.get(path).json()["installation_id"] == 42


def test_personal_webhook_requires_verified_installation(hosted, monkeypatch):
    """Personal workspace routing uses the stored installation, never the payload owner."""
    from dashboard.api import github_webhooks
    from tests.test_github_webhook import _payload
    client, org_id, _ = hosted
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "webhook-secret")
    payload = _payload()
    payload["repository"]["full_name"] = "owner/repo"
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": "pull_request", "X-Hub-Signature-256":
        "sha256=" + hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()}
    assert client.post("/api/v1/webhooks/github", content=body, headers=headers).status_code == 404
    with SessionLocal.begin() as db:
        db.get(Organization, org_id).github_installation_id = 42
    assert client.post("/api/v1/webhooks/github", content=body, headers=headers).json()["status"] == "ignored"
    with SessionLocal.begin() as db:
        db.add(Repository(org_id=org_id, github_repo_full_name="owner/repo"))
    monkeypatch.setattr(github_webhooks, "installation_token", lambda *args: "test-token")
    monkeypatch.setattr(github_webhooks, "pull_request_diff", lambda *args: "print('hello')")
    class Queue:
        """Record acceptance without a network queue."""
        def __init__(self, *args, **kwargs):
            pass
        def enqueue(self, *args, **kwargs):
            pass
    monkeypatch.setattr(github_webhooks, "Queue", Queue)
    monkeypatch.setattr(github_webhooks.Redis, "from_url", lambda *args, **kwargs: object())
    assert client.post("/api/v1/webhooks/github", content=body, headers=headers).status_code == 202
