"""GitHub App webhook contract tests with mocked GitHub and Redis edges."""

from __future__ import annotations

import hashlib
import hmac
import json
from uuid import UUID

from sqlalchemy import select

from dashboard.db.models import Audit, Organization, Repository
from dashboard.db.session import SessionLocal
from tests.test_dashboard_audits import hosted


def _payload() -> dict:
    return {
        "action": "opened",
        "installation": {"id": 42},
        "repository": {"full_name": "Example/repo"},
        "pull_request": {
            "number": 7,
            "head": {"sha": "a" * 40, "ref": "feature/security"},
        },
    }


def test_signed_pull_request_queues_tenant_audit(hosted, monkeypatch):
    client, org_id, _key = hosted
    with SessionLocal.begin() as db:
        db.get(Organization, org_id).github_slug = "example"
        db.get(Organization, org_id).github_installation_id = 42
        db.add(Repository(org_id=org_id, github_repo_full_name="Example/repo"))
    from dashboard.api import github_webhooks

    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "webhook-secret")
    monkeypatch.setattr(github_webhooks, "installation_token", lambda settings, installation_id: "ghs_test")
    monkeypatch.setattr(github_webhooks, "pull_request_diff", lambda settings, token, repo, pr: "diff --git a/x.py b/x.py\n+x = eval(user_input)\n")
    queued = []

    class FakeQueue:
        def __init__(self, *args, **kwargs):
            pass

        def enqueue(self, *args, **kwargs):
            queued.append((args, kwargs))

    monkeypatch.setattr(github_webhooks.Redis, "from_url", lambda *args, **kwargs: object())
    monkeypatch.setattr(github_webhooks, "Queue", FakeQueue)
    body = json.dumps(_payload(), separators=(",", ":")).encode()
    signature = "sha256=" + hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()
    response = client.post("/api/v1/webhooks/github", content=body, headers={
        "X-GitHub-Event": "pull_request", "X-Hub-Signature-256": signature,
    })
    assert response.status_code == 202
    audit_id = response.json()["audit_id"]
    with SessionLocal() as db:
        audit = db.scalar(select(Audit).where(Audit.id == UUID(audit_id)))
        assert audit is not None
        assert audit.pr_number == 7
        assert audit.commit_sha == "a" * 40
    assert queued and queued[0][1]["args"][3] == "python"


def test_unsigned_pull_request_is_rejected(hosted, monkeypatch):
    client, _org_id, _key = hosted
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "webhook-secret")
    body = json.dumps(_payload()).encode()
    response = client.post("/api/v1/webhooks/github", content=body, headers={"X-GitHub-Event": "pull_request"})
    assert response.status_code == 401
