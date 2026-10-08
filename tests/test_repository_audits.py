"""Manual branch audits enforce identity, quota, and immutable commit selection."""

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from dashboard.db.models import Audit, Organization, Repository, User
from dashboard.db.session import SessionLocal
from tests.test_dashboard_audits import hosted


@pytest.fixture
def repo(hosted):
    """Create an active repository belonging to the signed-in workspace."""
    client, org_id, _ = hosted
    with SessionLocal.begin() as db:
        row = Repository(org_id=org_id, github_repo_full_name="owner/project", default_branch="main", is_active=True)
        db.add(row)
        db.flush()
        repo_id = row.id
    return client, org_id, repo_id


def test_manual_audit_pins_selected_branch(repo, monkeypatch):
    """Branch names with slashes resolve once and reserve an audit before processing."""
    import dashboard.api.repository_audits as routes
    client, org_id, repo_id = repo
    client.get("/_test/login")
    github = AsyncMock(return_value={"commit": {"sha": "a" * 40}})
    monkeypatch.setattr(routes, "_github_get", github)
    monkeypatch.setenv("INLINE_AUDITS", "1")
    processed = []
    monkeypatch.setattr(routes, "fetch_and_process_repository_audit", lambda *args: processed.append(args))
    response = client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "feature/security"})
    assert response.status_code == 202
    assert response.json()["commit_sha"] == "a" * 40
    assert response.json()["status"] == "QUEUED"
    assert github.call_args.args[1].endswith("branches/feature%2Fsecurity")
    assert processed[0][:2] == (response.json()["audit_id"], str(org_id))
    with SessionLocal() as db:
        saved = db.get(Audit, UUID(response.json()["audit_id"]))
        assert saved.branch == "feature/security"
        assert saved.repo_id == repo_id


def test_branch_listing_is_paginated_and_requires_membership(repo, monkeypatch):
    """Anonymous and cross-workspace calls cannot contact GitHub."""
    import dashboard.api.repository_audits as routes
    client, org_id, repo_id = repo
    github = AsyncMock(return_value=[{"name": f"branch-{i}"} for i in range(100)])
    monkeypatch.setattr(routes, "_github_get", github)
    path = f"/api/v1/orgs/{org_id}/repos/{repo_id}/branches"
    assert client.get(path).status_code == 401
    client.get("/_test/login")
    assert client.get(path.replace(str(org_id), str(uuid4()))).status_code == 404
    github.assert_not_called()
    response = client.get(path + "?page=2")
    assert response.status_code == 200
    assert response.json()["next_page"] == 3
    assert len(response.json()["items"]) == 100


def test_invalid_commit_does_not_reserve_audit(repo, monkeypatch):
    """A malformed GitHub response cannot become a commit URL or queued job."""
    import dashboard.api.repository_audits as routes
    client, org_id, repo_id = repo
    client.get("/_test/login")
    monkeypatch.setattr(routes, "_github_get", AsyncMock(return_value={"commit": {"sha": "../unsafe"}}))
    response = client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "main"})
    assert response.status_code == 503
    with SessionLocal() as db:
        assert db.scalar(select(Audit.id)) is None


def test_inactive_repository_cannot_run(repo, monkeypatch):
    """Inactive repositories reject manual runs before contacting GitHub."""
    import dashboard.api.repository_audits as routes
    client, org_id, repo_id = repo
    client.get("/_test/login")
    with SessionLocal.begin() as db:
        db.get(Repository, repo_id).is_active = False
    github = AsyncMock()
    monkeypatch.setattr(routes, "_github_get", github)
    assert client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "main"}).status_code == 409
    github.assert_not_called()


def test_manual_audit_obeys_daily_quota(repo, monkeypatch):
    """Manual submissions share the same reservation counter as API-key audits."""
    import dashboard.api.repository_audits as routes
    from dashboard.api.billing_middleware import PLAN_LIMITS
    client, org_id, repo_id = repo
    client.get("/_test/login")
    monkeypatch.setattr(routes, "_github_get", AsyncMock(return_value={"commit": {"sha": "a" * 40}}))
    monkeypatch.setitem(PLAN_LIMITS, "free", 0)
    assert client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "main"}).status_code == 429
    with SessionLocal() as db:
        assert db.scalar(select(Audit.id)) is None


@pytest.mark.parametrize("code, expected", [("eval(input())", "FAILED"), ('print("hello")', "PASSED")])
def test_manual_worker_persists_scanner_results(repo, monkeypatch, code, expected):
    """The new route reaches the real static/taint pipeline with mocked Ollama."""
    import dashboard.api.repository_audits as routes
    from dashboard.worker import repository_audit_worker as worker, audit_worker
    client, org_id, repo_id = repo
    client.get("/_test/login")
    with SessionLocal.begin() as db:
        owner = db.get(Organization, org_id).owner_id
        db.get(User, owner).github_token_ciphertext = "encrypted-test-token"
    monkeypatch.setenv("INLINE_AUDITS", "1")
    monkeypatch.setenv("STATIC_ONLY_MODE", "0")
    monkeypatch.setattr(routes, "_github_get", AsyncMock(return_value={"commit": {"sha": "a" * 40}}))
    monkeypatch.setattr(worker, "fetch_commit_diff", lambda *args: "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+" + code + "\n")
    monkeypatch.setattr(audit_worker.AIAuditor, "analyze", AsyncMock(return_value=[]))
    monkeypatch.setattr(audit_worker, "_post_commit_status", lambda *args: None)
    monkeypatch.setattr(audit_worker, "_post_check_run", lambda *args: None)
    response = client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "main"})
    assert response.status_code == 202
    detail = client.get(f"/api/v1/orgs/{org_id}/audits/{response.json()['audit_id']}")
    assert detail.json()["status"] == expected
    assert (detail.json()["risk_score"] >= 40) == (expected == "FAILED")


def test_failed_download_is_a_visible_error(repo, monkeypatch):
    """A missing credential is a terminal error, never a clean security result."""
    import dashboard.api.repository_audits as routes
    client, org_id, repo_id = repo
    client.get("/_test/login")
    monkeypatch.setenv("INLINE_AUDITS", "1")
    monkeypatch.setattr(routes, "_github_get", AsyncMock(return_value={"commit": {"sha": "a" * 40}}))
    response = client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "main"})
    detail = client.get(f"/api/v1/orgs/{org_id}/audits/{response.json()['audit_id']}")
    assert detail.json()["status"] == "ERROR"


@pytest.mark.parametrize("diff", ["x" * 200001, "diff --git a/app.py b/app.py\n@@ -0,0 +1,2001 @@\n" + "+x = 1\n" * 2001], ids=["byte-limit", "line-limit"])
def test_commit_diff_bounds(diff, monkeypatch):
    """Transport and added-line limits are enforced before the scanner runs."""
    import httpx
    from dashboard.worker import repository_audit_worker as worker
    original_client = httpx.Client
    monkeypatch.setenv("DASHBOARD_DEV_MODE", "1")
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "local-test-session-secret-with-forty-characters")
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=diff))
    monkeypatch.setattr(worker, "decrypt_github_token", lambda value: "test-token")
    monkeypatch.setattr(worker.httpx, "Client", lambda **kwargs: original_client(transport=transport, **kwargs))
    with pytest.raises(ValueError, match="Commit diff exceeds"):
        worker.fetch_commit_diff("owner/project", "a" * 40, "encrypted")


def test_queue_failure_is_not_left_pending(repo, monkeypatch):
    """A broken Redis connection yields a retriable error and terminal audit row."""
    import dashboard.api.repository_audits as routes
    client, org_id, repo_id = repo
    client.get("/_test/login")
    monkeypatch.setenv("INLINE_AUDITS", "0")
    monkeypatch.setenv("STATIC_ONLY_MODE", "0")
    monkeypatch.setattr(routes, "_github_get", AsyncMock(return_value={"commit": {"sha": "a" * 40}}))
    def unavailable(*args, **kwargs):
        raise ConnectionError("test queue unavailable")
    monkeypatch.setattr(routes.Redis, "from_url", unavailable)
    response = client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": "main"})
    assert response.status_code == 503
    with SessionLocal() as db:
        assert db.scalar(select(Audit.status)) == "ERROR"


@pytest.mark.parametrize("branch", ["../main", "main?token=x", "main\n", "/main", "main.lock"])
def test_invalid_branches_rejected(repo, branch):
    """Reject invalid refs rather than interpolating them into GitHub requests."""
    client, org_id, repo_id = repo
    client.get("/_test/login")
    assert client.post(f"/api/v1/orgs/{org_id}/repos/{repo_id}/audits", json={"branch": branch}).status_code == 422
