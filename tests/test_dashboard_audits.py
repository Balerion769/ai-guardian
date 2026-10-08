"""Hosted audit API integration with real ORM rows and a synchronous fake queue."""

from __future__ import annotations

import secrets
from uuid import uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import dashboard.api.audits as audit_routes
import dashboard.db.session as db_session
from dashboard.app import create_app
from dashboard.db.models import ApiKey, Audit, Base, OrgMember, Organization, Repository, User
from dashboard.security import hash_api_key


@pytest.fixture
def hosted(monkeypatch):
    """Serve hosted routes over a shared in-memory relational database."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://unused:6379/0")
    monkeypatch.setenv("DASHBOARD_DEV_MODE", "1")
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "local-test-session-secret-with-forty-characters")
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(db_session, "_engine", engine)
    monkeypatch.setattr(db_session, "_factory", sessionmaker(bind=engine, expire_on_commit=False))
    key_id = uuid4()
    raw_key = f"ag_live_{key_id}_{secrets.token_urlsafe(36)}"
    salt = secrets.token_hex(16)
    with db_session.SessionLocal.begin() as session:
        user = User(github_id=123, login="owner")
        session.add(user)
        session.flush()
        org = Organization(name="Example", owner_id=user.id)
        session.add(org)
        session.flush()
        session.add(OrgMember(org_id=org.id, user_id=user.id, role="owner"))
        session.add(ApiKey(id=key_id, org_id=org.id, created_by=user.id, name="CI", key_prefix=f"ag_live_{key_id}_", key_last4=raw_key[-4:], salt=salt, key_hash=hash_api_key(raw_key, salt)))
        user_id, org_id = user.id, org.id

    app = create_app()

    @app.get("/_test/login")
    def test_login(request: Request):
        request.session["user_id"] = str(user_id)
        return {"ok": True}

    with TestClient(app) as client:
        yield client, org_id, raw_key
    engine.dispose()


def test_queued_audit_requires_key_and_reserves_quota(hosted, monkeypatch):
    """A valid key queues an audit and the plan quota blocks the next one."""
    client, org_id, key = hosted

    class FakeQueue:
        def __init__(self, *args, **kwargs):
            pass

        def enqueue(self, *args, **kwargs):
            return None

    monkeypatch.setattr(audit_routes.Redis, "from_url", lambda *args, **kwargs: object())
    monkeypatch.setattr(audit_routes, "Queue", FakeQueue)
    monkeypatch.setitem(audit_routes.PLAN_LIMITS, "free", 1)
    payload = {"diff_content": "eval(user_input)", "language": "python"}
    assert client.post("/api/v1/audit", json=payload).status_code == 401
    assert client.post("/api/v1/audit", json=payload, headers={"X-API-Key": "bad"}).status_code == 401
    first = client.post("/api/v1/audit", json=payload, headers={"X-API-Key": key})
    assert first.status_code == 202
    assert first.json()["status"] == "QUEUED"
    second = client.post("/api/v1/audit", json=payload, headers={"X-API-Key": key})
    assert second.status_code == 429
    with db_session.SessionLocal() as session:
        assert session.scalar(select(Audit.org_id)) == org_id


def test_fast_path_persists_findings_and_stats(hosted, monkeypatch):
    """The queue's worker result is returned and visible in tenant statistics."""
    client, org_id, key = hosted

    async def no_model_findings(*args, **kwargs):
        return []

    from dashboard.worker import audit_worker
    monkeypatch.setattr(audit_worker.AIAuditor, "analyze", no_model_findings)
    monkeypatch.setattr(audit_routes.Redis, "from_url", lambda *args, **kwargs: object())

    class ImmediateQueue:
        def __init__(self, *args, **kwargs):
            pass

        def enqueue(self, _callable, args, **kwargs):
            audit_worker.process_audit(*args)

    monkeypatch.setattr(audit_routes, "Queue", ImmediateQueue)
    with db_session.SessionLocal.begin() as session:
        repo = Repository(org_id=org_id, github_repo_full_name="example/repo")
        session.add(repo)
        session.flush()
        repo_id = repo.id
    result = client.post("/api/v1/audit", json={"diff_content": "user_input = input()\neval(user_input)", "language": "python", "repo_id": str(repo_id)}, headers={"X-API-Key": key})
    assert result.status_code == 202
    data = result.json()
    assert data["status"] == "FAILED"
    assert data["risk_score"] >= 40
    assert data["total_findings"] >= 1
    assert all(item["line_number"] == 2 for item in data["findings"])
    client.get("/_test/login")
    detail = client.get(f"/api/v1/orgs/{org_id}/audits/{data['audit_id']}")
    assert detail.status_code == 200
    assert detail.json()["total_findings"] == data["total_findings"]
    stats = client.get(f"/api/v1/orgs/{org_id}/stats")
    assert stats.status_code == 200
    assert stats.json()["risk_over_time"][0]["audit_count"] == 1
    assert stats.json()["findings_by_category"]
    assert stats.json()["top_vulnerable_repos"][0]["repo_id"] == str(repo_id)
    fixed = client.patch(f"/api/v1/orgs/{org_id}/findings/{data['findings'][0]['id']}")
    assert fixed.status_code == 200
    assert fixed.json()["is_fixed"] is True
    assert client.get(f"/api/v1/orgs/{org_id}/stats").json()["mttr_hours"] is not None


def test_cross_tenant_history_is_hidden(hosted, monkeypatch):
    """A member of another organization cannot read audit history or stats."""
    client, org_id, _key = hosted
    with db_session.SessionLocal.begin() as session:
        other_user = User(github_id=456, login="other")
        session.add(other_user)
        session.flush()
        other_org = Organization(name="Other", owner_id=other_user.id)
        session.add(other_org)
        session.flush()
        session.add(OrgMember(org_id=other_org.id, user_id=other_user.id, role="owner"))
        other_id = other_user.id

    @client.app.get("/_test/login-other")
    def login_other(request: Request):
        request.session["user_id"] = str(other_id)
        return {"ok": True}

    client.get("/_test/login-other")
    assert client.get(f"/api/v1/orgs/{org_id}/audits").status_code == 404
    assert client.get(f"/api/v1/orgs/{org_id}/stats").status_code == 404


def test_queue_outage_marks_attempt_error(hosted, monkeypatch):
    """A Redis failure never leaves an audit pending indefinitely."""
    client, _org_id, key = hosted

    class BrokenQueue:
        def __init__(self, *args, **kwargs):
            raise ConnectionError("redis unavailable")

    monkeypatch.setattr(audit_routes.Redis, "from_url", lambda *args, **kwargs: object())
    monkeypatch.setattr(audit_routes, "Queue", BrokenQueue)
    result = client.post("/api/v1/audit", json={"diff_content": "print('hello')", "language": "python"}, headers={"X-API-Key": key})
    assert result.status_code == 503
    with db_session.SessionLocal() as session:
        assert session.scalar(select(Audit.status)) == "ERROR"


@pytest.mark.parametrize("size, expected", [(200_001, 200), (2_000_000, 200), (2_000_001, 413)])
def test_audit_diff_is_fetched_on_demand_and_not_persisted(hosted, monkeypatch, size, expected):
    """A linked PR diff is retrieved from GitHub for a member only."""
    client, org_id, _key = hosted
    prefix = b"diff --git a/x.py b/x.py\n+print('hello')\n"
    diff = prefix + b"#" * (size - len(prefix))
    with db_session.SessionLocal.begin() as session:
        user = session.scalar(select(User))
        user.github_token_ciphertext = "encrypted"
        repo = Repository(org_id=org_id, github_repo_full_name="example/repo")
        session.add(repo)
        session.flush()
        audit = Audit(org_id=org_id, repo_id=repo.id, pr_number=7,
                      status="PASSED", risk_score=0, summary="Clean")
        session.add(audit)
        session.flush()
        audit_id = audit.id
    client.get("/_test/login")
    monkeypatch.setattr(audit_routes, "decrypt_github_token", lambda value: "verified")

    class FakeResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def raise_for_status(self):
            return None

        async def aiter_bytes(self):
            for offset in range(0, len(diff), 65_536):
                yield diff[offset:offset + 65_536]

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def stream(self, method, url, *, headers):
            assert method == "GET"
            assert url.endswith("/repos/example/repo/pulls/7")
            assert headers["Authorization"] == "Bearer verified"
            return FakeResponse()

    monkeypatch.setattr(audit_routes.httpx, "AsyncClient", lambda **kwargs: FakeHttpClient())
    result = client.get(f"/api/v1/orgs/{org_id}/audits/{audit_id}/diff")
    assert result.status_code == expected
    if expected == 200:
        assert result.content == diff
        assert result.headers["cache-control"] == "no-store"
    else:
        assert "display limit" in result.json()["detail"]
    with db_session.SessionLocal() as session:
        assert "diff --git" not in session.get(Audit, audit_id).summary
