"""Identity routes and tenant boundary checks for hosted mode."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from dashboard.api import auth, orgs
from dashboard.db.models import ApiKey, Base, User
from dashboard.db.session import get_db
from dashboard.security import authenticate_api_key, decrypt_github_token


@pytest.fixture
def site(monkeypatch):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    settings = SimpleNamespace(
        github_client_id="client",
        github_client_secret="secret",
        github_callback_url="http://testserver/api/v1/auth/github/callback",
        github_api_url="https://api.github.com",
        token_encryption_key=Fernet.generate_key().decode(),
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(orgs, "get_settings", lambda: settings)
    monkeypatch.setattr("dashboard.security.get_settings", lambda: settings)
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="s" * 40)
    app.include_router(auth.auth_router)
    app.include_router(orgs.orgs_router)

    def session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = session_override
    with TestClient(app) as client:
        yield client, engine, settings
    engine.dispose()


def _login(client, monkeypatch, github_id=123, login="alice"):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"id": github_id, "login": login, "email": None}

    class FakeClient:
        async def authorize_redirect(self, request, callback, state):
            from starlette.responses import RedirectResponse
            return RedirectResponse("https://github.com/login/oauth/authorize?state=" + state)

        async def fetch_access_token(self, **kwargs):
            return {"access_token": "gho-secret"}

        async def authorize_access_token(self, request):
            return {"access_token": "gho-secret"}

        async def get(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(auth, "_github_client", lambda: FakeClient())
    response = client.get("/api/v1/auth/github", follow_redirects=False)
    assert response.status_code == 307
    state = response.headers["location"].split("state=", 1)[1]
    return state


def test_oauth_state_and_encrypted_token(site, monkeypatch):
    client, engine, _ = site
    state = _login(client, monkeypatch)
    bad = client.post("/api/v1/auth/github", json={"code": "abc", "state": "wrong"})
    assert bad.status_code == 400
    response = client.post("/api/v1/auth/github", json={"code": "abc", "state": state})
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me").json()["login"] == "alice"
    personal_orgs = client.get("/api/v1/orgs").json()
    assert len(personal_orgs) == 1
    assert personal_orgs[0]["name"] == "alice's workspace"
    assert personal_orgs[0]["role"] == "owner"
    with Session(engine) as db:
        user = db.scalar(select(User).where(User.github_id == "123"))
        assert user.github_token_ciphertext != "gho-secret"
        assert decrypt_github_token(user.github_token_ciphertext) == "gho-secret"
    assert client.post("/api/v1/auth/github", json={"code": "abc", "state": state}).status_code == 400


def test_get_oauth_callback(site, monkeypatch):
    client, _, _ = site
    state = _login(client, monkeypatch)
    response = client.get(f"/api/v1/auth/github/callback?code=abc&state={state}")
    assert response.status_code == 200
    assert response.json()["login"] == "alice"


def test_nextauth_token_exchange_verifies_github_and_creates_workspace(site, monkeypatch):
    """An access token is accepted only after GitHub confirms the user."""
    client, engine, _ = site

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, *, headers):
            assert headers["Authorization"] == "Bearer verified-token"
            if url == "https://api.github.com/user":
                return FakeResponse({"id": 876, "login": "nextauth-user", "name": "Next User"})
            assert url == "https://api.github.com/user/emails"
            return FakeResponse([{"email": "owner@example.test", "primary": True, "verified": True}])

    monkeypatch.setattr(auth.httpx, "AsyncClient", lambda **kwargs: FakeHttpClient())
    result = client.post("/api/v1/auth/github", headers={"Authorization": "Bearer verified-token"})
    assert result.status_code == 200
    assert result.json()["org_id"]
    assert client.get("/api/v1/orgs").json()[0]["name"] == "nextauth-user's workspace"
    with Session(engine) as db:
        user = db.scalar(select(User).where(User.github_id == 876))
        assert decrypt_github_token(user.github_token_ciphertext) == "verified-token"
        assert user.email == "owner@example.test"


def test_org_membership_and_one_time_api_key(site, monkeypatch):
    client, engine, _ = site
    state = _login(client, monkeypatch)
    assert client.post("/api/v1/auth/github", json={"code": "abc", "state": state}).status_code == 200
    assert client.post("/api/v1/orgs", json={"name": "Acme"}).status_code == 429
    org_id = client.get("/api/v1/orgs").json()[0]["id"]
    key_response = client.post(f"/api/v1/orgs/{org_id}/keys", json={"name": "CI"})
    assert key_response.status_code == 201
    raw = key_response.json()["key"]
    assert raw.startswith("ag_live_")
    listed = client.get(f"/api/v1/orgs/{org_id}/keys").json()
    assert listed[0]["last4"] == raw[-4:]
    assert "key" not in listed[0]
    with Session(engine) as db:
        stored = db.get(ApiKey, UUID(key_response.json()["id"]))
        assert stored.key_hash != raw
        assert authenticate_api_key(raw, db).id == stored.id
        with pytest.raises(Exception):
            authenticate_api_key(raw[:-1] + ("A" if raw[-1] != "A" else "B"), db)
        other = User(github_id=456, login="other")
        db.add(other)
        db.flush()
        other_id = other.id
        db.commit()
    revoked = client.delete(f"/api/v1/orgs/{org_id}/api-keys/{key_response.json()['id']}")
    assert revoked.status_code == 204
    assert client.get(f"/api/v1/orgs/{org_id}/keys").json()[0]["revoked"] is True
    with Session(engine) as db:
        with pytest.raises(Exception):
            authenticate_api_key(raw, db)
    assert client.post(f"/api/v1/orgs/{org_id}/members", json={"user_id": str(other_id), "role": "owner"}).status_code == 422
    client.post("/api/v1/auth/logout")
    other_state = _login(client, monkeypatch, github_id=456, login="other")
    client.post("/api/v1/auth/github", json={"code": "abc", "state": other_state})
    assert client.get(f"/api/v1/orgs/{org_id}/keys").status_code == 404
    other_orgs = client.get("/api/v1/orgs").json()
    assert len(other_orgs) == 1
    assert other_orgs[0]["name"] == "other's workspace"


def test_repo_requires_live_github_access(site, monkeypatch):
    client, _, _ = site
    state = _login(client, monkeypatch)
    client.post("/api/v1/auth/github", json={"code": "abc", "state": state})
    org_id = client.get("/api/v1/orgs").json()[0]["id"]

    async def denied(*args, **kwargs):
        from fastapi import HTTPException
        raise HTTPException(403, "GitHub access required")

    monkeypatch.setattr(orgs, "_github_get", denied)
    result = client.post(
        f"/api/v1/orgs/{org_id}/repos",
        json={"github_repo_full_name": "owner/private"},
    )
    assert result.status_code == 403
    assert client.get(f"/api/v1/orgs/{org_id}/repos").json() == []

    async def allowed(*args, **kwargs):
        return {"full_name": "owner/private", "permissions": {"push": True}}

    monkeypatch.setattr(orgs, "_github_get", allowed)
    added = client.post(
        f"/api/v1/orgs/{org_id}/repos",
        json={"github_repo_full_name": "owner/private"},
    )
    assert added.status_code == 201
    assert client.get(f"/api/v1/orgs/{org_id}/repos").json()[0]["id"] == added.json()["id"]
