"""Free deployment behavior using real persisted audits and unavailable networks."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from dashboard.app import create_app
from dashboard.config import get_settings
from dashboard.db.models import Audit
from dashboard.db.session import SessionLocal
from tests.test_dashboard_audits import hosted


@pytest.mark.parametrize("code,status", [('eval(user_input)', 'FAILED'), ('print("hello")', 'PASSED')])
def test_static_only_audit_without_queue_or_model(hosted, monkeypatch, code, status):
    """Free audits finish and persist without reaching Redis or Ollama."""
    client, org_id, key = hosted
    monkeypatch.setenv("STATIC_ONLY_MODE", "1")
    with patch("dashboard.api.audits.Redis.from_url", side_effect=AssertionError("Redis forbidden")), \
         patch("dashboard.worker.audit_worker.AIAuditor", side_effect=AssertionError("Ollama forbidden")):
        response = client.post("/api/v1/audit", json={"diff_content": code, "language": "python"},
                               headers={"X-API-Key": key})
    assert response.status_code == 202
    assert response.json()["status"] == status
    assert response.json()["model_used"] == "static-only"
    if status == "FAILED":
        assert response.json()["risk_score"] >= 40
    with SessionLocal() as session:
        audit = session.scalar(select(Audit).where(Audit.org_id == org_id))
        assert audit.status == status
        assert audit.ai_count == 0


def test_static_only_failure_is_error(hosted, monkeypatch):
    """An unavailable sole engine must never approve a change."""
    client, _, key = hosted
    monkeypatch.setenv("STATIC_ONLY_MODE", "1")
    with patch("dashboard.worker.audit_worker.static_analyzer.analyze", side_effect=RuntimeError("unavailable")):
        response = client.post("/api/v1/audit", json={"diff_content": "eval(input())", "language": "python"},
                               headers={"X-API-Key": key})
    assert response.json()["status"] == "ERROR"


def test_health_and_landing_need_no_database_connection(hosted, monkeypatch):
    """Sleeping or unavailable storage does not fail the platform liveness check."""
    monkeypatch.setattr("dashboard.db.session.get_engine", lambda: pytest.fail("Database accessed"))
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/").json() == {"message": "AI Guardian API live", "docs": "/docs"}


def test_sqlite_fallback_is_local_only(monkeypatch):
    """Only explicit development may omit durable database configuration."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DASHBOARD_DEV_MODE", "1")
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "s" * 40)
    assert get_settings().database_url.startswith("sqlite")
    monkeypatch.setenv("DASHBOARD_DEV_MODE", "0")
    with pytest.raises(ValueError, match="DATABASE_URL"):
        get_settings()


def test_local_api_skips_ollama(monkeypatch):
    """The local scanner also honors the static-only deployment switch."""
    from main import app
    monkeypatch.setenv("STATIC_ONLY_MODE", "1")
    with patch("scanner.ai_auditor.AIAuditor.analyze", side_effect=AssertionError("Ollama forbidden")), TestClient(app) as client:
        response = client.post("/api/v1/audit", json={"diff_content": "eval(input())", "language": "python"})
    assert response.json()["status"] == "FAILED"
    assert response.json()["model_used"] == "static-only"
    assert response.json()["ai_count"] == 0


def test_free_webhook_persists_inline_and_publishes_check(hosted, monkeypatch):
    """A verified PR delivery completes without leaving a job in an unused queue."""
    import hashlib
    import hmac
    import json
    from uuid import UUID
    from dashboard.api import github_webhooks
    from dashboard.db.models import Organization
    from tests.test_github_webhook import _payload

    client, org_id, _ = hosted
    monkeypatch.setenv("STATIC_ONLY_MODE", "1")
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "webhook-test-secret")
    with SessionLocal.begin() as session:
        session.get(Organization, org_id).github_slug = "example"
    monkeypatch.setattr(github_webhooks, "installation_token", lambda *args: "test-token")
    monkeypatch.setattr(github_webhooks, "pull_request_diff", lambda *args: "diff --git a/x.py b/x.py\n@@ -0,0 +1 @@\n+eval(user_input)\n")
    body = json.dumps(_payload()).encode()
    signature = "sha256=" + hmac.new(b"webhook-test-secret", body, hashlib.sha256).hexdigest()
    with patch("dashboard.api.github_webhooks.Redis.from_url", side_effect=AssertionError("Redis forbidden")), \
         patch("dashboard.worker.audit_worker.AIAuditor", side_effect=AssertionError("Ollama forbidden")), \
         patch("dashboard.worker.audit_worker._post_check_run") as publish:
        response = client.post("/api/v1/webhooks/github", content=body,
                               headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": signature})
    assert response.status_code == 202
    assert response.json()["status"] == "processed"
    with SessionLocal() as session:
        audit = session.get(Audit, UUID(response.json()["audit_id"]))
        assert audit.status == "FAILED"
    assert publish.call_args.args[2] == "failure"
