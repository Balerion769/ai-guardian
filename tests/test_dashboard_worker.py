"""Worker behavior with database, model, and GitHub boundaries mocked."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dashboard.worker import audit_worker as worker
from scanner.models import Vulnerability

AUDIT_ID = "11111111-1111-4111-8111-111111111111"
ORG_ID = "22222222-2222-4222-8222-222222222222"


def _settings():
    return SimpleNamespace(
        ollama_url="http://ollama:11434/api/generate",
        ollama_model="test-model",
        github_api_url="https://api.github.com",
        public_base_url="https://guardian.example",
    )


def _database(audit):
    session = MagicMock()
    session.scalar.return_value = audit
    session_factory = MagicMock()
    session_factory.begin.return_value.__enter__.return_value = session
    return session_factory, session


def _finding(severity="HIGH"):
    return Vulnerability(
        severity=severity,
        category="Code Injection",
        description="Dynamic code execution may run untrusted input.",
        line_reference="src/app.py:Line 3",
        remediation="Avoid dynamic execution.",
    )


def test_worker_persists_high_finding_and_failure_status():
    audit = SimpleNamespace(status="QUEUED", repo_id=None, commit_sha=None)
    factory, session = _database(audit)
    auditor = MagicMock()
    auditor.analyze.return_value = []
    with (
        patch.object(worker, "SessionLocal", factory),
        patch.object(worker, "tenant_scope") as scope,
        patch.object(worker, "get_settings", return_value=_settings()),
        patch.object(worker, "static_analyzer") as static,
        patch.object(worker, "analyze_taint", return_value=[]),
        patch.object(worker, "AIAuditor", return_value=auditor),
        patch.object(worker.asyncio, "run", return_value=[]),
        patch.object(worker, "_post_commit_status") as post,
    ):
        static.analyze.return_value = [_finding()]
        worker.process_audit(AUDIT_ID, ORG_ID, "+eval(input())", "python")

    assert audit.status == "FAILED"
    assert audit.risk_score == 40
    assert audit.static_count == 1 and audit.ai_count == 0
    assert (audit.total_findings, audit.high_count, audit.medium_count, audit.low_count) == (1, 1, 0, 0)
    assert audit.model_used == "test-model"
    assert audit.latency_ms >= 0
    assert session.add.call_count == 1
    post.assert_called_once_with(AUDIT_ID, ORG_ID, "failure", audit.summary)
    assert scope.call_count == 2


def test_worker_keeps_static_finding_when_model_is_down(caplog):
    audit = SimpleNamespace(status="QUEUED", repo_id=None, commit_sha=None)
    factory, session = _database(audit)
    with (
        patch.object(worker, "SessionLocal", factory),
        patch.object(worker, "tenant_scope"),
        patch.object(worker, "get_settings", return_value=_settings()),
        patch.object(worker, "static_analyzer") as static,
        patch.object(worker, "analyze_taint", return_value=[]),
        patch.object(worker, "AIAuditor"),
        patch.object(worker.asyncio, "run", side_effect=OSError("model unavailable")),
        patch.object(worker, "_post_commit_status") as post,
    ):
        static.analyze.return_value = [_finding("LOW")]
        worker.process_audit(AUDIT_ID, ORG_ID, "+safe_code()", "python")

    assert audit.status == "PASSED"
    assert audit.risk_score == 5
    assert (audit.total_findings, audit.high_count, audit.medium_count, audit.low_count) == (1, 0, 0, 1)
    assert "Semantic review was unavailable" in audit.summary
    assert session.add.call_count == 1
    post.assert_called_once_with(AUDIT_ID, ORG_ID, "success", audit.summary)
    assert "+safe_code()" not in caplog.text


def test_worker_deduplicates_static_and_model_findings():
    audit = SimpleNamespace(status="QUEUED", repo_id=None, commit_sha=None)
    factory, session = _database(audit)
    with (
        patch.object(worker, "SessionLocal", factory),
        patch.object(worker, "tenant_scope"),
        patch.object(worker, "get_settings", return_value=_settings()),
        patch.object(worker, "static_analyzer") as static,
        patch.object(worker, "analyze_taint", return_value=[]),
        patch.object(worker, "AIAuditor"),
        patch.object(worker.asyncio, "run", return_value=[_finding("HIGH")]),
        patch.object(worker, "_post_commit_status"),
    ):
        static.analyze.return_value = [_finding("LOW")]
        worker.process_audit(AUDIT_ID, ORG_ID, "+eval(input())", "python")

    assert audit.status == "FAILED"
    assert audit.static_count == 1 and audit.ai_count == 1
    assert audit.total_findings == 1 and audit.risk_score == 40
    assert session.add.call_count == 1


def test_worker_marks_error_when_both_engines_fail():
    audit = SimpleNamespace(status="QUEUED", repo_id=None, commit_sha=None)
    factory, session = _database(audit)
    with (
        patch.object(worker, "SessionLocal", factory),
        patch.object(worker, "tenant_scope"),
        patch.object(worker, "get_settings", return_value=_settings()),
        patch.object(worker, "static_analyzer") as static,
        patch.object(worker, "AIAuditor"),
        patch.object(worker.asyncio, "run", side_effect=OSError("model unavailable")),
        patch.object(worker, "_post_commit_status") as post,
    ):
        static.analyze.side_effect = RuntimeError("static unavailable")
        worker.process_audit(AUDIT_ID, ORG_ID, "+safe_code()", "python")

    assert audit.status == "ERROR"
    assert audit.static_count == 0 and audit.ai_count == 0
    assert session.add.call_count == 0
    post.assert_called_once_with(AUDIT_ID, ORG_ID, "failure", audit.summary)


def test_github_failure_does_not_erase_committed_result():
    audit = SimpleNamespace(repo_id="repo-id", commit_sha="a" * 40)
    repository = SimpleNamespace(github_repo_full_name="owner/repo")
    factory, session = _database(audit)
    session.scalar.side_effect = [audit, repository]
    session.scalars.return_value.first.return_value = "encrypted-token"
    with (
        patch.object(worker, "SessionLocal", factory),
        patch.object(worker, "tenant_scope"),
        patch.object(worker, "get_settings", return_value=_settings()),
        patch.object(worker, "decrypt_github_token", return_value="secret-token"),
        patch.object(worker.httpx, "post", side_effect=OSError("GitHub unavailable")) as post,
    ):
        worker._post_commit_status(AUDIT_ID, ORG_ID, "failure", "Finding detected")
    assert post.call_count == 1
    assert post.call_args.kwargs["json"]["state"] == "failure"


def test_unexpected_failure_sets_error_without_logging_source(caplog):
    """A worker crash leaves an explicit terminal audit state."""
    audit = SimpleNamespace(status="RUNNING", summary="")
    factory, _session = _database(audit)
    with (
        patch.object(worker, "_process_audit", side_effect=RuntimeError("database unavailable")),
        patch.object(worker, "SessionLocal", factory),
        patch.object(worker, "tenant_scope"),
        patch.object(worker, "_post_commit_status") as post,
    ):
        with pytest.raises(RuntimeError):
            worker.process_audit(AUDIT_ID, ORG_ID, "secret-source-text", "python")
    assert audit.status == "ERROR"
    assert "retry" in audit.summary
    post.assert_called_once()
    assert "secret-source-text" not in caplog.text
