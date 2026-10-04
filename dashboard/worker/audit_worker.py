"""RQ entry point for one tenant-scoped hosted audit."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from uuid import UUID

import httpx
from sqlalchemy import delete, select

from dashboard.config import get_settings
from dashboard.db.models import Audit, Finding, OrgMember, Organization, Repository, User
from dashboard.db.session import SessionLocal, tenant_scope
from dashboard.security import decrypt_github_token
from dashboard.github_app import create_check_run, installation_token
from dashboard.observability import record_audit, record_llm_result
from scanner.pipeline import _downgrade_examples, calculate_risk_score, combine_findings
from scanner.ai_auditor import AIAuditor
from scanner.static_rules import StaticAnalyzer
from scanner.taint import analyze_taint

logger = logging.getLogger(__name__)
static_analyzer = StaticAnalyzer()
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT_SHA = re.compile(r"^[a-fA-F0-9]{7,64}$")


def _post_commit_status(audit_id: str, org_id: str, state: str, summary: str) -> None:
    """Publish a bounded status after the audit transaction is committed."""
    with SessionLocal.begin() as session:
        tenant_scope(session, UUID(org_id))
        audit = session.scalar(select(Audit).where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
        if audit is None or not audit.repo_id or not audit.commit_sha:
            return
        repository = session.scalar(
            select(Repository).where(Repository.id == audit.repo_id, Repository.org_id == UUID(org_id))
        )
        if repository is None or not _REPOSITORY_NAME.fullmatch(repository.github_repo_full_name):
            return
        if not _COMMIT_SHA.fullmatch(audit.commit_sha):
            return
        credentials = session.scalars(
            select(User.github_token_ciphertext)
            .join(OrgMember, OrgMember.user_id == User.id)
            .where(
                OrgMember.org_id == UUID(org_id),
                OrgMember.role == "owner",
                User.github_token_ciphertext.is_not(None),
            )
        ).first()
        if not credentials:
            return
        full_name = repository.github_repo_full_name
        commit_sha = audit.commit_sha

    try:
        token = decrypt_github_token(credentials)
        settings = get_settings()
        url = f"{settings.github_api_url.rstrip('/')}/repos/{full_name}/statuses/{commit_sha}"
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={
                "state": state,
                "context": "AI Guardian",
                "description": summary[:140],
                "target_url": f"{settings.public_base_url.rstrip('/')}/audits/{audit_id}",
            },
            timeout=10.0,
        )
        response.raise_for_status()
    except Exception:
        # The findings are already committed. Never log the token or response body.
        logger.warning("github_commit_status_failed audit_id=%s org_id=%s", audit_id, org_id)


def _post_check_run(audit_id: str, org_id: str, conclusion: str, summary: str) -> None:
    """Publish a GitHub App check run when the repository has an installation."""
    with SessionLocal.begin() as session:
        tenant_scope(session, UUID(org_id))
        row = session.execute(
            select(Audit, Organization, Repository)
            .join(Organization, Organization.id == Audit.org_id)
            .join(Repository, Repository.id == Audit.repo_id)
            .where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id))
        ).first()
        if row is None:
            return
        try:
            audit, organization, repository = row
        except (TypeError, ValueError):
            # Lightweight unit-test/session doubles may not expose ORM rows.
            return
        if not organization.github_installation_id or not audit.commit_sha:
            return
        installation_id = organization.github_installation_id
        full_name = repository.github_repo_full_name
        commit_sha = audit.commit_sha
    try:
        settings = get_settings()
        token = installation_token(settings, int(installation_id))
        details = f"{settings.web_base_url.rstrip('/')}/dashboard/audits/{audit_id}"
        create_check_run(settings, token, full_name, commit_sha,
                         conclusion=conclusion, summary=summary, details_url=details)
    except Exception:
        logger.warning("github_check_run_failed audit_id=%s org_id=%s", audit_id, org_id)


def process_audit(audit_id: str, org_id: str, diff_content: str, language: str) -> None:
    """Run one job and turn unexpected failures into a visible audit error."""
    try:
        _process_audit(audit_id, org_id, diff_content, language)
    except Exception as exc:
        logger.error("audit_worker_failed audit_id=%s org_id=%s error_type=%s",
                     audit_id, org_id, type(exc).__name__)
        try:
            with SessionLocal.begin() as session:
                tenant_scope(session, UUID(org_id))
                audit = session.scalar(select(Audit).where(
                    Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
                if audit is not None:
                    audit.status = "ERROR"
                    audit.summary = "Audit processing failed; retry submission."
                    audit.completed_at = datetime.now(timezone.utc)
            _post_commit_status(audit_id, org_id, "failure", "AI Guardian audit processing failed")
        except Exception as recovery_error:
            logger.error("audit_worker_recovery_failed audit_id=%s org_id=%s error_type=%s",
                         audit_id, org_id, type(recovery_error).__name__)
        raise


def _process_audit(audit_id: str, org_id: str, diff_content: str, language: str) -> None:
    """Analyze queued source and persist findings without retaining the source."""
    started = time.perf_counter()
    audit_uuid = UUID(audit_id)
    org_uuid = UUID(org_id)
    with SessionLocal.begin() as session:
        tenant_scope(session, org_uuid)
        audit = session.scalar(select(Audit).where(Audit.id == audit_uuid, Audit.org_id == org_uuid))
        if audit is None:
            raise ValueError("Audit is unavailable")
        if audit.status in {"PASSED", "FAILED"}:
            return
        audit.status = "RUNNING"
        audit.started_at = datetime.now(timezone.utc)

    static_failed = False
    try:
        static_findings = static_analyzer.analyze(diff_content, language)
        static_findings.extend(analyze_taint(diff_content, language))
    except Exception:
        static_failed = True
        static_findings = []
        logger.warning("static_audit_failed audit_id=%s org_id=%s", audit_id, org_id)

    ai_failed = False
    model_used = "unavailable"
    try:
        settings = get_settings()
        model_used = settings.ollama_model
        auditor = AIAuditor(base_url=settings.ollama_url, model=model_used)
        ai_findings = asyncio.run(auditor.analyze(diff_content, language))
    except Exception:
        ai_failed = True
        ai_findings = []
        logger.warning("semantic_audit_failed audit_id=%s org_id=%s", audit_id, org_id)
    record_llm_result(ai_failed)

    findings = _downgrade_examples(combine_findings(static_findings, ai_findings))
    risk_score = calculate_risk_score(findings)
    if static_failed and ai_failed:
        status = "ERROR"
        summary = "Both static analysis and semantic review were unavailable; retry the audit."
    else:
        status = "FAILED" if any(item.severity == "HIGH" for item in findings) else "PASSED"
        summary = f"Found {len(findings)} security finding(s)."
        if ai_failed:
            summary += " Semantic review was unavailable; only static analysis completed."
        elif static_failed:
            summary += " Static analysis failed; only semantic review completed."
        elif any(item.category == "Analysis Incomplete" for item in findings):
            summary += " Semantic analysis was incomplete; repeat the audit before accepting the change."
        elif not findings:
            summary = "No security vulnerabilities detected in the supplied change."

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    with SessionLocal.begin() as session:
        tenant_scope(session, org_uuid)
        audit = session.scalar(select(Audit).where(Audit.id == audit_uuid, Audit.org_id == org_uuid))
        if audit is None:
            raise ValueError("Audit is unavailable")
        session.execute(delete(Finding).where(Finding.audit_id == audit_uuid, Finding.org_id == org_uuid))
        audit.status = status
        audit.risk_score = risk_score
        audit.summary = summary
        audit.static_count = len(static_findings)
        audit.ai_count = len(ai_findings)
        audit.total_findings = len(findings)
        audit.high_count = sum(item.severity == "HIGH" for item in findings)
        audit.medium_count = sum(item.severity == "MEDIUM" for item in findings)
        audit.low_count = sum(item.severity == "LOW" for item in findings)
        audit.latency_ms = latency_ms
        audit.model_used = model_used[:255]
        audit.completed_at = datetime.now(timezone.utc)
        if audit.repo_id is not None:
            repository = session.scalar(select(Repository).where(
                Repository.id == audit.repo_id, Repository.org_id == org_uuid))
            if repository is not None:
                repository.last_audit_at = audit.completed_at
        for item in findings:
            match = re.fullmatch(r"(?:(.+):)?Line (\d+)", item.line_reference)
            session.add(Finding(
                org_id=org_uuid,
                audit_id=audit_uuid,
                severity=item.severity,
                category=item.category[:255],
                description=item.description,
                file_path=match.group(1) if match else None,
                line_number=int(match.group(2)) if match else None,
                line_reference=item.line_reference[:512],
                remediation=item.remediation,
                confidence=item.confidence,
                tainted=item.tainted,
            ))

    commit_state = "failure" if status in {"FAILED", "ERROR"} else "success"
    try:
        _post_commit_status(audit_id, org_id, commit_state, summary)
    except Exception:
        logger.warning("github_commit_status_failed audit_id=%s org_id=%s", audit_id, org_id)
    logger.info("audit_complete audit_id=%s org_id=%s status=%s findings=%d", audit_id, org_id, status, len(findings))
    record_audit(status, latency_ms)
    if audit.repo_id is not None:
        _post_check_run(audit_id, org_id, "failure" if status in {"FAILED", "ERROR"} else "success", summary)
