"""Verified GitHub App pull request webhook integration."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool
from redis import Redis
from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from dashboard.config import get_settings
from dashboard.db.models import Audit, Organization, Repository, User
from dashboard.db.session import SessionLocal, get_db, tenant_scope
from dashboard.github_app import installation_token, pull_request_diff
from dashboard.api.billing_middleware import enforce_audit_access

logger = logging.getLogger(__name__)
github_webhook_router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])
_DIFF_FILE = re.compile(r"^diff --git a/(.+?) b/(.+?)$", re.MULTILINE)
_LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
}


def verify_signature(body: bytes, signature: str | None, secret: str) -> bool:
    """Verify GitHub's HMAC-SHA256 delivery signature in constant time."""
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _language_from_diff(diff: str) -> str:
    """Select the first supported language represented in the patch."""
    for match in _DIFF_FILE.finditer(diff):
        path = match.group(2).lower()
        for extension, language in _LANGUAGES.items():
            if path.endswith(extension):
                return language
    return "text"


def _repository_path(payload: dict) -> str:
    repository = payload.get("repository")
    full_name = repository.get("full_name") if isinstance(repository, dict) else None
    if not isinstance(full_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid repository in webhook")
    return full_name


@github_webhook_router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def receive_github_webhook(request: Request, background_tasks: BackgroundTasks,
                                 db: Session = Depends(get_db)) -> dict[str, str]:
    """Read bounded raw bytes before JSON parsing so GitHub signatures remain valid."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 2_000_000:
            raise HTTPException(413, "GitHub webhook payload exceeds size limit")
        chunks.append(chunk)
    return await run_in_threadpool(github_webhook, request, b"".join(chunks), db, background_tasks)


def github_webhook(request: Request, body: bytes, db: Session,
                   background_tasks: BackgroundTasks) -> dict[str, str]:
    """Queue a PR audit after authenticating and fetching its GitHub diff."""
    settings = get_settings()
    if not verify_signature(body, request.headers.get("x-hub-signature-256"), settings.github_app_webhook_secret):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid GitHub webhook signature")
    event = request.headers.get("x-github-event", "")
    if event != "pull_request":
        return {"status": "ignored"}
    try:
        parsed = json.loads(body)
        payload = parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, TypeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid GitHub webhook JSON") from exc
    if payload is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid GitHub webhook JSON")
    action = payload.get("action")
    if action not in {"opened", "synchronize"}:
        return {"status": "ignored"}
    pull_request = payload.get("pull_request")
    installation = payload.get("installation")
    if not isinstance(pull_request, dict) or not isinstance(installation, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing pull request installation data")
    try:
        pr_number = int(pull_request["number"])
        commit_sha = str(pull_request["head"]["sha"])
        branch = str(pull_request["head"]["ref"])
        installation_id = int(installation["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid pull request metadata") from exc
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid pull request commit")
    full_name = _repository_path(payload)
    owner = full_name.split("/", 1)[0]
    organization = db.scalar(select(Organization).where(
        Organization.github_installation_id == installation_id).with_for_update())
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub installation is not connected")
    expected_owner = organization.github_slug or db.get(User, organization.owner_id).login
    if owner.casefold() != expected_owner.casefold():
        raise HTTPException(403, "Repository owner differs from installation account")
    tenant_scope(db, organization.id)
    repository = db.scalar(select(Repository).where(
        Repository.org_id == organization.id,
        Repository.github_repo_full_name.ilike(full_name),
    ))
    if repository is None:
        return {"status": "ignored", "reason": "Repository is not linked"}
    if not repository.is_active:
        return {"status": "ignored", "reason": "Repository is inactive"}
    enforce_audit_access(db, organization)
    if settings.static_only_mode:
        audit = Audit(
            org_id=organization.id, repo_id=repository.id, pr_number=pr_number,
            commit_sha=commit_sha, branch=branch[:255], triggered_by=organization.owner_id,
            status="QUEUED", risk_score=0, total_findings=0, high_count=0,
            medium_count=0, low_count=0, diff_size=0, latency_ms=0.0,
            model_used="static-only", summary="GitHub audit accepted for analysis.",
        )
        db.add(audit)
        db.flush()
        audit_id, org_id = str(audit.id), str(organization.id)
        db.commit()
        background_tasks.add_task(_fetch_and_process_github_audit, audit_id, org_id,
                                  installation_id, full_name, pr_number)
        return {"status": "accepted", "audit_id": audit_id}
    try:
        token = installation_token(settings, installation_id)
        diff = pull_request_diff(settings, token, full_name, pr_number)
    except ValueError as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc)) from exc
    except Exception as exc:
        logger.warning("github_diff_fetch_failed org_id=%s repo=%s pr=%d error_type=%s",
                       organization.id, full_name, pr_number, type(exc).__name__)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub diff unavailable") from exc
    audit = Audit(
        org_id=organization.id,
        repo_id=repository.id,
        pr_number=pr_number,
        commit_sha=commit_sha,
        branch=branch[:255],
        triggered_by=organization.owner_id,
        status="QUEUED",
        risk_score=0,
        total_findings=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        diff_size=len(diff.encode("utf-8")),
        latency_ms=0.0,
        model_used=settings.ollama_model,
        summary="Audit queued for analysis.",
    )
    db.add(audit)
    db.flush()
    try:
        queue = Queue("audits", connection=Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2))
        queue.enqueue(
            "dashboard.worker.audit_worker.process_audit",
            args=(str(audit.id), str(organization.id), diff, _language_from_diff(diff)),
            job_id=str(audit.id), job_timeout=120, ttl=3600, result_ttl=0, failure_ttl=0,
            description=f"github pull request audit {audit.id}",
        )
    except Exception as exc:
        audit.status = "ERROR"
        audit.summary = "Audit queue unavailable; retry the webhook."
        db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Audit queue unavailable") from exc
    db.commit()
    logger.info("github_audit_queued org_id=%s repo=%s pr=%d audit_id=%s diff_bytes=%d",
                organization.id, full_name, pr_number, audit.id, len(diff.encode("utf-8")))
    return {"status": "queued", "audit_id": str(audit.id)}


def _fetch_and_process_github_audit(audit_id: str, org_id: str, installation_id: int,
                                   full_name: str, pr_number: int) -> None:
    """Fetch and scan after acknowledging GitHub, using independent transactions."""
    from uuid import UUID
    from dashboard.worker.audit_worker import process_audit
    try:
        settings = get_settings()
        token = installation_token(settings, installation_id)
        diff = pull_request_diff(settings, token, full_name, pr_number)
        with SessionLocal.begin() as db:
            tenant_scope(db, org_id)
            audit = db.scalar(select(Audit).where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
            if audit is None:
                return
            audit.diff_size = len(diff.encode("utf-8"))
        process_audit(audit_id, org_id, diff, _language_from_diff(diff))
    except Exception as exc:
        logger.warning("github_background_audit_failed org_id=%s audit_id=%s error_type=%s",
                       org_id, audit_id, type(exc).__name__)
        with SessionLocal.begin() as db:
            tenant_scope(db, org_id)
            audit = db.scalar(select(Audit).where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
            if audit is not None:
                audit.status = "ERROR"
                audit.summary = "GitHub diff fetch or audit failed; retry the PR event."
                audit.completed_at = datetime.now(timezone.utc)
