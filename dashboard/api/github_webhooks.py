"""Verified GitHub App pull request webhook integration."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from redis import Redis
from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from dashboard.config import get_settings
from dashboard.db.models import Audit, Organization, Repository
from dashboard.db.session import get_db, tenant_scope
from dashboard.github_app import installation_token, pull_request_diff

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
def github_webhook(request: Request, body: bytes = Body(...), db: Session = Depends(get_db)) -> dict[str, str]:
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
    organization = db.scalar(select(Organization).where(Organization.github_slug.ilike(owner)).with_for_update())
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "GitHub organization is not linked")
    organization.github_installation_id = installation_id
    organization.github_app_installed_at = datetime.now(timezone.utc)
    tenant_scope(db, organization.id)
    repository = db.scalar(select(Repository).where(
        Repository.org_id == organization.id,
        Repository.github_repo_full_name.ilike(full_name),
    ))
    if repository is None:
        repository = Repository(org_id=organization.id, github_repo_full_name=full_name)
        db.add(repository)
        db.flush()
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
