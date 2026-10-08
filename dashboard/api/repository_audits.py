"""Session-authenticated latest-commit audits for linked repositories."""

from __future__ import annotations

import re
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from redis import Redis
from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from dashboard.api.billing_middleware import enforce_audit_access
from dashboard.api.orgs import _github_get
from dashboard.config import get_settings
from dashboard.db.models import Audit, Organization, Repository, User
from dashboard.db.session import get_db, tenant_scope
from dashboard.security import require_org_member, require_user
from dashboard.worker.repository_audit_worker import fetch_and_process_repository_audit, mark_failed

router = APIRouter(prefix="/api/v1/orgs", tags=["repository audits"])


class BranchAuditRequest(BaseModel):
    """Select a Git ref without accepting source text or credentials."""

    model_config = ConfigDict(strict=True, extra="forbid")
    branch: str = Field(min_length=1, max_length=255)

    @field_validator("branch")
    @classmethod
    def valid_ref(cls, value: str) -> str:
        """Reject Git's forbidden ref characters and ambiguous path components."""
        if (re.search(r"[\s\x00-\x1f\x7f~^:?*\[\\]", value)
                or ".." in value or "@{" in value or "//" in value
                or value == "@" or value.startswith("/") or value.endswith(("/", "."))
                or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))):
            raise ValueError("Invalid Git branch name")
        return value


def _repository(db: Session, request: Request, org_id: UUID, repo_id: UUID) -> tuple[User, Repository]:
    """Authorize membership before reading a tenant-scoped active repository."""
    user = require_user(request, db)
    require_org_member(org_id, user, db)
    tenant_scope(db, org_id)
    repo = db.scalar(select(Repository).where(Repository.id == repo_id, Repository.org_id == org_id))
    if repo is None:
        raise HTTPException(404, "Repository not found")
    if not repo.is_active:
        raise HTTPException(409, "Repository is inactive")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo.github_repo_full_name):
        raise HTTPException(409, "Invalid linked repository")
    return user, repo


@router.get("/{org_id}/repos/{repo_id}/branches")
async def list_branches(org_id: UUID, repo_id: UUID, request: Request,
                        page: int = Query(default=1, ge=1, le=10000),
                        db: Session = Depends(get_db)) -> dict:
    """List a bounded GitHub branch page using the current user's live access."""
    user, repo = _repository(db, request, org_id, repo_id)
    data = await _github_get(user, f"repos/{repo.github_repo_full_name}/branches?per_page=100&page={page}")
    if not isinstance(data, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in data):
        raise HTTPException(503, "Invalid GitHub branch response")
    return {"items": [{"name": item["name"]} for item in data],
            "next_page": page + 1 if len(data) == 100 else None}


@router.post("/{org_id}/repos/{repo_id}/audits", status_code=202)
async def start_repository_audit(org_id: UUID, repo_id: UUID, payload: BranchAuditRequest,
                                 request: Request, background_tasks: BackgroundTasks,
                                 db: Session = Depends(get_db)) -> dict[str, str]:
    """Pin the branch's latest commit, reserve quota, and schedule its diff audit."""
    user, repo = _repository(db, request, org_id, repo_id)
    data = await _github_get(user, f"repos/{repo.github_repo_full_name}/branches/{quote(payload.branch, safe='')}")
    commit = data.get("commit") if isinstance(data, dict) else None
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", sha):
        raise HTTPException(503, "GitHub did not return a valid branch commit")
    organization = db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
    if organization is None:
        raise HTTPException(404, "Organization not found")
    enforce_audit_access(db, organization)
    settings = get_settings()
    audit = Audit(org_id=org_id, repo_id=repo_id, commit_sha=sha, branch=payload.branch,
                  triggered_by=user.id, status="QUEUED", risk_score=0, latency_ms=0,
                  model_used="static-only" if settings.static_only_mode else settings.ollama_model,
                  summary="Latest commit audit accepted; analysis is pending.")
    db.add(audit)
    db.flush()
    audit_id, user_id = str(audit.id), str(user.id)
    db.commit()
    args = (audit_id, str(org_id), user_id)
    if settings.inline_audits or settings.static_only_mode:
        background_tasks.add_task(fetch_and_process_repository_audit, *args)
    else:
        try:
            queue = Queue("audits", connection=Redis.from_url(settings.redis_url,
                          socket_connect_timeout=2, socket_timeout=2))
            queue.enqueue(fetch_and_process_repository_audit, args=args, job_timeout=120)
        except Exception as exc:
            mark_failed(audit_id, str(org_id), "Audit queue unavailable. Please retry.")
            raise HTTPException(503, "Audit queue unavailable. Please retry.") from exc
    return {"audit_id": audit_id, "status": "QUEUED", "commit_sha": sha, "branch": payload.branch}
