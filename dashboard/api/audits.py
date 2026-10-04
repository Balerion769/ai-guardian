"""Tenant-scoped audit submission, history, findings, and risk statistics."""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
import httpx
from pydantic import BaseModel, ConfigDict, Field
from redis import Redis
from rq import Queue
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dashboard.config import get_settings
from dashboard.api.billing_middleware import PLAN_LIMITS, enforce_audit_access
from dashboard.db.models import Audit, Finding, Organization, Repository
from dashboard.db.session import SessionLocal, get_db, tenant_scope
from dashboard.security import authenticate_api_key, decrypt_github_token, require_org_member, require_user
from scanner.models import AuditRequest
from scanner.static_rules import get_added_lines


logger = logging.getLogger(__name__)
router = APIRouter()
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class HostedAuditRequest(AuditRequest):
    """Existing scanner input plus optional repository and PR context."""

    repo_id: UUID | None = Field(default=None, strict=False)
    pr_number: int | None = Field(default=None, ge=1)
    commit_sha: str | None = Field(default=None, min_length=40, max_length=40, pattern=r"^[0-9a-fA-F]{40}$")
    branch: str | None = Field(default=None, min_length=1, max_length=255)


class FindingView(BaseModel):
    """Persisted finding, including state used for time-to-remediation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    severity: str
    category: str
    description: str
    remediation: str
    file_path: str | None
    line_number: int | None
    line_reference: str
    confidence: float
    is_fixed: bool
    fixed_at: datetime | None


class AuditView(BaseModel):
    """One tenant-visible audit without source text."""

    model_config = ConfigDict(from_attributes=True)

    audit_id: UUID
    org_id: UUID
    repo_id: UUID | None
    pr_number: int | None
    commit_sha: str | None
    branch: str | None
    status: str
    risk_score: int
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    diff_size: int
    latency_ms: float
    model_used: str | None
    summary: str
    created_at: datetime
    findings: list[FindingView]


class AuditList(BaseModel):
    """A bounded page of audit metadata."""

    items: list[AuditView]
    total: int


class DailyRisk(BaseModel):
    """Mean completed audit score for one UTC date."""

    date: str
    average_risk_score: float
    audit_count: int


class CategoryCount(BaseModel):
    """Finding count for a normalized category."""

    category: str
    count: int


class VulnerableRepo(BaseModel):
    """Repository ranked by retained high-severity findings."""

    repo_id: UUID
    github_repo_full_name: str
    high_findings: int
    audit_count: int


class StatsView(BaseModel):
    """Organization risk trends and mean time to remediation in hours."""

    risk_over_time: list[DailyRisk]
    findings_by_category: list[CategoryCount]
    top_vulnerable_repos: list[VulnerableRepo]
    mttr_hours: float | None


def _as_view(audit: Audit, findings: list[Finding]) -> AuditView:
    """Convert one ORM row and its findings to the public response schema."""
    return AuditView(
        audit_id=audit.id, org_id=audit.org_id, repo_id=audit.repo_id,
        pr_number=audit.pr_number, commit_sha=audit.commit_sha, branch=audit.branch,
        status=audit.status, risk_score=audit.risk_score,
        total_findings=audit.total_findings, high_count=audit.high_count,
        medium_count=audit.medium_count, low_count=audit.low_count,
        diff_size=audit.diff_size, latency_ms=audit.latency_ms,
        model_used=audit.model_used, summary=audit.summary,
        created_at=audit.created_at,
        findings=[FindingView.model_validate(finding) for finding in findings],
    )


def _read_audit(org_id: UUID, audit_id: UUID) -> AuditView:
    """Read one completed or queued audit using PostgreSQL tenant context."""
    with SessionLocal() as session:
        with session.begin():
            tenant_scope(session, org_id)
            audit = session.scalar(select(Audit).where(Audit.id == audit_id, Audit.org_id == org_id))
            if audit is None:
                raise HTTPException(status_code=404, detail="Audit not found")
            findings = list(session.scalars(select(Finding).where(Finding.audit_id == audit_id).order_by(Finding.created_at, Finding.id)))
            return _as_view(audit, findings)


@router.post("/api/v1/audit", response_model=AuditView, status_code=202)
def submit_audit(
    payload: HostedAuditRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    session: Session = Depends(get_db),
) -> AuditView:
    """Authenticate a key, reserve quota, enqueue work, and optionally return fast findings."""
    if len(get_added_lines(payload.diff_content)) > 2000:
        raise HTTPException(status_code=413, detail="Audit input exceeds 2000 added lines")
    key = authenticate_api_key(x_api_key or "", session)
    org_id = key.org_id
    session.commit()  # Persist last-used metadata before the quota transaction.
    with session.begin():
        tenant_scope(session, org_id)
        organization = session.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
        if organization is None:
            raise HTTPException(status_code=404, detail="Organization not found")
        enforce_audit_access(session, organization)
        if payload.repo_id is not None:
            repository = session.scalar(select(Repository).where(
                Repository.id == payload.repo_id, Repository.org_id == org_id, Repository.is_active.is_(True)))
            if repository is None:
                raise HTTPException(status_code=404, detail="Repository not found")
        audit = Audit(
            org_id=org_id, repo_id=payload.repo_id, pr_number=payload.pr_number,
            commit_sha=payload.commit_sha, branch=payload.branch, triggered_by=key.created_by,
            status="QUEUED", risk_score=0, total_findings=0, high_count=0,
            medium_count=0, low_count=0, diff_size=len(payload.diff_content.encode("utf-8")),
            latency_ms=0.0, model_used=get_settings().ollama_model,
            summary="Audit queued for analysis.",
        )
        session.add(audit)
        session.flush()
        audit_id = audit.id
    settings = get_settings()
    try:
        connection = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        queue = Queue("audits", connection=connection)
        queue.enqueue(
            "dashboard.worker.audit_worker.process_audit",
            args=(str(audit_id), str(org_id), payload.diff_content, payload.language),
            job_id=str(audit_id), job_timeout=120, ttl=3600,
            result_ttl=0, failure_ttl=0, description=f"audit {audit_id}",
        )
    except Exception as exc:
        with SessionLocal() as failed_session:
            with failed_session.begin():
                tenant_scope(failed_session, org_id)
                record = failed_session.get(Audit, audit_id)
                if record is not None:
                    record.status = "ERROR"
                    record.summary = "Audit queue unavailable; retry submission."
        logger.error("audit_enqueue_failed org_id=%s audit_id=%s error_type=%s", org_id, audit_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="Audit queue unavailable; retry submission") from exc

    deadline = time.monotonic() + 2.0
    while True:
        current = _read_audit(org_id, audit_id)
        if current.status in {"PASSED", "FAILED", "ERROR"} or time.monotonic() >= deadline:
            return current
        time.sleep(0.05)


@router.get("/api/v1/orgs/{org_id}/audits", response_model=AuditList)
def list_audits(
    org_id: UUID, request: Request,
    repo_id: UUID | None = None,
    severity: str | None = Query(default=None, pattern=r"^(HIGH|MEDIUM|LOW)$"),
    time_range: str = Query(default="7d", pattern=r"^(7d|30d|90d)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_db),
) -> AuditList:
    """List audits after membership and row-security checks."""
    user = require_user(request, session)
    require_org_member(org_id, user, session)
    tenant_scope(session, org_id)
    since = datetime.now(timezone.utc) - timedelta(days=int(time_range[:-1]))
    conditions = [Audit.org_id == org_id, Audit.created_at >= since]
    if repo_id is not None:
        conditions.append(Audit.repo_id == repo_id)
    if severity is not None:
        conditions.append(select(Finding.id).where(
            Finding.audit_id == Audit.id, Finding.severity == severity).exists())
    total = session.scalar(select(func.count(Audit.id)).where(*conditions)) or 0
    audits = list(session.scalars(select(Audit).where(*conditions).order_by(Audit.created_at.desc(), Audit.id.desc()).limit(limit).offset(offset)))
    items = []
    for audit in audits:
        findings = list(session.scalars(select(Finding).where(Finding.audit_id == audit.id).order_by(Finding.created_at, Finding.id)))
        items.append(_as_view(audit, findings))
    return AuditList(items=items, total=total)


@router.get("/api/v1/orgs/{org_id}/audits/{audit_id}", response_model=AuditView)
def get_audit(org_id: UUID, audit_id: UUID, request: Request, session: Session = Depends(get_db)) -> AuditView:
    """Return an audit only when the caller belongs to its organization."""
    user = require_user(request, session)
    require_org_member(org_id, user, session)
    tenant_scope(session, org_id)
    audit = session.scalar(select(Audit).where(Audit.id == audit_id, Audit.org_id == org_id))
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    findings = list(session.scalars(select(Finding).where(Finding.audit_id == audit_id).order_by(Finding.created_at, Finding.id)))
    return _as_view(audit, findings)


@router.get("/api/v1/orgs/{org_id}/audits/{audit_id}/diff")
async def get_audit_diff(org_id: UUID, audit_id: UUID, request: Request,
                         session: Session = Depends(get_db)) -> Response:
    """Fetch a linked PR or commit diff from GitHub without retaining source."""
    user = require_user(request, session)
    require_org_member(org_id, user, session)
    tenant_scope(session, org_id)
    audit = session.scalar(select(Audit).where(Audit.id == audit_id, Audit.org_id == org_id))
    if audit is None or audit.repo_id is None:
        raise HTTPException(status_code=404, detail="Linked GitHub diff unavailable")
    repository = session.scalar(select(Repository).where(
        Repository.id == audit.repo_id, Repository.org_id == org_id))
    if repository is None or not _REPOSITORY_NAME.fullmatch(repository.github_repo_full_name):
        raise HTTPException(status_code=404, detail="Linked GitHub diff unavailable")
    if audit.pr_number is not None:
        suffix = f"pulls/{audit.pr_number}"
    elif audit.commit_sha is not None and re.fullmatch(r"[0-9a-fA-F]{40}", audit.commit_sha):
        suffix = f"commits/{audit.commit_sha}"
    else:
        raise HTTPException(status_code=404, detail="Linked GitHub diff unavailable")
    if not user.github_token_ciphertext:
        raise HTTPException(status_code=401, detail="GitHub sign-in required")
    token = decrypt_github_token(user.github_token_ciphertext)
    url = f"{get_settings().github_api_url.rstrip('/')}/repos/{repository.github_repo_full_name}/{suffix}"
    chunks: list[bytes] = []
    size = 0
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            async with client.stream("GET", url, headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3.diff",
            }) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 200_000:
                        raise HTTPException(status_code=413, detail="GitHub diff exceeds display limit")
                    chunks.append(chunk)
    except httpx.HTTPError as exc:
        logger.warning("github_diff_failed org_id=%s audit_id=%s error_type=%s",
                       org_id, audit_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail="GitHub diff unavailable") from exc
    return Response(content=b"".join(chunks), media_type="text/plain; charset=utf-8",
                    headers={"Cache-Control": "no-store"})


@router.get("/api/v1/orgs/{org_id}/stats", response_model=StatsView)
def get_stats(org_id: UUID, request: Request, session: Session = Depends(get_db)) -> StatsView:
    """Aggregate risk, categories, repository exposure, and remediation time."""
    user = require_user(request, session)
    require_org_member(org_id, user, session)
    tenant_scope(session, org_id)
    day = (func.date(func.timezone("UTC", Audit.created_at))
           if session.get_bind().dialect.name == "postgresql"
           else func.date(Audit.created_at))
    daily_rows = session.execute(
        select(day, func.avg(Audit.risk_score), func.count(Audit.id))
        .where(Audit.org_id == org_id, Audit.status.in_(("PASSED", "FAILED")))
        .group_by(day).order_by(day)
    ).all()
    category_rows = session.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.org_id == org_id)
        .group_by(Finding.category)
        .order_by(func.count(Finding.id).desc(), Finding.category)
    ).all()
    high_sum = func.sum(Audit.high_count)
    repository_rows = session.execute(
        select(Repository.id, Repository.github_repo_full_name, high_sum, func.count(Audit.id))
        .join(Audit, Audit.repo_id == Repository.id)
        .where(Repository.org_id == org_id, Audit.org_id == org_id,
               Audit.status.in_(("PASSED", "FAILED")))
        .group_by(Repository.id, Repository.github_repo_full_name)
        .having(high_sum > 0)
        .order_by(high_sum.desc(), Repository.github_repo_full_name)
        .limit(10)
    ).all()
    if session.get_bind().dialect.name == "postgresql":
        mttr = session.scalar(select(func.avg(
            func.extract("epoch", Finding.fixed_at - Finding.created_at) / 3600.0
        )).where(Finding.org_id == org_id, Finding.fixed_at.is_not(None)))
        mttr_hours = round(float(mttr), 2) if mttr is not None else None
    else:
        fixed_rows = session.scalars(select(Finding).where(
            Finding.org_id == org_id, Finding.fixed_at.is_not(None)))
        hours = [(finding.fixed_at - finding.created_at).total_seconds() / 3600 for finding in fixed_rows]
        mttr_hours = round(sum(hours) / len(hours), 2) if hours else None
    return StatsView(
        risk_over_time=[DailyRisk(date=str(date), average_risk_score=round(float(average), 2), audit_count=count)
                        for date, average, count in daily_rows],
        findings_by_category=[CategoryCount(category=category, count=count)
                              for category, count in category_rows],
        top_vulnerable_repos=[VulnerableRepo(repo_id=repo_id, github_repo_full_name=name,
                                             high_findings=int(high_count), audit_count=count)
                              for repo_id, name, high_count, count in repository_rows],
        mttr_hours=mttr_hours,
    )


@router.patch("/api/v1/orgs/{org_id}/findings/{finding_id}", response_model=FindingView)
def mark_finding_fixed(org_id: UUID, finding_id: UUID, request: Request, session: Session = Depends(get_db)) -> FindingView:
    """Allow an organization admin to mark a finding remediated for MTTR."""
    user = require_user(request, session)
    require_org_member(org_id, user, session, minimum_role="admin")
    tenant_scope(session, org_id)
    finding = session.scalar(select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.fixed_at is None:
        finding.fixed_at = datetime.now(timezone.utc)
        finding.is_fixed = True
        session.commit()
    return FindingView.model_validate(finding)
