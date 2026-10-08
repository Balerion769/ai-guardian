"""Fetch immutable latest-commit diffs without persisting source or job credentials."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from uuid import UUID

import httpx
from sqlalchemy import select

from dashboard.api.github_webhooks import _language_from_diff
from dashboard.config import get_settings
from dashboard.db.models import Audit, OrgMember, Repository, User
from dashboard.db.session import SessionLocal, tenant_scope
from dashboard.security import decrypt_github_token
from dashboard.worker.audit_worker import process_audit
from scanner.static_rules import get_added_lines

logger = logging.getLogger(__name__)


def mark_failed(audit_id: str, org_id: str, summary: str) -> None:
    """Persist a safe terminal error so the progress page cannot poll indefinitely."""
    with SessionLocal.begin() as db:
        tenant_scope(db, org_id)
        audit = db.scalar(select(Audit).where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
        if audit is not None:
            audit.status = "ERROR"
            audit.summary = summary
            audit.completed_at = datetime.now(timezone.utc)


def fetch_commit_diff(full_name: str, sha: str, credential: str) -> str:
    """Stream a GitHub diff with strict transport and scanner size bounds."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name) or not re.fullmatch(r"[a-fA-F0-9]{40}", sha):
        raise ValueError("Invalid commit context")
    url = f"{get_settings().github_api_url.rstrip('/')}/repos/{full_name}/commits/{sha}"
    chunks: list[bytes] = []
    size = 0
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        with client.stream("GET", url, headers={"Authorization": f"Bearer {decrypt_github_token(credential)}",
                           "Accept": "application/vnd.github.diff"}) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 200_000:
                    raise ValueError("Commit diff exceeds 200,000 bytes; use smaller commits.")
                chunks.append(chunk)
    diff = b"".join(chunks).decode("utf-8", errors="strict")
    if len(get_added_lines(diff)) > 2000:
        raise ValueError("Commit diff exceeds 2,000 added lines; use smaller commits.")
    return diff


def fetch_and_process_repository_audit(audit_id: str, org_id: str, user_id: str) -> None:
    """Recheck access, download the pinned commit, then run the shared scanner."""
    try:
        with SessionLocal.begin() as db:
            tenant_scope(db, org_id)
            audit = db.scalar(select(Audit).where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
            if audit is None or audit.status != "QUEUED":
                return
            member = db.scalar(select(OrgMember).where(OrgMember.org_id == UUID(org_id), OrgMember.user_id == UUID(user_id)))
            user = db.get(User, UUID(user_id))
            repo = db.scalar(select(Repository).where(Repository.id == audit.repo_id, Repository.org_id == UUID(org_id)))
            if member is None or user is None or not user.github_token_ciphertext or repo is None or not repo.is_active:
                raise PermissionError("Repository access is no longer available")
            full_name, sha, credential = repo.github_repo_full_name, audit.commit_sha, user.github_token_ciphertext
        diff = fetch_commit_diff(full_name, sha or "", credential)
        with SessionLocal.begin() as db:
            tenant_scope(db, org_id)
            audit = db.scalar(select(Audit).where(Audit.id == UUID(audit_id), Audit.org_id == UUID(org_id)))
            if audit is None:
                return
            audit.diff_size = len(diff)
        process_audit(audit_id, org_id, diff, _language_from_diff(diff))
    except Exception as exc:
        logger.warning("manual_audit_failed audit_id=%s org_id=%s error_type=%s", audit_id, org_id, type(exc).__name__)
        summary = "Commit audit failed. Check GitHub access and retry."
        if isinstance(exc, ValueError) and str(exc).startswith("Commit diff exceeds"):
            summary = str(exc)
        mark_failed(audit_id, org_id, summary)
