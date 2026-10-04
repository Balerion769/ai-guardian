"""Remove audit metadata and findings after each organization's retention window."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete, select

from dashboard.db.models import Audit, Finding, Organization
from dashboard.db.session import SessionLocal, tenant_scope


logger = logging.getLogger(__name__)
RETENTION_DAYS = {"free": 7, "pro": 7, "team": 90}


def prune_org_audits(org_id: UUID, days: int, *, now: datetime | None = None) -> int:
    """Delete old audits and their findings within one tenant transaction."""
    if days < 1:
        raise ValueError("Retention window must be positive")
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    with SessionLocal.begin() as db:
        tenant_scope(db, org_id)
        expired = select(Audit.id).where(Audit.org_id == org_id, Audit.created_at < cutoff)
        db.execute(delete(Finding).where(Finding.org_id == org_id, Finding.audit_id.in_(expired)))
        result = db.execute(delete(Audit).where(Audit.org_id == org_id, Audit.created_at < cutoff))
        return result.rowcount or 0


def run_once() -> int:
    """Prune all organizations, keeping tenant boundaries for each delete."""
    with SessionLocal() as db:
        organizations = list(db.execute(select(Organization.id, Organization.plan)).all())
    removed = 0
    for org_id, plan in organizations:
        removed += prune_org_audits(org_id, RETENTION_DAYS[plan])
    logger.info("billing_retention_completed organizations=%d audits_removed=%d", len(organizations), removed)
    return removed


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error("billing_retention_failed error_type=%s", type(exc).__name__)
        time.sleep(3600)
