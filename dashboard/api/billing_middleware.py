"""Tenant aware billing admission checks shared by hosted audit routes."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dashboard.db.models import Audit, Organization, OrgMember


PLAN_LIMITS: dict[str, int | None] = {"free": 100, "pro": 1000, "team": None}


def audits_today(db: Session, org_id) -> int:
    """Count attempts reserved since the beginning of the UTC day."""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return db.scalar(select(func.count(Audit.id)).where(Audit.org_id == org_id, Audit.created_at >= today)) or 0


def enforce_audit_access(db: Session, org: Organization) -> None:
    """Run after locking the organization row to serialize quota reservations."""
    if org.billing_status == "past_due":
        raise HTTPException(status_code=402, detail="Billing is past due; update your payment method")
    if org.plan in {"pro", "team"} and org.stripe_subscription_id:
        members = db.scalar(select(func.count(OrgMember.id)).where(OrgMember.org_id == org.id)) or 0
        if members > org.seat_count:
            raise HTTPException(status_code=402, detail="Increase billed seats to cover organization members")
    limit = PLAN_LIMITS.get(org.plan)
    if org.plan not in PLAN_LIMITS:
        raise HTTPException(status_code=503, detail="Organization plan unavailable")
    if limit is not None and audits_today(db, org.id) >= limit:
        message = "Free limit reached, upgrade" if org.plan == "free" else "Daily Pro audit limit reached"
        raise HTTPException(status_code=429, detail=message)
