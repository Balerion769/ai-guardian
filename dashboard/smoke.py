"""Opt-in local Compose smoke test for hosted API, worker, stats, and RLS."""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from uuid import UUID, uuid4

import httpx
from itsdangerous import TimestampSigner
from sqlalchemy import delete, select, text

from dashboard.config import get_settings
from dashboard.db.models import ApiKey, Audit, Finding, OrgMember, Organization, User
from dashboard.db.session import SessionLocal, tenant_scope


logger = logging.getLogger(__name__)


def _session_cookie(user_id: UUID, secret: str) -> str:
    """Create a development-only authenticated cookie for route verification."""
    data = base64.b64encode(json.dumps({"user_id": str(user_id)}).encode())
    return TimestampSigner(secret).sign(data).decode()


def run_smoke() -> None:
    """Exercise the actual HTTP process, queue worker, database, and tenant policies."""
    settings = get_settings()
    if not settings.dev_mode:
        raise RuntimeError("The smoke seed is allowed only with DASHBOARD_DEV_MODE=1")
    with SessionLocal.begin() as session:
        user = User(github_id=secrets.randbelow(2_000_000_000) + 5_000_000_000, login="aiguardian-smoke")
        session.add(user)
        session.flush()
        user_id = user.id
    org_id: UUID | None = None
    audit_id: UUID | None = None
    try:
        cookie = _session_cookie(user_id, settings.session_secret)
        with httpx.Client(base_url="http://127.0.0.1:8000", cookies={"session": cookie}, timeout=15.0) as client:
            org_response = client.post("/api/v1/orgs", json={"name": "AIGuardian smoke"})
            org_response.raise_for_status()
            org_id = UUID(org_response.json()["id"])
            key_response = client.post(f"/api/v1/orgs/{org_id}/api-keys", json={"name": "smoke key"})
            key_response.raise_for_status()
            raw_key = key_response.json()["key"]
            submit_response = client.post(
                "/api/v1/audit",
                headers={"X-API-Key": raw_key},
                json={"diff_content": "user_input = input()\neval(user_input)", "language": "python"},
            )
            submit_response.raise_for_status()
            audit_id = UUID(submit_response.json()["audit_id"])
            deadline = time.monotonic() + 30
            result = submit_response.json()
            while result["status"] in {"QUEUED", "RUNNING"} and time.monotonic() < deadline:
                time.sleep(0.2)
                detail = client.get(f"/api/v1/orgs/{org_id}/audits/{audit_id}")
                detail.raise_for_status()
                result = detail.json()
            if result["status"] != "FAILED" or result["risk_score"] < 40 or result["total_findings"] < 1:
                raise AssertionError("Hosted worker did not persist a high-risk audit")
            stats = client.get(f"/api/v1/orgs/{org_id}/stats")
            stats.raise_for_status()
            if not stats.json()["risk_over_time"] or not stats.json()["findings_by_category"]:
                raise AssertionError("Hosted stats did not include the completed audit")
            fixed_response = client.patch(
                f"/api/v1/orgs/{org_id}/findings/{result['findings'][0]['id']}"
            )
            fixed_response.raise_for_status()
            if client.get(f"/api/v1/orgs/{org_id}/stats").json()["mttr_hours"] is None:
                raise AssertionError("Hosted MTTR did not include the fixed finding")
            if client.get("/api/v1/orgs").status_code != 200:
                raise AssertionError("Organization listing failed")

        with SessionLocal.begin() as session:
            current_role = session.execute(text("SELECT current_user")).scalar_one()
            if current_role != "aiguardian_app":
                raise AssertionError("Runtime database role does not enforce tenant RLS")
            if session.scalar(select(Audit.id).where(Audit.id == audit_id)) is not None:
                raise AssertionError("Audit visible without tenant context")
        with SessionLocal.begin() as session:
            tenant_scope(session, org_id)
            if session.scalar(select(Audit.id).where(Audit.id == audit_id)) != audit_id:
                raise AssertionError("Audit missing inside its tenant context")
        with SessionLocal.begin() as session:
            tenant_scope(session, uuid4())
            if session.scalar(select(Audit.id).where(Audit.id == audit_id)) is not None:
                raise AssertionError("Audit visible in another tenant context")
        logger.info("hosted_smoke_pass status=%s risk_score=%d findings=%d rls=isolated", result["status"], result["risk_score"], result["total_findings"])
    finally:
        # Test credentials and audit data are removed in dependency order.
        if org_id is not None:
            with SessionLocal.begin() as session:
                tenant_scope(session, org_id)
                session.execute(delete(Finding).where(Finding.org_id == org_id))
                session.execute(delete(Audit).where(Audit.org_id == org_id))
                session.execute(delete(ApiKey).where(ApiKey.org_id == org_id))
                session.execute(delete(OrgMember).where(OrgMember.org_id == org_id))
                session.execute(delete(Organization).where(Organization.id == org_id))
        with SessionLocal.begin() as session:
            session.execute(delete(User).where(User.id == user_id))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    run_smoke()
