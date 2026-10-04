"""Organization billing routes and signature-verified Stripe webhooks."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Any, Literal
from uuid import UUID

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dashboard.api.billing_middleware import PLAN_LIMITS, audits_today
from dashboard.billing import stripe as stripe_service
from dashboard.config import get_settings
from dashboard.db.models import OrgMember, Organization, Repository, StripeEvent, User
from dashboard.db.session import get_db, tenant_scope
from dashboard.security import require_org_member, require_user


logger = logging.getLogger(__name__)
billing_router = APIRouter(tags=["billing"])


class PlanChange(BaseModel):
    """Paid plan selected by name, never by arbitrary Stripe Price ID."""

    model_config = ConfigDict(extra="forbid")
    plan: Literal["pro", "team"]


def _org_for_owner(org_id: UUID, request: Request, db: Session) -> tuple[Organization, User]:
    user = require_user(request, db)
    require_org_member(org_id, user, db, "owner")
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org, user


def _stripe_error(exc: Exception) -> HTTPException:
    logger.warning("stripe_request_failed error_type=%s", type(exc).__name__)
    return HTTPException(status_code=503, detail="Billing provider unavailable; try again")


@billing_router.get("/api/v1/orgs/{org_id}/billing")
def billing_summary(org_id: UUID, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return plan and today's usage to any member, including when past due."""
    user = require_user(request, db)
    require_org_member(org_id, user, db)
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    tenant_scope(db, org_id)
    return {"plan": org.plan, "billing_status": org.billing_status,
            "audits_today": audits_today(db, org_id), "daily_limit": PLAN_LIMITS[org.plan],
            "seat_count": org.seat_count, "features": stripe_service.PLANS[org.plan]["features"],
            "has_subscription": bool(org.stripe_subscription_id),
            "has_customer": bool(org.stripe_customer_id)}


@billing_router.post("/api/v1/orgs/{org_id}/billing/checkout")
def checkout(org_id: UUID, payload: PlanChange, request: Request,
             db: Session = Depends(get_db)) -> dict[str, Any]:
    """Only the owner can open Stripe Checkout for a configured plan."""
    org, user = _org_for_owner(org_id, request, db)
    settings = get_settings()
    if not settings.stripe_secret_key and settings.dev_mode:
        logger.warning("stripe_checkout_unconfigured org_id=%s", org_id)
        return {"url": None, "development": True}
    if not settings.stripe_secret_key or not stripe_service.price_for_plan(payload.plan):
        raise HTTPException(status_code=503, detail="Stripe billing is not configured")
    if org.stripe_subscription_id:
        raise HTTPException(status_code=409, detail="Manage your existing subscription in the billing portal")
    seats = db.scalar(select(func.count(OrgMember.id)).where(OrgMember.org_id == org_id)) or 1
    try:
        url = stripe_service.create_checkout(
            org_id=str(org_id), plan=payload.plan, seats=seats,
            customer_id=org.stripe_customer_id, email=user.email,
            return_url=f"{settings.web_base_url.rstrip('/')}/dashboard/settings",
        )
    except stripe.StripeError as exc:
        raise _stripe_error(exc) from exc
    return {"url": url, "development": False}


@billing_router.post("/api/v1/orgs/{org_id}/billing/portal")
def portal(org_id: UUID, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    """Only the owner can create a customer portal session."""
    org, _ = _org_for_owner(org_id, request, db)
    if not org.stripe_customer_id:
        raise HTTPException(status_code=409, detail="No Stripe customer exists for this organization")
    try:
        url = stripe_service.create_portal(
            org.stripe_customer_id, f"{get_settings().web_base_url.rstrip('/')}/dashboard/settings"
        )
    except (stripe.StripeError, ValueError) as exc:
        raise _stripe_error(exc) from exc
    return {"url": url}


@billing_router.get("/api/v1/orgs/{org_id}/billing/invoices")
def invoices(org_id: UUID, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """List the organization's invoices with no payment method details."""
    org, _ = _org_for_owner(org_id, request, db)
    if not org.stripe_customer_id:
        return {"items": []}
    try:
        return {"items": stripe_service.list_invoices(org.stripe_customer_id)}
    except (stripe.StripeError, ValueError) as exc:
        raise _stripe_error(exc) from exc


@billing_router.post("/api/v1/orgs/{org_id}/billing/dev-activate")
def dev_activate(org_id: UUID, payload: PlanChange, request: Request,
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    """Manually set a plan in local development when Stripe is unconfigured."""
    settings = get_settings()
    if not settings.dev_mode or settings.stripe_secret_key:
        raise HTTPException(status_code=404, detail="Resource unavailable")
    org, _ = _org_for_owner(org_id, request, db)
    org.plan = payload.plan
    org.billing_status = "active"
    org.daily_limit = PLAN_LIMITS[payload.plan] or 2_147_483_647
    db.commit()
    logger.warning("billing_dev_plan_activated org_id=%s plan=%s", org_id, payload.plan)
    return {"plan": org.plan, "development": True}


def _price_and_seats(subscription: dict[str, Any]) -> tuple[str | None, int]:
    items = subscription.get("items", {}).get("data", [])
    if len(items) != 1 or not isinstance(items[0], dict):
        return None, 1
    return stripe_service.plan_for_price(str(items[0].get("price", {}).get("id") or "")), max(1, int(items[0].get("quantity") or 1))


def _subscription_id(obj: dict[str, Any], event_type: str) -> str:
    """Read both legacy and current invoice subscription references."""
    direct = obj.get("subscription")
    if not direct and event_type.startswith("invoice."):
        direct = ((obj.get("parent") or {}).get("subscription_details") or {}).get("subscription")
    if not direct and event_type.startswith("customer.subscription."):
        direct = obj.get("id")
    return str(direct or "")


def _send_payment_failure_email(owner: User | None, org: Organization) -> None:
    settings = get_settings()
    if not owner or not owner.email or not settings.smtp_host or not settings.billing_email_from:
        logger.warning("billing_owner_email_unavailable org_id=%s", org.id)
        return
    message = EmailMessage()
    message["From"] = settings.billing_email_from
    message["To"] = owner.email
    message["Subject"] = "AI Guardian payment needs attention"
    message.set_content(f"Payment for {org.name} failed. Sign in to AI Guardian and update billing in Settings.")
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        logger.error("billing_owner_email_failed org_id=%s error_type=%s", org.id, type(exc).__name__)


@billing_router.post("/api/v1/webhooks/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)) -> dict[str, bool]:
    """Verify, deduplicate, and apply supported Stripe subscription events."""
    settings = get_settings()
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Stripe webhook is not configured")
    body_chunks: list[bytes] = []
    body_size = 0
    async for chunk in request.stream():
        body_size += len(chunk)
        if body_size > 256_000:
            raise HTTPException(status_code=413, detail="Webhook too large")
        body_chunks.append(chunk)
    body = b"".join(body_chunks)
    try:
        event = stripe.Webhook.construct_event(body, request.headers.get("stripe-signature", ""),
                                                settings.stripe_webhook_secret)
    except (ValueError, stripe.SignatureVerificationError) as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature") from exc
    event_type = str(event.get("type") or "")
    event_id = str(event.get("id") or "")
    if not event_id or len(event_id) > 255:
        raise HTTPException(status_code=400, detail="Invalid Stripe event")
    if db.get(StripeEvent, event_id):
        return {"received": True}
    obj = event.get("data", {}).get("object", {})
    if not isinstance(obj, dict):
        raise HTTPException(status_code=400, detail="Invalid Stripe event")
    customer_id = str(obj.get("customer") or "")
    org: Organization | None = None
    if event_type == "checkout.session.completed":
        try:
            org_id = UUID(str(obj.get("client_reference_id")))
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="Invalid organization reference") from exc
        org = db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
    elif customer_id:
        org = db.scalar(select(Organization).where(Organization.stripe_customer_id == customer_id).with_for_update())
    if org is None:
        logger.info("stripe_event_unmatched event_id=%s type=%s", event_id, event_type)
        return {"received": True}
    if db.get(StripeEvent, event_id):
        return {"received": True}
    changed = False
    email_owner: User | None = None
    event_created = int(event.get("created") or 0)
    if org and event_created >= org.billing_event_created:
        sub_id = _subscription_id(obj, event_type)
        if event_type == "checkout.session.completed" and sub_id and customer_id:
            if org.stripe_customer_id and org.stripe_customer_id != customer_id:
                raise HTTPException(status_code=409, detail="Stripe customer mismatch")
            try:
                subscription = stripe_service.retrieve_subscription(sub_id)
            except (stripe.StripeError, ValueError) as exc:
                raise _stripe_error(exc) from exc
            plan, seats = _price_and_seats(subscription)
            if (obj.get("payment_status") in {"paid", "no_payment_required"} and
                    subscription.get("customer") == customer_id and
                    subscription.get("status") in {"active", "trialing"} and plan):
                org.stripe_customer_id = customer_id
                org.stripe_subscription_id = sub_id
                org.plan = plan
                org.daily_limit = PLAN_LIMITS[plan] or 2_147_483_647
                org.billing_status = "active"
                org.seat_count = seats
                changed = True
        elif event_type == "customer.subscription.updated" and sub_id == org.stripe_subscription_id:
            plan, seats = _price_and_seats(obj)
            if obj.get("status") in {"active", "trialing"} and plan:
                org.plan = plan
                org.daily_limit = PLAN_LIMITS[plan] or 2_147_483_647
                org.billing_status = "active"
                org.seat_count = seats
                changed = True
            elif obj.get("status") in {"past_due", "unpaid", "paused", "incomplete", "incomplete_expired"}:
                org.billing_status = "past_due"
                changed = True
        elif event_type == "customer.subscription.deleted" and sub_id == org.stripe_subscription_id:
            org.plan = "free"
            org.daily_limit = 100
            org.stripe_subscription_id = None
            org.billing_status = "active"
            org.seat_count = 1
            changed = True
        elif event_type == "invoice.payment_failed" and sub_id == org.stripe_subscription_id:
            if org.billing_status != "past_due":
                email_owner = db.get(User, org.owner_id)
            org.billing_status = "past_due"
            changed = True
        elif event_type == "invoice.payment_succeeded" and sub_id == org.stripe_subscription_id:
            org.billing_status = "active"
            changed = True
        if changed:
            org.billing_event_created = event_created
    db.add(StripeEvent(id=event_id, event_type=event_type, org_id=org.id if org else None))
    db.commit()
    if email_owner and org:
        _send_payment_failure_email(email_owner, org)
    logger.info("stripe_event_processed event_id=%s type=%s org_id=%s changed=%s",
                event_id, event_type, org.id if org else "none", changed)
    return {"received": True}
