"""Stripe SDK boundary, catalog, checkout, portal, and invoice serialization."""

from __future__ import annotations

import logging
import os
from typing import Any

import stripe

from dashboard.config import get_settings


logger = logging.getLogger(__name__)

PLANS: dict[str, dict[str, Any]] = {
    "free": {"monthly_usd_per_developer": 0, "audits_per_day": 100, "max_repos": 3,
             "retention_days": 7, "features": ["Community support", "7-day audit retention"]},
    "pro": {"monthly_usd_per_developer": 19, "audits_per_day": 1000, "max_repos": None,
            "retention_days": 7, "features": ["7-day audit retention", "Autofix suggestions (planned)", "Slack webhook (planned)"]},
    "team": {"monthly_usd_per_developer": 49, "audits_per_day": None, "max_repos": None,
             "retention_days": 90, "features": ["90-day audit retention", "SSO (planned)", "SOC 2 export (planned)", "Custom rules (planned)"]},
}


def _configure() -> None:
    """Set Stripe credentials for the current hosted process."""
    key = os.getenv("STRIPE_SECRET_KEY", "")
    if not key:
        raise ValueError("STRIPE_SECRET_KEY is not configured")
    stripe.api_key = key


def price_for_plan(plan: str) -> str | None:
    """Return the server configured Price ID; never trust a client supplied ID."""
    settings = get_settings()
    return {"pro": settings.stripe_price_pro, "team": settings.stripe_price_team}.get(plan) or None


def plan_for_price(price_id: str) -> str | None:
    """Map an actual Stripe Price ID back to a paid entitlement."""
    if price_for_plan("pro") and price_for_plan("pro") == price_for_plan("team"):
        logger.error("stripe_prices_ambiguous")
        return None
    for plan in ("pro", "team"):
        if price_id and price_id == price_for_plan(plan):
            return plan
    return None


def create_checkout(*, org_id: str, plan: str, seats: int, customer_id: str | None,
                    email: str | None, return_url: str) -> str:
    """Create a hosted monthly per-developer subscription Checkout Session."""
    _configure()
    price_id = price_for_plan(plan)
    if not price_id:
        raise ValueError("Stripe price is not configured for this plan")
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        **({"customer_email": email} if email and not customer_id else {}),
        client_reference_id=org_id,
        line_items=[{"price": price_id, "quantity": max(1, seats)}],
        subscription_data={"metadata": {"org_id": org_id}},
        success_url=f"{return_url}?billing=success",
        cancel_url=f"{return_url}?billing=cancelled",
        metadata={"org_id": org_id, "plan": plan},
    )
    return str(session["url"])


def create_portal(customer_id: str, return_url: str) -> str:
    """Create a short lived customer portal session."""
    _configure()
    session = stripe.billing_portal.Session.create(customer=customer_id, return_url=return_url)
    return str(session["url"])


def retrieve_subscription(subscription_id: str) -> dict[str, Any]:
    """Read current subscription details before granting Checkout access."""
    _configure()
    return dict(stripe.Subscription.retrieve(subscription_id))


def list_invoices(customer_id: str) -> list[dict[str, Any]]:
    """Return a bounded, public subset of Stripe invoice data."""
    _configure()
    invoices = stripe.Invoice.list(customer=customer_id, limit=20)
    return [
        {"id": invoice["id"], "number": invoice.get("number"), "status": invoice.get("status"),
         "amount_paid": invoice.get("amount_paid", 0), "currency": invoice.get("currency", "usd"),
         "created": invoice.get("created"), "hosted_invoice_url": invoice.get("hosted_invoice_url")}
        for invoice in invoices.get("data", [])
    ]


def provision_products() -> dict[str, str]:
    """Create versioned products and monthly licensed prices once per Stripe account."""
    _configure()
    price_ids: dict[str, str] = {}
    for plan, details in PLANS.items():
        product = stripe.Product.create(
            name=f"AI Guardian {plan.title()}",
            description=f"{details['audits_per_day'] or 'Unlimited'} audits per day",
            metadata={"aiguardian_plan": plan, "catalog_version": "1"},
            idempotency_key=f"aiguardian-{plan}-product-v1",
        )
        price = stripe.Price.create(
            product=product["id"], currency="usd",
            unit_amount=details["monthly_usd_per_developer"] * 100,
            recurring={"interval": "month", "usage_type": "licensed"},
            idempotency_key=f"aiguardian-{plan}-monthly-price-v1",
        )
        price_ids[plan] = str(price["id"])
    logger.info("stripe_catalog_provisioned plans=%d", len(price_ids))
    return price_ids


if __name__ == "__main__":
    for plan_name, stripe_price_id in provision_products().items():
        logger.warning("STRIPE_PRICE_%s=%s", plan_name.upper(), stripe_price_id)
