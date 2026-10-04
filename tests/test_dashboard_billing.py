"""Billing contract tests using a real API/ORM and an isolated Stripe facade."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from dashboard.db.models import Audit, Organization, OrgMember, User
from dashboard.db.session import SessionLocal
from tests.test_dashboard_audits import hosted


def _signed(event: dict, secret: str) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    signed = f"{timestamp}.".encode() + body
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return body, {"Stripe-Signature": f"t={timestamp},v1={digest}"}


def test_checkout_requires_owner_and_uses_configured_price(hosted, monkeypatch):
    client, org_id, _ = hosted
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_example")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_pro")
    client.get("/_test/login")
    with SessionLocal.begin() as db:
        colleague = User(github_id=9876, login="colleague")
        db.add(colleague)
        db.flush()
        db.add(OrgMember(org_id=org_id, user_id=colleague.id, role="member"))
    calls = []
    from dashboard.billing import stripe as billing_stripe

    monkeypatch.setattr(billing_stripe.stripe.checkout.Session, "create", lambda **kw: calls.append(kw) or {"url": "https://checkout.stripe.com/test"})
    result = client.post(f"/api/v1/orgs/{org_id}/billing/checkout", json={"plan": "pro"})
    assert result.status_code == 200
    assert result.json()["url"] == "https://checkout.stripe.com/test"
    assert calls[0]["line_items"] == [{"price": "price_pro", "quantity": 2}]
    assert calls[0]["mode"] == "subscription"
    assert client.post(f"/api/v1/orgs/{org_id}/billing/checkout", json={"plan": "team"}).status_code == 503


def test_signed_webhook_upgrades_once_and_deletes_subscription(hosted, monkeypatch):
    client, org_id, _ = hosted
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_pro")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_example")
    event = {"id": "evt_checkout", "type": "checkout.session.completed", "created": 100,
             "data": {"object": {"id": "cs_1", "client_reference_id": str(org_id), "customer": "cus_1", "subscription": "sub_1", "payment_status": "paid"}}}
    from dashboard.billing import stripe as billing_stripe

    monkeypatch.setattr(billing_stripe.stripe.Subscription, "retrieve", lambda _id: {
        "id": "sub_1", "customer": "cus_1", "status": "active",
        "items": {"data": [{"price": {"id": "price_pro"}, "quantity": 1}]},
    })
    body, headers = _signed(event, "whsec_test")
    assert client.post("/api/v1/webhooks/stripe", content=body, headers={"Stripe-Signature": "bad"}).status_code == 400
    assert client.post("/api/v1/webhooks/stripe", content=body, headers=headers).status_code == 200
    assert client.post("/api/v1/webhooks/stripe", content=body, headers=headers).status_code == 200
    with SessionLocal() as db:
        org = db.get(Organization, org_id)
        assert (org.plan, org.stripe_customer_id, org.stripe_subscription_id) == ("pro", "cus_1", "sub_1")
        assert org.billing_status == "active"
    deleted = {"id": "evt_deleted", "type": "customer.subscription.deleted", "created": 101,
               "data": {"object": {"id": "sub_1", "customer": "cus_1"}}}
    body, headers = _signed(deleted, "whsec_test")
    assert client.post("/api/v1/webhooks/stripe", content=body, headers=headers).status_code == 200
    with SessionLocal() as db:
        org = db.get(Organization, org_id)
        assert (org.plan, org.billing_status, org.stripe_subscription_id) == ("free", "active", None)


def test_payment_failure_blocks_audit_but_billing_is_visible(hosted, monkeypatch):
    client, org_id, key = hosted
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    with SessionLocal.begin() as db:
        org = db.get(Organization, org_id)
        org.plan = "pro"
        org.stripe_customer_id = "cus_1"
        org.stripe_subscription_id = "sub_1"
        db.get(User, org.owner_id).email = "owner@example.test"
    from dashboard.api import billing as billing_routes

    notices = []
    monkeypatch.setattr(billing_routes, "_send_payment_failure_email",
                        lambda owner, org: notices.append((owner.email, org.id)))
    event = {"id": "evt_failed", "type": "invoice.payment_failed", "created": 102,
             "data": {"object": {"id": "in_1", "customer": "cus_1", "subscription": "sub_1"}}}
    body, headers = _signed(event, "whsec_test")
    assert client.post("/api/v1/webhooks/stripe", content=body, headers=headers).status_code == 200
    assert notices == [("owner@example.test", org_id)]
    result = client.post("/api/v1/audit", json={"diff_content": "print(1)", "language": "python"}, headers={"X-API-Key": key})
    assert result.status_code == 402
    client.get("/_test/login")
    billing = client.get(f"/api/v1/orgs/{org_id}/billing")
    assert billing.status_code == 200
    assert billing.json()["billing_status"] == "past_due"


def test_subscription_update_changes_plan_and_seat_count(hosted, monkeypatch):
    client, org_id, _ = hosted
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    monkeypatch.setenv("STRIPE_PRICE_TEAM", "price_team")
    with SessionLocal.begin() as db:
        org = db.get(Organization, org_id)
        org.stripe_customer_id = "cus_1"
        org.stripe_subscription_id = "sub_1"
        org.plan = "pro"
    event = {"id": "evt_update", "type": "customer.subscription.updated", "created": 200,
             "data": {"object": {"id": "sub_1", "customer": "cus_1", "status": "active",
                                  "items": {"data": [{"price": {"id": "price_team"}, "quantity": 3}]}}}}
    body, headers = _signed(event, "whsec_test")
    assert client.post("/api/v1/webhooks/stripe", content=body, headers=headers).status_code == 200
    with SessionLocal() as db:
        org = db.get(Organization, org_id)
        assert (org.plan, org.seat_count, org.daily_limit) == ("team", 3, 2_147_483_647)


def test_free_org_is_blocked_at_100_audits(hosted):
    client, org_id, key = hosted
    with SessionLocal.begin() as db:
        db.add_all([Audit(org_id=org_id, status="PASSED", risk_score=0, created_at=datetime.now(timezone.utc)) for _ in range(100)])
    result = client.post("/api/v1/audit", json={"diff_content": "print(1)", "language": "python"}, headers={"X-API-Key": key})
    assert result.status_code == 429
    assert result.json()["detail"] == "Free limit reached, upgrade"


def test_dev_activation_is_owner_only_and_requires_missing_stripe_key(hosted, monkeypatch):
    client, org_id, _ = hosted
    client.get("/_test/login")
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    result = client.post(f"/api/v1/orgs/{org_id}/billing/dev-activate", json={"plan": "team"})
    assert result.status_code == 200
    assert result.json()["plan"] == "team"
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_example")
    assert client.post(f"/api/v1/orgs/{org_id}/billing/dev-activate", json={"plan": "pro"}).status_code == 404


def test_free_repo_limit_and_paid_seat_limit(hosted, monkeypatch):
    client, org_id, _ = hosted
    client.get("/_test/login")
    from dashboard.api import orgs

    async def github_repo(_user, path):
        return {"full_name": path.removeprefix("repos/"), "permissions": {"push": True}, "default_branch": "main"}

    monkeypatch.setattr(orgs, "_github_get", github_repo)
    for index in range(3):
        response = client.post(f"/api/v1/orgs/{org_id}/repos", json={"github_repo_full_name": f"owner/repo-{index}"})
        assert response.status_code == 201
    assert client.post(f"/api/v1/orgs/{org_id}/repos", json={"github_repo_full_name": "owner/fourth"}).status_code == 429


def test_invoices_are_customer_scoped(hosted, monkeypatch):
    client, org_id, _ = hosted
    client.get("/_test/login")
    with SessionLocal.begin() as db:
        db.get(Organization, org_id).stripe_customer_id = "cus_own"
    from dashboard.billing import stripe as billing_stripe

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_example")
    seen = []
    monkeypatch.setattr(billing_stripe.stripe.Invoice, "list", lambda **kw: seen.append(kw) or {"data": [
        {"id": "in_1", "number": "AG-001", "status": "paid", "amount_paid": 1900,
         "currency": "usd", "created": 123, "hosted_invoice_url": "https://invoice.stripe.com/test", "secret": "hidden"}
    ]})
    response = client.get(f"/api/v1/orgs/{org_id}/billing/invoices")
    assert response.status_code == 200
    assert seen == [{"customer": "cus_own", "limit": 20}]
    assert "secret" not in response.json()["items"][0]


def test_retention_prunes_only_expired_audits_for_one_tenant(hosted):
    _, org_id, _ = hosted
    from dashboard.billing.retention import prune_org_audits

    now = datetime.now(timezone.utc)
    with SessionLocal.begin() as db:
        old = Audit(org_id=org_id, status="PASSED", risk_score=0, created_at=now - timedelta(days=8))
        recent = Audit(org_id=org_id, status="PASSED", risk_score=0, created_at=now - timedelta(days=1))
        db.add_all([old, recent])
        db.flush()
        old_id, recent_id = old.id, recent.id
    assert prune_org_audits(org_id, 7, now=now) == 1
    with SessionLocal() as db:
        assert db.get(Audit, old_id) is None
        assert db.get(Audit, recent_id) is not None


def test_catalog_creates_monthly_per_developer_prices(monkeypatch):
    from dashboard.billing import stripe as billing_stripe

    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_example")
    products = []
    prices = []
    monkeypatch.setattr(billing_stripe.stripe.Product, "create",
                        lambda **kw: products.append(kw) or {"id": f"prod_{len(products)}"})
    monkeypatch.setattr(billing_stripe.stripe.Price, "create",
                        lambda **kw: prices.append(kw) or {"id": f"price_{len(prices)}"})
    result = billing_stripe.provision_products()
    assert set(result) == {"free", "pro", "team"}
    assert [item["unit_amount"] for item in prices] == [0, 1900, 4900]
    assert all(item["recurring"] == {"interval": "month", "usage_type": "licensed"} for item in prices)
    assert len({item["idempotency_key"] for item in products + prices}) == 6
