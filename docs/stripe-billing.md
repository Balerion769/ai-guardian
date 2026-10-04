# Stripe billing setup

Billing runs in hosted mode (`docker compose up --build -d`) on `http://127.0.0.1:8001` by default. The local scanner on port 8000 has no organization billing routes. Copy the repository root `.env.example` to `.env`, keep it private, and set a Stripe **test** secret key. Set `DASHBOARD_WEB_BASE_URL=http://localhost:3000` so Checkout and portal return to the web dashboard.

Create the catalog once for each Stripe account:

```powershell
$env:STRIPE_SECRET_KEY = 'sk_test_REPLACE_ME'
.\.venv\Scripts\python.exe -m dashboard.billing.stripe
```

The command creates Free ($0), Pro ($19/developer/month), and Team ($49/developer/month) products and monthly licensed prices with stable idempotency keys. Copy the printed Pro and Team IDs into `STRIPE_PRICE_PRO` and `STRIPE_PRICE_TEAM` in `.env`, then rebuild the Compose API. Checkout quantity equals the current organization member count. To add more paid members later, increase quantity in the Stripe portal first; Stripe's subscription update webhook refreshes the allowed seat count.

Run the Stripe CLI in a second terminal:

```powershell
stripe login
stripe listen --events checkout.session.completed,customer.subscription.updated,customer.subscription.deleted,invoice.payment_failed,invoice.payment_succeeded --forward-to http://127.0.0.1:8001/api/v1/webhooks/stripe
```

Copy the CLI's `whsec_...` signing secret into `STRIPE_WEBHOOK_SECRET` and restart the API. The CLI command can use port 8000 only when hosted mode itself is bound to 8000. Open the web dashboard, sign in with GitHub, and choose **Settings → Billing → Upgrade to Pro**. Complete Stripe test Checkout with a test card. The verified `checkout.session.completed` webhook upgrades the organization after its subscription is active. The portal button opens Stripe-hosted subscription management. Stripe invoices appear in the dashboard for the organization owner.

For owner payment-failure email, set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `BILLING_EMAIL_FROM`. If SMTP is absent or the GitHub owner has no email, the past-due status still blocks audits and an operator warning is logged. Do not use a production Stripe key with the local demo.

Without Stripe keys, Checkout logs a warning and returns a development response. A signed-in owner can manually activate a local plan with `POST /api/v1/orgs/{org_id}/billing/dev-activate` and `{"plan":"pro"}` or `{"plan":"team"}`. This route returns 404 when production mode or a Stripe key is configured. The browser's interactive demo uses only synthetic state and cannot charge a card.

Free organizations are limited to 100 audits per UTC day, one owned organization, and three repositories. Pro allows 1,000 audits per UTC day and unlimited repositories. Team allows unlimited audits. Paid seats must cover organization membership. Audit submissions are blocked with HTTP 402 when payment is past due; billing views remain available. The retention service removes audit metadata and findings hourly after seven days for Free/Pro or 90 days for Team. SSO, SOC 2 exports, custom rules, Slack delivery, and automatic fixes are planned and are not active entitlements.
