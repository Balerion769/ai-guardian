# Billing design

Stripe Prices configured in `STRIPE_PRICE_PRO` and `STRIPE_PRICE_TEAM` are the only accepted paid prices. A provisioning command creates monthly per-seat products/prices in Stripe test or live mode; it does not run during API startup. Checkout quantity is the organization member count, at least one. The organization owner initiates Checkout and customer-portal sessions.

The webhook verifies Stripe's signature over the unmodified request body, records each event ID once, and updates one organization's subscription state. Paid access follows active/trialing subscriptions; a failed invoice marks `past_due`, and cancellation restores free. Owner email uses configured SMTP; delivery failure is logged without exposing credentials and does not acknowledge the payment as successful. Session and subscription IDs are used to match events; unrecognized prices never grant access.

Audit admission checks `billing_status` and an organization-row-locked UTC daily count. Free permits 100, Pro 1000, Team unlimited. Free also permits one organization per owner and three linked repositories. Billing read endpoints are available during `past_due`; audit submission is blocked. The local demo uses synthetic billing data and changes no real Stripe account or hosted database. Development-only manual activation requires a signed-in organization owner.

Retention runs hourly and removes audit metadata and findings after seven days on Free/Pro or 90 days on Team. Billing features such as SSO, Slack delivery, SOC 2 exports, custom rules, and automated fixes are outside the current scanner and dashboard; plan catalog entries describe intended entitlements, but the UI must identify them as planned until implemented.
