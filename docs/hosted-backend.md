# Hosted backend setup

The Docker stack starts PostgreSQL, Redis, a one-shot schema initializer, a protected FastAPI service, and an RQ worker. The existing scanner remains the audit engine. `main:app` is local by default; Compose sets `AIGUARDIAN_MODE=hosted`, where `POST /api/v1/audit` requires `X-API-Key`.

The stack also runs an hourly audit-retention process. To configure Stripe Checkout, webhooks, invoices, and owner notifications, follow the [billing setup](stripe-billing.md).

## Local development

1. Configure a GitHub OAuth app with callback URL `http://127.0.0.1:8001/api/v1/auth/github/callback`. Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in a local `.env` file if you want browser sign-in. Without those credentials, the stack runs but OAuth returns 503.
2. Run `docker compose up --build -d`. Check `docker compose ps` and `curl http://127.0.0.1:8001/health`. Port 8001 leaves the existing local scanner on port 8000 untouched.
3. Open `http://127.0.0.1:8001/api/v1/auth/github` in a browser. Sign-in creates a personal workspace organization. Use `POST /api/v1/orgs` to create another organization if needed, then create a key with `POST /api/v1/orgs/{org_id}/api-keys`. The response contains the raw key only once.
4. Submit a diff with `POST /api/v1/audit` and `X-API-Key: ag_live_...`. The response contains `audit_id`, `status`, and findings if the worker finishes within two seconds. Poll `GET /api/v1/orgs/{org_id}/audits/{audit_id}` using the browser session for final results.

Example PowerShell request after receiving an API key:

```powershell
$headers = @{ 'X-API-Key' = 'ag_live_REPLACE_WITH_NEW_KEY' }
$body = @{ diff_content = 'eval(user_input)'; language = 'python' } | ConvertTo-Json
Invoke-RestMethod 'http://127.0.0.1:8001/api/v1/audit' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

## Production configuration

The Compose defaults are local-development credentials and bind the API to loopback. Before hosting, set `DASHBOARD_DEV_MODE=0`, a 32-character-or-longer `DASHBOARD_SESSION_SECRET`, a generated Fernet `DASHBOARD_TOKEN_ENCRYPTION_KEY`, unique PostgreSQL passwords, `DASHBOARD_PUBLIC_BASE_URL=https://...`, the matching `GITHUB_CALLBACK_URL`, and GitHub OAuth credentials. Put the API behind HTTPS and keep PostgreSQL/Redis private. The worker's `OLLAMA_URL` may point to a trusted remote model server; source is sent to that endpoint. GitHub OAuth requests `read:user`, `read:org`, and `repo` scopes so the service can verify repository access and publish commit statuses. A GitHub commit status blocks merging only when branch protection requires the `AI Guardian` context.

Secrets should be injected by a deployment secret manager; do not commit `.env`. The service stores encrypted GitHub access tokens and salted API-key hashes. Redis temporarily contains queued source; it has no published port. RQ jobs are configured with a safe description and zero result/failure retention.

## Limits

`init_db` creates the initial schema idempotently and applies the billing column migration for existing PostgreSQL organizations; later schema changes need versioned migrations before rolling upgrades. The quota uses UTC days and serializes submissions per organization. Daily limits are 100 for Free, 1000 for Pro, and unlimited for Team. Stats are exact over retained audits and may need pre-aggregation for very large tenants. An unavailable Ollama leaves static findings and an incomplete-analysis summary. An unavailable Redis returns 503 and marks the attempted audit `ERROR`.
