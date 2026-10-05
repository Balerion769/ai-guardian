# Free Deploy Guide

Deploy branch `ast-security-rules` as a personal demo: Render runs the API,
Neon stores users and audits, and Vercel hosts the Next.js dashboard. No GPU,
Ollama, Together API key, paid worker, or Redis subscription is required.
`STATIC_ONLY_MODE=1` runs static AST and taint analysis within each request,
then persists results. Authentication, org membership, quotas, and tenant
policies remain enforced.

## Free-plan boundaries

Verified against provider documentation on October 5, 2026:

- [Render](https://render.com/docs/free): 750 free instance hours/workspace/month,
  sleeps after 15 idle minutes, and startup takes about a minute. Background
  workers have no free instance type. Free Postgres expires after 30 days, so
  this Blueprint uses external Neon.
- [Neon](https://neon.com/blog/neon-free-plan-1-gb-per-project): current free
  storage is 1 GB/project, not 3 GB. Observe your console's compute and transfer
  allowances and retain your own backups.
- [Upstash](https://upstash.com/pricing/redis): optional free Redis has 256 MB,
  500K commands/month, and 10 GB monthly bandwidth. This profile uses no queue.
- [Vercel Hobby](https://vercel.com/docs/plans/hobby): personal, non-commercial
  use only. Quotas and fair-use terms apply; a commercial SaaS needs an
  appropriate plan.

Select only free plans; do not enable usage-based upgrades or add payment
methods for this demo. Providers can require account verification and change
quotas. The repository cannot bypass those requirements. URLs below are
placeholders until providers assign your actual deployments.

## 1. Neon Postgres in Singapore

1. Sign in at [Neon Console](https://console.neon.tech/), create a free project
   `ai-guardian`, choose AWS Singapore (`ap-southeast-1`), and database `guardian`.
   Colocating the API and database reduces cross-region calls for Bangalore
   users; latency still depends on the network and cold starts.
2. Keep the direct TLS schema-owner URL private as `MIGRATION_DATABASE_URL`.
   Apply migrations locally before provisioning the runtime role:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r dashboard/requirements.txt
   # Set MIGRATION_DATABASE_URL privately; never commit it.
   .\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
   ```

3. In Neon's SQL editor as schema owner, provision a non-owner runtime role.
   Replace the password privately and substitute your actual migration owner
   for `neondb_owner`:

   ```sql
   CREATE ROLE guardian_app WITH LOGIN PASSWORD 'REPLACE_WITH_GENERATED_PASSWORD'
     NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
   GRANT CONNECT ON DATABASE guardian TO guardian_app;
   GRANT USAGE ON SCHEMA public TO guardian_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO guardian_app;
   ALTER DEFAULT PRIVILEGES FOR ROLE neondb_owner IN SCHEMA public
     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO guardian_app;
   ```

4. Set Render's `DATABASE_URL` to the application role's TLS URL and
   `MIGRATION_DATABASE_URL` to the schema owner. Use `sslmode=require` on both.
   Runtime must not use a superuser or `BYPASSRLS` role. The backend normalizes
   provider `postgresql://` URLs to the installed psycopg driver.

For a legacy database, follow [DEPLOY.md](DEPLOY.md): verify its schema before
stamping the initial revision. Failed migrations stop deployment. Never
auto-stamp an unverified database.

## 2. Upstash Redis (optional)

Skip Redis for this free profile: audits finish inline. For a later paid RQ
worker, create free Redis at [Upstash Console](https://console.upstash.com/),
in Singapore if available, then set its TCP TLS
`rediss://default:PASSWORD@HOST:PORT/0` as `REDIS_URL`. The HTTPS REST URL/token
does not work with RQ. Avoid a continuously polling worker for this free demo.

## 3. Render API

1. Push branch `ast-security-rules`. Choose **New → Blueprint**, connect
   `Balerion769/ai-guardian`, and select that branch. `render.yaml` creates one
   **free web service in Singapore**, with no worker or expiring database.
2. Set prompted variables from `.env.free.example`: `DATABASE_URL`,
   `MIGRATION_DATABASE_URL`, `DASHBOARD_PUBLIC_BASE_URL=https://YOUR-API.onrender.com`,
   and `DASHBOARD_WEB_BASE_URL=https://YOUR-PROJECT.vercel.app`.
   Generate `DASHBOARD_TOKEN_ENCRYPTION_KEY` locally:

   ```powershell
   python -c "from cryptography.fernet import Fernet; import sys; sys.stdout.write(Fernet.generate_key().decode())"
   ```

   Render generates `DASHBOARD_SESSION_SECRET`; retain it across deployments.
3. Keep `STATIC_ONLY_MODE=1`, `DASHBOARD_DEV_MODE=0`. No `OLLAMA_URL` is required.
   Together's API is incompatible with Ollama's protocol; no external LLM
   requests occur in this deployment.
4. Deploy and record its actual API domain. Manual alternative: **New Web
   Service → Python → Singapore → Free**, repository root, branch
   `ast-security-rules`, build `pip install -r dashboard/requirements.txt`,
   start `python -m dashboard.free_start`, health path `/health`, same variables.
   If a just-released Python patch is unavailable on Render, select a supported
   current Python 3.11 security patch in its settings.
5. Startup runs Alembic then one Uvicorn worker on `$PORT`. Visit `/`: expect
   `{"message":"AI Guardian API live","docs":"/docs"}`, then open `/docs`.
   `/health` checks liveness without connecting to DB, Redis, or Ollama.
   Unavailable storage still fails data requests; health is not DB readiness.

Docker alternative: build `Dockerfile.api.free` using repository-root context.
Dependencies are mandatory; installation failures are never ignored. SQLite
fallback is only for explicit local `DASHBOARD_DEV_MODE=1`; cloud mode requires
durable storage and valid secrets.

## 4. Vercel dashboard

1. Import `Balerion769/ai-guardian` into a personal Hobby account. Set **Root
   Directory = dashboard/web**, Next.js framework, Node.js 24, and production
   branch `ast-security-rules`. Deploy buttons may clone the default branch:
   verify that the selected branch contains this dashboard.
2. `vercel.json` uses `npm ci`, `npm run build`, `.next`, and Singapore `sin1`.
3. Set Production environment variables: `NEXTAUTH_URL` to your assigned
   `https://YOUR-PROJECT.vercel.app`, unique random `NEXTAUTH_SECRET` with at
   least 32 characters, `GITHUB_ID`, `GITHUB_SECRET`, and
   `BACKEND_API_URL=https://YOUR-API.onrender.com`.
   `NEXT_PUBLIC_API_URL` may provide that same URL as a server-side fallback.
4. Deploy, record its actual URL, update Render's `DASHBOARD_WEB_BASE_URL`, and
   redeploy after build-time variable changes. The GitHub callback and
   `NEXTAUTH_URL` must match the exact public dashboard domain.

Database, Redis, encryption, session, and OAuth secrets must never be
`NEXT_PUBLIC_*`. Browser calls use relative `/api/dashboard`; only the server
forwards the backend's signed cookie to Render. Calls cancel after 10 seconds
and show a retry message. Cold starts can exceed that: open `/health`, wait
about a minute, then retry login or reads. Mutations are never auto-retried.

## 5. Monitoring and cold starts

An optional free uptime monitor can send availability alerts. It does not
guarantee uptime or override Render's free-tier rules. Keeping a service awake
consumes monthly hours; expect sleeps, restarts, and quota suspensions.
Do not rely on keep-alive pings for production availability.

## 6. GitHub OAuth and App

Create an OAuth App at [GitHub Developer Settings](https://github.com/settings/developers).
Homepage: your dashboard URL. Callback:
`https://YOUR-PROJECT.vercel.app/api/auth/callback/github`.
Store client ID/secret on Vercel and redeploy. Login verifies the GitHub token
with the backend and creates a user/personal org. Production has no anonymous
demo login.

Optional GitHub App: configure its ID, private key, webhook secret, and install
URL on Render. Webhook:
`https://YOUR-API.onrender.com/api/v1/webhooks/github`.
Signed PR webhooks run static analysis inline and publish checks. Cold starts
may exceed GitHub delivery timeouts: review/redeliver failed deliveries. This
free profile is not an availability guarantee for required PR checks.

## 7. Verify the complete flow

Sign in, create an API key in Settings, and retain the raw key once. Set
`AG_API_KEY` privately in PowerShell, then:

```powershell
$api = 'https://YOUR-API.onrender.com'
Invoke-RestMethod "$api/health"
$body = @{diff_content='eval(user_input)'; language='python'} | ConvertTo-Json
$result = Invoke-RestMethod "$api/api/v1/audit" -Method Post -ContentType 'application/json' -Headers @{'X-API-Key'=$env:AG_API_KEY} -Body $body
$result | ConvertTo-Json -Depth 6
```

Expect HTTP 202, completed `FAILED`, risk at least 40, `model_used=static-only`,
and persisted findings. Repeat with `print("hello")`: expect `PASSED`. Verify
both records and statistics in the same org's dashboard. Invalid API keys
must return 401; daily plan quotas remain enforced.

## 8. Automatic deployments

Vercel deploys its configured production branch through Git integration.
Render Blueprint auto-deploys changes. For the optional
`.github/workflows/deploy-free.yml`, set Actions secret `RENDER_DEPLOY_HOOK`;
disable duplicate Render auto-deploys if desired. The workflow validates the
destination, hides responses, and skips the step when the secret is absent.

Add README demo links only after both assigned URLs have been verified.
`ai-guardian.vercel.app` and `ai-guardian-api.onrender.com` are not reserved
by this repository.
