# Production deployment

AI Guardian runs as five services: PostgreSQL, Redis, a hosted FastAPI API, an RQ worker, and the Next.js dashboard. Copy `.env.prod.example` to `.env.prod`, generate unique secrets, and configure GitHub OAuth, the GitHub App, Stripe, Ollama, and Sentry before exposing the service.

## Docker Compose

```powershell
Copy-Item .env.prod.example .env.prod
# edit .env.prod with production values
docker compose --env-file .env.prod -f docker-compose.prod.yml up --build -d
docker compose --env-file .env.prod -f docker-compose.prod.yml ps
curl https://api.example.com/health
```

The API and web containers have HTTP health checks. The database initializer runs before the API and worker and is safe to run again for the initial schema. Put TLS and a reverse proxy in front of the two HTTP services; keep PostgreSQL and Redis private.

## Fly.io

The checked-in [`fly.toml`](fly.toml) deploys the API and RQ worker as Fly process groups. It runs the Alembic migration as a release command and exposes only the API process through the HTTPS health-checked service.

```bash
fly auth login
fly apps create ai-guardian-api
fly mpg create
fly mpg list
fly mpg attach CLUSTER_ID --app ai-guardian-api
fly secrets set --app ai-guardian-api \
  REDIS_URL="rediss://:<password>@<private-redis-host>:6380/0" \
  OLLAMA_URL="https://<private-ollama-host>/api/generate" \
  OLLAMA_MODEL="qwen2.5-coder" \
  DASHBOARD_SESSION_SECRET="REPLACE_WITH_32_OR_MORE_RANDOM_CHARACTERS" \
  DASHBOARD_TOKEN_ENCRYPTION_KEY="REPLACE_WITH_FERNET_KEY" \
  DASHBOARD_PUBLIC_BASE_URL="https://ai-guardian-api.fly.dev" \
  DASHBOARD_WEB_BASE_URL="https://ai-guardian-dashboard.fly.dev" \
  GITHUB_CLIENT_ID="..." GITHUB_CLIENT_SECRET="..." \
  GITHUB_APP_ID="..." GITHUB_APP_PRIVATE_KEY="$(cat github-app-private-key.pem)" \
  GITHUB_APP_WEBHOOK_SECRET="..." \
  GITHUB_APP_INSTALL_URL="https://github.com/apps/YOUR_APP/installations/new"
fly deploy --config fly.toml
fly scale count app=1 worker=1 --app ai-guardian-api
fly status --app ai-guardian-api
curl https://ai-guardian-api.fly.dev/health
```

Install the [Fly CLI](https://fly.io/docs/flyctl/install/) first. App names must be globally unique: replace the names in both configuration files and these commands. Select the same region for the app and [Managed Postgres](https://fly.io/docs/mpg/); replace `CLUSTER_ID` with the ID shown by `fly mpg list`. Use a managed Redis service reachable over TLS. Generate a Fernet key with `python -c "from cryptography.fernet import Fernet; import sys; sys.stdout.write(Fernet.generate_key().decode())"`, then set the encryption secret to that value. Configure the remaining Stripe/SMTP/Sentry variables from `.env.prod.example` when those services are enabled.

Fly supplies a PostgreSQL URL on attachment; the application selects the installed psycopg driver automatically. For production, use a non-superuser runtime role for `DATABASE_URL` and a separate schema-owner URL in `MIGRATION_DATABASE_URL`. Give the runtime role `USAGE` on schema `public` and `SELECT, INSERT, UPDATE, DELETE` on application tables after migration. Run migrations as the schema owner. The initial revision creates new tables; an existing database created by the legacy initializer must be brought to the current schema and verified before `alembic stamp 0001_initial_schema` is used. Back up the database before that transition.

Deploy the web app from its own build context:

```bash
cd dashboard/web
fly apps create ai-guardian-dashboard
fly secrets set --app ai-guardian-dashboard \
  NEXTAUTH_URL="https://ai-guardian-dashboard.fly.dev" \
  NEXTAUTH_SECRET="REPLACE_WITH_32_OR_MORE_RANDOM_CHARACTERS" \
  BACKEND_API_URL="https://ai-guardian-api.fly.dev" \
  GITHUB_CLIENT_ID="..." GITHUB_CLIENT_SECRET="..."
fly deploy --config fly.toml
curl https://ai-guardian-dashboard.fly.dev/login
```

Set the GitHub OAuth callback to `https://ai-guardian-dashboard.fly.dev/api/auth/callback/github` and the GitHub App webhook to `https://ai-guardian-api.fly.dev/api/v1/webhooks/github`. Set custom domains and certificates through `fly certs add YOUR_DOMAIN`. Validate a sign-in, a queued audit, the worker result, and a PR check before enabling required branch checks. These commands provision paid infrastructure; the repository does not include a running Fly deployment.

## Render

Create a private PostgreSQL database and Redis instance. Add a Docker web service using `dashboard/Dockerfile.api`, a background worker using `dashboard/Dockerfile.worker`, and a dashboard web service with root directory `dashboard/web` and Dockerfile `Dockerfile`. The API and worker use the repository root as their build context. Set `DATABASE_URL`, `REDIS_URL`, and the variables in `.env.prod` in each service. Configure the API health path as `/health` and the dashboard health path as `/login`. Run `alembic upgrade head` as a pre-deploy command or one-off job before the first deploy, then verify `/health` and worker logs.

## Railway

Create PostgreSQL and Redis plugins, then deploy three services from this repository: API (Dockerfile `dashboard/Dockerfile.api`), worker (`dashboard/Dockerfile.worker`), and dashboard (root directory `dashboard/web`, Dockerfile `Dockerfile`). Reference the private service URLs in `DATABASE_URL`, `REDIS_URL`, and `BACKEND_API_URL`. Set the API pre-deploy command to `alembic upgrade head`, use `/health` as the deployment health check, and scale the worker independently from the API.

All providers should use a private network for API-to-database, worker-to-Redis, and API-to-Ollama traffic. Rotate the GitHub App private key, webhook secret, session secret, encryption key, database passwords, and Stripe keys through the provider secret manager.
