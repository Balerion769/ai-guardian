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

Create one Fly app for the API and one for the dashboard, then attach managed Postgres and Redis (or private equivalents). Build with `dashboard/Dockerfile.api` and `dashboard/web/Dockerfile`, set the variables from `.env.prod` with `fly secrets set`, and expose `/health` as the API health check. Run the worker as a second process group using `dashboard/Dockerfile.worker` and command `rq worker audits --url $REDIS_URL`. Run `python -m dashboard.db.migrate` once as a release command before promoting the API.

## Render

Create a private PostgreSQL database and Redis instance. Add a Docker web service using `dashboard/Dockerfile.api`, a background worker using `dashboard/Dockerfile.worker`, and a web service using `dashboard/web/Dockerfile`. Set `DATABASE_URL`, `REDIS_URL`, and the variables in `.env.prod` in each service. Configure the API health path as `/health` and the dashboard health path as `/login`; run the migration as a one-off job before the first deploy.

## Railway

Create PostgreSQL and Redis plugins, then deploy three services from this repository: API (Dockerfile `dashboard/Dockerfile.api`), worker (`dashboard/Dockerfile.worker`), and dashboard (`dashboard/web/Dockerfile`). Reference the private service URLs in `DATABASE_URL`, `REDIS_URL`, and `BACKEND_API_URL`. Run `python -m dashboard.db.migrate` from the API service shell and use `/health` as the deployment health check.

All providers should use a private network for API-to-database, worker-to-Redis, and API-to-Ollama traffic. Rotate the GitHub App private key, webhook secret, session secret, encryption key, database passwords, and Stripe keys through the provider secret manager.
