# Hosted AIGuardian backend design

The hosted service wraps the existing scanner without copying it. `main:app` keeps the local API by default; `AIGUARDIAN_MODE=hosted` exposes the hosted app at the same `/api/v1/audit` path. Docker runs hosted mode. This preserves local CLI and VS Code users while making hosted requests require `X-API-Key`.

## Trust and identity

GitHub OAuth uses Authlib, a state-protected callback, an HTTP-only session cookie, and the minimum requested scopes for profile, organization membership, and commit statuses. Tokens are encrypted at rest so a worker can post a commit status; API keys are random, shown once, indexed by an embedded UUID, and stored as salted SHA-256 digests. All application logs omit source, tokens, and request headers.

Users own tenant organizations and may add members with owner/admin/member roles. GitHub-backed organizations and repositories require a live GitHub membership/access check when linked. Every organization route verifies membership. PostgreSQL RLS policies on repositories, audits, and findings require a transaction-local organization ID, and the API/worker use a non-owner database role.

## Audit lifecycle

An API key resolves to one organization. In one database transaction the API locks the organization, enforces its UTC daily plan quota, creates a queued audit, and commits. It enqueues a bounded RQ job carrying the diff and identifiers; the job description never includes source. On enqueue failure the audit becomes `ERROR` and the API returns 503. The API waits up to two seconds for a completed row and otherwise returns its ID and `QUEUED` status.

The worker runs static/taint and Ollama analysis through the existing scanner functions, merges/downgrades/scores findings, persists metadata and findings, and posts a GitHub `failure` or `success` commit status when a linked repository and SHA are present. This status blocks a PR only when the repository config requires the `AI Guardian` status check. A model outage preserves static findings and marks semantic review incomplete in the summary. Failed jobs set `ERROR`.

## Storage and aggregates

The seven requested tables use UUID primary keys, foreign keys, indexes, and UTC timestamps. `users` also stores an encrypted GitHub token for authenticated repository links and commit statuses. `audits` stores an error-safe summary, but never raw source. Redis holds queued source only for the lifetime of a job; it is an internal service without a published port. Stats are scoped by organization and aggregate daily average risk, category counts, top repositories, and mean time to remediation from `fixed_at - created_at` on fixed findings. A finding-fix endpoint makes MTTR actionable.

## Operations

Compose starts PostgreSQL, Redis, a one-shot schema initializer, FastAPI, and an RQ worker. Local defaults are for development only; real hosting requires HTTPS, unique session/encryption secrets, GitHub OAuth credentials, database and Redis credentials, and an Ollama endpoint reachable by the worker. Tests use mocks for GitHub/Ollama plus a real PostgreSQL/Redis Compose integration path. GitHub credentials are never embedded in source.
