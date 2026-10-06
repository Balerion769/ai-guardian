# AIGuardian architecture

## Free hosting profile

The verified public deployment uses `ai-guardian-theta.vercel.app` for the web
dashboard and `ai-guardian-api-vwj7.onrender.com` for FastAPI. Both track
`ast-security-rules`. On October 5, 2026, GitHub OAuth completed, the API
created a personal workspace in Neon, and dashboard statistics loaded through
the authenticated server proxy. The runtime database role is
`guardian_runtime`, with `rolsuper=false` and `rolbypassrls=false`; migrations
use the separate schema owner. The API is in Singapore and the existing Neon
project is in Ohio, so this deployment incurs cross-region database latency.

`render.yaml` deploys one free Python API in Singapore. `dashboard.api.main:app`
exposes the hosted app; `dashboard.free_start` applies Alembic then starts one
Uvicorn worker using `PORT`. Neon supplies durable PostgreSQL; Vercel deploys
`dashboard/web` with `vercel.json`. Schema-owner migrations and a non-owner
runtime role preserve forced tenant RLS. Only explicit local development may
use a SQLite fallback; a configured database is never silently replaced.

With `STATIC_ONLY_MODE=1`, authenticated audit submissions and verified GitHub
PR webhooks execute the existing worker function within the request after the
audit row commits. No Redis connection or Ollama request occurs. The worker
persists static plus taint results with `model_used=static-only`; a static
engine failure is `ERROR`, never a clean approval. This avoids paid background
workers and incomplete queued jobs when the free API sleeps. Regular hosting
keeps the existing RQ flow when the flag is off.

The dashboard retains its same-origin `/api/dashboard` proxy and private
backend session cookie. Server upstream configuration resolves
`BACKEND_API_URL`, then `NEXT_PUBLIC_API_URL`, then the local development URL.
Browser, proxy, and OAuth exchanges cancel stalled fetches after 10 seconds,
without automatic mutation retries. Cold starts can exceed this timeout.
`/` and `/health` use no database connection. See [DEPLOY_FREE.md](../DEPLOY_FREE.md)
for provider quotas, sign-in, migration roles, and complete-flow verification.

## Request flow

`POST /api/v1/audit` accepts strict `AuditRequest` fields `diff_content` and `language`. Pydantic rejects unknown fields and inputs over 200,000 characters; the route rejects more than 2,000 added lines with HTTP 413. SlowAPI limits the route to 60 requests per minute per client IP.

The route records a SHA-256 hash of the submitted text for diagnostics. It runs `StaticAnalyzer`, then the Python taint pass, then Ollama review. Results are combined by normalized category and line; the higher severity wins. The response contains `status`, `risk_score`, `vulnerabilities`, `summary`, `static_count`, `ai_count`, `latency_ms`, and `model_used`. Each finding has severity, category, description, line reference, remediation, confidence, and a taint marker.

Local API remediation fields contain unified diffs. Supported single-line Python AST shapes produce source edits for literal parsing, disabling `exec`, and loading literal secrets from environment variables. Other findings produce an `AI_GUARDIAN_REVIEW.txt` patch containing explicit review guidance. Model prose is never inserted into executable source. Applying a fix remains a user action, and changes such as disabling `exec` deliberately change application behavior.

`GET /health` reports process status and the configured model name. `GET /metrics` reports process-local audit/finding counts. Health does not probe Ollama.

## Static syntax analysis

`scanner/static_rules.py` reconstructs new-file line numbers from Git hunks and selects only added lines; plain snippets treat every line as added. The public `get_added_lines` helper returns `(line_number, text)` pairs. Candidate windows keep 200,000-character scans bounded. Python uses `ast`; JavaScript and TypeScript use tree-sitter, with esprima as a JavaScript fallback. Dotenv assignments use key/value parsing because that format has no Python or JavaScript AST.

Twenty rule families cover dynamic execution, command and SQL injection, embedded secrets, traversal, SSRF, template injection, deserialization, weak crypto, signing keys, DOM XSS, wildcard CORS, debug mode, fixed private-IP calls, disabled TLS verification, world-writable permissions, and insecure temporary files. Findings include a replacement code example. More than 128 suspicious lines are sampled in normal requests and produce a high-severity `Analysis Incomplete` finding; `BENCHMARK_MODE=1` inspects every candidate for recall measurement. Incomplete hunks can lose multiline context; unsupported languages have no static syntax rules.

`scanner/taint.py` tracks Python Flask/Django request attributes, FastAPI `Request` parameters, `input()`, `sys.argv`, `os.environ`, and `os.environ.get` through local assignments to selected sinks. A parameterized SQL query is not reported solely because its parameter value is tainted. This analysis is intraprocedural and neither branch-sensitive nor alias-complete.

## Ollama analysis

`scanner/ai_auditor.py` sends the submitted change to Ollama's `/api/generate` endpoint with `stream: false`, temperature 0, and a JSON schema. Its system prompt treats source text as untrusted data and requests only concrete findings on introduced lines. The Ollama envelope and each finding are Pydantic-validated. Confidence below 0.6 is dropped; same-line/category duplicates keep the higher severity. Invalid output triggers up to three repair prompts inside a five-second total deadline. Exhausted repairs produce `Analysis Incomplete`.

An Ollama transport error or timeout yields the available static findings and an incomplete-analysis summary. HTTP 503 is returned only if both static and model passes fail. Logs contain the diff hash and counts. They do not include source, model output, or Authorization headers.

## Scoring and deployment

A retained HIGH adds 40 points, MEDIUM 15, LOW 5, and a tainted finding adds 10 more. Risk caps at 100. A finding in a test/example path is downgraded one severity step before scoring. Any retained HIGH yields `FAILED`; otherwise the status is `PASSED`. A PASSED result may contain medium/low findings and does not prove the code is secure.

The intended local deployment binds to `127.0.0.1`. Local mode has no authentication or TLS. Use an authenticated reverse proxy if exposing it. The in-memory rate limit and metrics are per process; multi-worker deployments need a shared rate-limit backend. `OLLAMA_URL` may cross a network boundary and sends the full source to that endpoint.

## GitHub Action boundary

The composite Action at the repository root and under `.github/actions/ai-guardian/` runs the trusted `audit_pr.py` script. It reads a Git comparison as data, splits it by file, and calls the configured API or imports the trusted static scanner directly. It never imports code from the checked-out PR. The default API URL is localhost; a remote URL is an explicit source-transfer boundary. A failed API call falls back to static analysis. Unsupported code languages in static-only mode and oversized source files produce HIGH `Analysis Incomplete` findings.

The PR comment contains only file, line, severity, an allowlisted category, and fixed remediation guidance. No code or model-authored text is included. Posting requires a write-capable GitHub token; fork PRs commonly have read-only tokens. The example uses `pull_request` rather than privileged `pull_request_target`. The published `@v1` reference requires a pushed release tag, which is separate from this local commit.

## Hosted mode

`AIGUARDIAN_MODE=hosted` replaces the local FastAPI route table at startup while retaining the scanner as a library. Docker Compose runs PostgreSQL, Redis, a one-shot schema initializer, the hosted API, and an RQ worker. Local mode remains the default. Hosted requests use GitHub OAuth browser sessions for organization management and a salted SHA-256 `X-API-Key` for audit submission. Raw API keys are returned once. GitHub tokens are encrypted at rest for repository access checks and commit statuses. Every organization route checks membership; PostgreSQL FORCE RLS on repositories, audits, and findings requires a transaction-local organization ID under a non-owner app role.

Audit submission locks the organization row before counting the current UTC day's audits, reserves a quota slot, and enqueues a bounded job. Free allows 100 audits/day, pro 1000, and enterprise has no daily limit. The worker executes the existing static, taint, and Ollama passes, persists only metadata/findings, and updates the GitHub commit status for a linked repository and SHA. `failure` status blocks a PR only if branch protection requires the `AI Guardian` context. An exception in the worker marks the audit `ERROR`; a queue outage marks the reserved audit `ERROR` and returns HTTP 503. Source exists temporarily in Redis job arguments and is deleted on job completion or failure; job descriptions and application logs omit it.

Organization audit history is filterable by repository, severity, and 7/30/90-day range. Statistics use SQL aggregates for daily mean risk, finding categories, and vulnerable repository ranking, plus mean hours from finding creation to fixed time. A development-only smoke command creates synthetic credentials, runs the real HTTP/Redis/PostgreSQL path, verifies that RLS hides audits without tenant context, and removes its data. OAuth needs real GitHub credentials for live sign-in; tests mock GitHub interactions.

The Compose file binds the hosted API to loopback port 8001 with development defaults. Production must provide HTTPS, unique secrets, private PostgreSQL/Redis, and a trusted model endpoint. New deployments run the Alembic `0001_initial_schema` revision; rolling schema upgrades must add a new versioned migration before deployment.

## Verification and current limits

The web dashboard under `dashboard/web/` uses patched Next.js 15.5.27 App Router, NextAuth GitHub OAuth, Tailwind, Recharts, and local shadcn-style components. The NextAuth sign-in callback exchanges its provider access token with the hosted backend, which verifies it against GitHub and creates a personal workspace. The backend's signed session cookie remains inside the encrypted NextAuth token. A same-origin route handler validates the active organization, HTTP method, path, and mutation origin before forwarding requests. Development-only demo mode returns synthetic data instead of contacting FastAPI. Audit detail polls queued/running status every five seconds, and a protected backend route streams a linked GitHub diff with a 200,000-byte display limit. API key creation displays the raw value once; revocation updates the backend key record. The browser never receives GitHub tokens or backend cookies. Real OAuth needs user-configured GitHub credentials and has not been exercised in the mock test suite. `npm audit --omit=dev` is clean with the lockfile's PostCSS 8.5.28 override.

Billing uses configured Stripe Price IDs for Pro and Team Checkout. The owner starts Checkout and portal sessions; the API never accepts an arbitrary client Price ID. A signed Stripe webhook is checked against the raw request body, recorded by event ID, and applies plan/subscription changes only for matching customers and current subscriptions. A payment failure marks the organization `past_due`, blocks API-key audit submissions, and sends an owner notification when SMTP is configured. Members retain dashboard read access during payment recovery. The subscription's licensed quantity is recorded as billed seats, and paid organizations cannot add more members or submit audits beyond that quantity. A separate retention process runs hourly with tenant-scoped deletes.

The initial PostgreSQL initializer also applies idempotent billing column and constraint changes to existing hosted databases; it converts legacy `enterprise` plans to `team`. New deployments use the Alembic `0001_initial_schema` revision and run `alembic upgrade head` as the release command. Billing is per organization. Local development without Stripe keys exposes an owner-authenticated manual plan activation endpoint; it is absent in configured or production mode. Real Stripe test-mode checkout and webhook delivery require user-provided Stripe credentials and are not covered by mock tests. Future plan features are labeled planned in the UI.

## Production cloud deployment and GitHub App

App JWTs carry a string issuer (numeric App ID represented as text), RS256 signatures, and a maximum nine-minute future lifetime, with a one-minute clock-skew allowance.

GitHub setup callback identifiers are untrusted. An authenticated workspace administrator binds an installation only after App-JWT verification of account ownership; installation IDs are unique across workspaces. Signed PR deliveries resolve the tenant by stored installation and validate the repository owner. Unlinked or paused repositories are ignored. PR and API-key audits share billing admission checks. Repository discovery uses encrypted OAuth credentials server-side and returns paginated metadata only. The Next.js proxy limits operations to the active tenant and checks mutation origin.

`docker-compose.prod.yml` builds separate Python 3.11 API and worker images plus the Next.js image. PostgreSQL, Redis, the schema initializer, API, worker, and web service have health checks; the API and web ports should be placed behind HTTPS while PostgreSQL and Redis stay private. `.env.prod.example` lists the required database, OAuth, Stripe, Ollama, Sentry, and GitHub App settings. Fly.io, Render, and Railway component deployment notes are in [`DEPLOY.md`](../DEPLOY.md).

The GitHub App webhook at `POST /api/v1/webhooks/github` accepts only signed `pull_request.opened` and `pull_request.synchronize` events. It resolves the linked organization, records the installation ID, obtains a short-lived installation token, downloads a bounded diff, and queues the same worker used by API-key submissions. The worker creates a completed `AI Guardian` check run with `failure` for retained HIGH findings and `success` otherwise. The App must be created in GitHub Developer Settings with contents read, pull requests read/write, and checks write; the setup steps are in [`docs/github-app.md`](github-app.md).

Hosted `/metrics` exposes Prometheus counters for completed audits, an audit latency histogram, and an LLM error-rate gauge. Sentry is opt-in through `SENTRY_DSN`; request bodies and headers are scrubbed before events are sent.

The VS Code extension under `vscode-extension/` activates for Python, JavaScript, and TypeScript. It posts a whole small file or a 200-line visible window to the audit API and maps relative API line references back to editor positions. Diagnostics, status bar state, save scans, optional debounced typing scans, and explicit commands run in the extension host. Requests have a seven-second client deadline; stale results are discarded by document version and superseded request controller. API errors trigger five local heuristic patterns, which are deliberately narrower than backend AST and taint analysis. A file over 200,000 characters is skipped. Five precise findings offer code actions: literal parsing for `eval`, disabling dynamic `exec`, `textContent` for `innerHTML`, environment loading for passwords, and environment loading for AWS keys. A custom remote API URL transfers source out of the machine.

`npm test` in the extension runs 11 offline rule tests and six CodeAction edit tests after strict TypeScript compilation. Secret environment edits in JavaScript/TypeScript require Node.js; browser applications need a server-side secret store. VS Code host integration and Marketplace packaging require manual verification in an Extension Development Host.

The extension includes `.vscode/launch.json` and `.vscode/tasks.json` so F5 compiles and launches the extension in a development host. The host can test offline fallback without the backend; model-assisted findings require the API and Ollama processes.

The unit suite uses mock Ollama transport. `tests/test_rules.py` has 20 vulnerable and 20 safe cases; `tests/test_taint.py` covers request, environment, CLI, and propagation flows. `tests/test_audit.py` checks contracts, repair, fallback, deduplication, logging privacy, unified remediation diffs, and the 200,000-character performance path.

`BENCHMARK_MODE=1 python -m tests.owasp_benchmark` downloads 50 labeled Python files from official OWASP BenchmarkPython v0.1 commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`: 25 true and 25 false cases selected with seed 42. It disables the production candidate cap and scores static plus taint analysis only. The measured table here was TP=15, FP=1, FN=10, TN=24 (precision 0.938, recall 0.600). The limited sample still misses framework-specific and interprocedural flows; model-assisted accuracy has not been measured by this benchmark.
