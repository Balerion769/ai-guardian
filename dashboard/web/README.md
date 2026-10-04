# AI Guardian dashboard

The web dashboard uses Next.js 14 App Router, Tailwind CSS, NextAuth, Recharts, and local shadcn-style UI components. It displays organization statistics, repositories, audit history, findings, and API keys from the hosted FastAPI service.

## Run a local demo

```powershell
cd dashboard/web
npm install
npm run dev
```

Open `http://localhost:3000/login` and select **Explore interactive demo**. Demo mode is enabled only during development when GitHub credentials are absent. It uses synthetic audits and sample keys, makes no hosted database changes, and its generated keys cannot authenticate against FastAPI. The dashboard runs without PostgreSQL, Redis, Ollama, or GitHub in this mode.

## Connect GitHub and FastAPI

Start the hosted backend from the repository root with `docker compose up --build -d`. Create a GitHub OAuth app whose callback URL is `http://localhost:3000/api/auth/callback/github`. Copy `.env.example` to `.env.local` and set `GITHUB_ID`, `GITHUB_SECRET`, a random `NEXTAUTH_SECRET`, and `BACKEND_API_URL=http://127.0.0.1:8001`. Then restart `npm run dev`. For deployment, set public HTTPS URLs and secrets through your deployment platform. The GitHub app must grant `read:user`, `read:org`, and `repo` scopes for private repository access and commit statuses.

NextAuth exchanges the GitHub access token with `POST /api/v1/auth/github`. FastAPI verifies it with GitHub, creates the user and personal workspace if needed, and returns a signed backend session cookie. The encrypted NextAuth session retains that cookie server-side; same-origin route handlers proxy an allowlisted set of organization requests. Browser JavaScript receives only dashboard data and the active organization ID.

Linked audit diffs are fetched from GitHub when an audit detail page opens. They are not retained in the audit database. An audit without a linked PR or commit displays an unavailable state. Audit status refreshes every five seconds while queued or running.

The API-key dialog shows the raw value once. Closing it discards the value from component state; the key list contains only its prefix and last four characters. Billing under **Settings → Billing** shows today's usage, configured plans, and Stripe invoices. Checkout and portal navigation use short-lived URLs created by the hosted API. In local demo mode, an upgrade changes synthetic in-memory data only.

The **Settings → GitHub App** page links to `NEXT_PUBLIC_GITHUB_APP_INSTALL_URL`. After creating the App, configure the backend webhook and private-key variables described in [`docs/github-app.md`](../../docs/github-app.md).

## Verification

```powershell
npm test
npm run typecheck
npm run lint
npm run build
```

The real GitHub OAuth flow needs your OAuth app credentials and an accessible hosted API. The automated suite uses mock GitHub responses and tests the dashboard's demo mode, filters, tenant proxy boundary, and one-time key dialog.

Next.js 14 is included as requested. Its current upstream dependency audit reports one critical and one high issue (`npm audit --omit=dev`). The development server binds to loopback. Upgrade to a supported patched Next.js release and rerun the audit before a public deployment.
