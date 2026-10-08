# Manual branch audits

1. Sign in and link a repository under **Repositories**.
2. Click **Audit** beside the repository, or open its name.
3. Select a branch. Use **Load more branches** when the repository has more than 100 branches.
4. Click **Audit now**. The audit detail page polls until the saved audit completes and shows its branch, immutable commit SHA, findings, model, and diff.

The scope is the **latest commit changes**, as returned by GitHub's commit diff endpoint. It is not a complete source-tree scan or a comparison against the default branch. A merge commit uses GitHub's commit-diff semantics.

## API

Both endpoints require an authenticated dashboard session and membership in the workspace:

- `GET /api/v1/orgs/{org_id}/repos/{repo_id}/branches?page=1`: returns `items: [{name}]` and `next_page`.
- `POST /api/v1/orgs/{org_id}/repos/{repo_id}/audits` with `{"branch":"feature/security"}`: resolves the live ref, reserves plan quota, and returns HTTP 202 with `audit_id`, `status: QUEUED`, `branch`, and `commit_sha`.

The browser uses the tenant-restricted Next.js proxy; OAuth credentials remain on the backend. Mutations require the same origin. Queue jobs contain only audit/workspace/user IDs. The worker rechecks membership and active repository state, fetches the pinned SHA using the initiating user's encrypted OAuth credential, bounds the diff, and invokes the shared scanner. It does not retain the diff in the database.

Anonymous requests return 401, unknown workspaces/repositories 404, inactive repositories 409, invalid refs 422, quota exhaustion 429, and unavailable GitHub/queue services 503. Failures after acceptance become saved `ERROR` results. Do not automatically retry a timed-out submission: it may already have reserved an audit; check history first.

## Operating limits

- Maximum commit diff: 200,000 UTF-8 bytes and 2,000 added lines.
- Existing static/taint/LLM behavior is reused, including static fallback when the local LLM is unavailable. Check the result summary for incomplete semantic review.
- Mixed-language patches currently choose the first supported file language; findings are advisory and a clean result is not proof of security.
- `INLINE_AUDITS=1` or static-only mode executes after response acknowledgement in the API process. Restarts can interrupt these jobs; retry explicitly after checking history. Redis/RQ mode provides a separate worker queue.
- Repeated deliberate clicks after completion create separate audits and consume quota. The UI prevents duplicate submissions while a request is pending.

## Verification

`python -m pytest tests/test_repository_audits.py` verifies immutable branch selection, tenancy, quota, queue failure, bounds, persisted safe/vulnerable scanner results, and rejected refs. `npm test` in `dashboard/web` verifies branch selection/pagination, stale responses, submission errors, duplicate-click protection, and proxy scope. Production compilation is checked with `npm run build`.
