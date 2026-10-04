# AIGuardian Web Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working authenticated dashboard for hosted audits and a safe local demo.

**Architecture:** NextAuth retains the backend cookie server-side after a GitHub token exchange. A same-origin Next.js route forwards allowlisted, tenant-scoped requests. React pages display backend responses and use synthetic demo data only in development.

**Tech Stack:** Next.js 14 App Router, TypeScript, Tailwind, NextAuth v4, Recharts, shadcn-style UI components, FastAPI.

**Spec:** `docs/dashboard-web-design.md`

## Global Constraints

- Do not expose GitHub tokens, backend cookies, API keys, or raw diffs in logs or browser session JSON.
- Never persist a raw API key; clear it after its one-time dialog closes.
- Preserve the local scanner behavior and organization isolation.

## Review Focus

- A different organization's path must be rejected by the proxy.
- OAuth failure must not create a web session.
- Demo mode must remain disabled in production.
- Unlinked audits must explain why a diff is unavailable.
- Key revocation and findings filters must update the view immediately.

### Task 1: Backend integration

- [x] Test and implement verified GitHub access-token exchange, protected diff retrieval, and key revocation.
- [x] Run focused and full Python tests.

### Task 2: Web foundation and identity

- [x] Add Next.js project, Tailwind, UI primitives, NextAuth, typed API client, safe proxy, and demo fixture.
- [x] Test tenant path checks, demo guard, and API data mapping.

### Task 3: Dashboard pages

- [x] Build login, overview, repository list/detail, audit detail, settings, and key administration.
- [x] Test filters, polling state, and one-time key display.

### Task 4: Verification and documentation

- [x] Install dependencies; pass tests, TypeScript, build, and local HTTP checks.
- [x] Update README Current limits and `docs/architecture.md`.
- [x] Commit `feat: Next.js dashboard with stats, repos, audits`.
