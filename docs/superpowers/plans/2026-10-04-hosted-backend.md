# Hosted AIGuardian Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a tenant-isolated hosted audit API backed by PostgreSQL and Redis while retaining the local scanner.

**Architecture:** `dashboard/` owns identity, persistence, queueing, and statistics. Existing scanner modules remain the analysis library. Hosted mode swaps the FastAPI app at startup.

**Tech Stack:** FastAPI, Pydantic v2, SQLAlchemy 2, PostgreSQL, Redis/RQ, Authlib, httpx, Docker Compose.

**Spec:** `docs/hosted-backend-design.md`

## Global Constraints

- Do not log diffs, OAuth tokens, API keys, or model raw output.
- Validate every request/response; authorize every tenant route and enforce PostgreSQL RLS for tenant data.
- Keep `main:app` local behavior unchanged unless `AIGUARDIAN_MODE=hosted`.
- Preserve existing scanner behavior and test suite.

## Review Focus

- Cross-tenant ID probing must return no data.
- Simultaneous quota requests must not exceed plan limits.
- Queue outage must not leave a queued audit indefinitely.
- Invalid OAuth state or revoked token must fail closed.
- GitHub status posting failure must not erase persisted findings.

### Task 1: Persistence and tenant policies

- [x] Add seven SQLAlchemy models and constraints in `dashboard/db/models.py`.
- [x] Add engine/session helpers and idempotent schema initialization with PostgreSQL RLS.
- [x] Test schema and organization isolation.

### Task 2: Identity and organization API

- [x] Add Authlib GitHub login/callback and encrypted token storage.
- [x] Add session-authenticated organization, membership, repository, and key endpoints.
- [x] Test state validation, key hashing, and cross-tenant access.

### Task 3: Queue and worker

- [x] Add RQ enqueue, scanner execution, persistence, error status, and GitHub commit status.
- [x] Test successful, model-failure, queue-failure, and GitHub-failure paths.

### Task 4: Hosted audit and reporting API

- [x] Add API-key protected enqueue route, quota handling, two-second fast path, audit list/detail, stats, and fixed finding mutation.
- [x] Test quotas, audit persistence, status, filters, and aggregates.

### Task 5: Deployment and verification

- [x] Add Dockerfile, Compose stack, environment configuration, and hosted setup docs.
- [x] Run unit suite and Compose integration with PostgreSQL/Redis.
- [ ] Update README Current limits and `docs/architecture.md`; commit conventional message.
