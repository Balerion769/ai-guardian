# Stripe Billing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-organization Stripe subscriptions, webhook-driven entitlements, billing UI, and quota enforcement.

**Architecture:** Keep Stripe SDK calls in a billing service, tenancy and HTTP validation in a billing router, and quota checks in a shared admission helper. Persist subscription state and processed event IDs; migrate existing PostgreSQL organizations in place.

**Tech Stack:** FastAPI, SQLAlchemy, Stripe Python SDK, Next.js 14, NextAuth, Vitest, pytest.

**Spec:** `docs/billing-design.md`

## Tasks

- [ ] Add failing backend tests for plan limits, Checkout/portal ownership, signed idempotent webhooks, invoices, and past-due blocking.
- [ ] Implement Stripe catalog/provisioning, schema migration, billing router, notification, and audit admission; rerun backend tests.
- [ ] Add failing web tests for billing proxy boundaries and demo billing, then implement typed client, billing page, and settings navigation.
- [ ] Update environment examples and architecture/limits, run full test/build/smoke checks, review diff, and commit.
