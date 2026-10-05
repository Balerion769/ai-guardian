"""Hosted FastAPI application with GitHub login and tenant-scoped APIs."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import Response as FastAPIResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from dashboard.api.audits import router as audits_router
from dashboard.api.billing import billing_router
from dashboard.api.auth import auth_router
from dashboard.api.orgs import orgs_router
from dashboard.api.github_webhooks import github_webhook_router
from dashboard.config import get_settings
from dashboard.observability import configure_sentry, metrics_payload


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Build the hosted API with secure cookies and no source-bearing logs."""
    settings = get_settings()
    configure_sentry(settings.sentry_dsn, settings.sentry_environment)
    app = FastAPI(title="AIGuardian Hosted", version="1.0.0")
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        https_only=settings.secure_cookie,
        same_site="lax",
        max_age=60 * 60 * 8,
    )

    @app.middleware("http")
    async def safe_request_logging(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Log only tenant identity and outcome, excluding body and credentials."""
        response = await call_next(request)
        org_id = getattr(request.state, "org_id", None) or request.path_params.get("org_id")
        logger.info("hosted_request org_id=%s status=%d", org_id or "none", response.status_code)
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        """Report process readiness without exposing configuration or credentials."""
        return {"status": "ok", "model": "static-only" if settings.static_only_mode else settings.ollama_model}

    @app.get("/")
    def landing() -> dict[str, str]:
        """Expose public documentation without querying storage."""
        return {"message": "AI Guardian API live", "docs": "/docs"}

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> FastAPIResponse:
        """Expose process metrics for Prometheus scraping."""
        payload, content_type = metrics_payload()
        return FastAPIResponse(content=payload, headers={"Content-Type": content_type})

    app.include_router(auth_router)
    app.include_router(orgs_router)
    app.include_router(audits_router)
    app.include_router(billing_router)
    app.include_router(github_webhook_router)
    return app
