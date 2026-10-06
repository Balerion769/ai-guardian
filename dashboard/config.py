"""Validated environment configuration for the hosted service."""

from __future__ import annotations

import os
import base64
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Deployment settings loaded once per request or worker job."""

    database_url: str
    redis_url: str
    github_client_id: str
    github_client_secret: str
    github_callback_url: str
    github_api_url: str
    session_secret: str
    token_encryption_key: str
    public_base_url: str
    ollama_url: str
    ollama_model: str
    dev_mode: bool
    stripe_secret_key: str
    stripe_webhook_secret: str
    stripe_price_pro: str
    stripe_price_team: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    billing_email_from: str
    web_base_url: str
    github_app_id: str
    github_app_private_key: str
    github_app_webhook_secret: str
    github_app_install_url: str
    sentry_dsn: str
    sentry_environment: str
    static_only_mode: bool = False
    inline_audits: bool = False

    @property
    def secure_cookie(self) -> bool:
        """Require HTTPS session cookies outside explicit local development."""
        return not self.dev_mode


def database_url() -> str:
    """Use configured storage; permit ephemeral SQLite only in explicit local dev."""
    return os.getenv("DATABASE_URL", "") or (
        "sqlite+pysqlite:///./dashboard-local.db" if os.getenv("DASHBOARD_DEV_MODE", "0") == "1" else ""
    )


def get_settings() -> Settings:
    """Read environment without caching, allowing isolated test configuration."""
    dev_mode = os.getenv("DASHBOARD_DEV_MODE", "0") == "1"
    session_secret = os.getenv("DASHBOARD_SESSION_SECRET", "")
    encryption_key = os.getenv("DASHBOARD_TOKEN_ENCRYPTION_KEY", "")
    if dev_mode and not encryption_key and session_secret:
        encryption_key = base64.urlsafe_b64encode(hashlib.sha256(session_secret.encode()).digest()).decode()
    settings = Settings(
        database_url=database_url(),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        github_client_id=os.getenv("GITHUB_CLIENT_ID", ""),
        github_client_secret=os.getenv("GITHUB_CLIENT_SECRET", ""),
        github_callback_url=os.getenv("GITHUB_CALLBACK_URL", "http://127.0.0.1:8000/api/v1/auth/github/callback"),
        github_api_url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
        session_secret=session_secret,
        token_encryption_key=encryption_key,
        public_base_url=os.getenv("DASHBOARD_PUBLIC_BASE_URL", "http://127.0.0.1:8000"),
        ollama_url=os.getenv("OLLAMA_URL", "http://ollama:11434/api/generate"),
        ollama_model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder"),
        dev_mode=dev_mode,
        stripe_secret_key=os.getenv("STRIPE_SECRET_KEY", ""),
        stripe_webhook_secret=os.getenv("STRIPE_WEBHOOK_SECRET", ""),
        stripe_price_pro=os.getenv("STRIPE_PRICE_PRO", ""),
        stripe_price_team=os.getenv("STRIPE_PRICE_TEAM", ""),
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_username=os.getenv("SMTP_USERNAME", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        billing_email_from=os.getenv("BILLING_EMAIL_FROM", ""),
        web_base_url=os.getenv("DASHBOARD_WEB_BASE_URL", "http://localhost:3000"),
        github_app_id=os.getenv("GITHUB_APP_ID", ""),
        github_app_private_key=os.getenv("GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n"),
        github_app_webhook_secret=os.getenv("GITHUB_APP_WEBHOOK_SECRET", ""),
        github_app_install_url=os.getenv("GITHUB_APP_INSTALL_URL", ""),
        sentry_dsn=os.getenv("SENTRY_DSN", ""),
        sentry_environment=os.getenv("SENTRY_ENVIRONMENT", "production"),
        static_only_mode=os.getenv("STATIC_ONLY_MODE", "0") == "1",
        inline_audits=os.getenv("INLINE_AUDITS", "0") == "1",
    )
    if not settings.database_url:
        raise ValueError("DATABASE_URL is required for hosted mode")
    if len(settings.session_secret) < 32:
        raise ValueError("DASHBOARD_SESSION_SECRET must contain at least 32 characters")
    if not settings.token_encryption_key:
        raise ValueError("DASHBOARD_TOKEN_ENCRYPTION_KEY is required")
    if not settings.dev_mode and not settings.public_base_url.startswith("https://"):
        raise ValueError("DASHBOARD_PUBLIC_BASE_URL must use HTTPS outside development")
    if not settings.dev_mode and not settings.web_base_url.startswith("https://"):
        raise ValueError("DASHBOARD_WEB_BASE_URL must use HTTPS outside development")
    return settings
