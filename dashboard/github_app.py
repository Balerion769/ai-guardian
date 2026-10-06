"""GitHub App authentication and API helpers.

The private key is read from deployment configuration and is never included in
logs or persisted audit records. Installation tokens are short lived and are
requested for the exact installation that delivered a webhook.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
import jwt

from dashboard.config import Settings

logger = logging.getLogger(__name__)


async def installation_details(settings: Settings, installation_id: int) -> dict[str, Any]:
    """Read an installation owned by this App using its signed JWT."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{settings.github_api_url.rstrip('/')}/app/installations/{installation_id}",
            headers={"Authorization": f"Bearer {app_jwt(settings)}",
                     "Accept": "application/vnd.github+json"},
        )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("account"), dict):
        raise ValueError("Invalid GitHub installation response")
    if payload.get("suspended_at"):
        raise ValueError("GitHub installation is suspended")
    return payload


def app_jwt(settings: Settings) -> str:
    """Create a GitHub App JWT valid for at most ten minutes."""
    if not settings.github_app_id or not settings.github_app_private_key:
        raise RuntimeError("GitHub App credentials are not configured")
    try:
        app_id = int(settings.github_app_id)
    except ValueError as exc:
        raise RuntimeError("GITHUB_APP_ID must be numeric") from exc
    now = int(time.time())
    return str(jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": str(app_id)},
        settings.github_app_private_key,
        algorithm="RS256",
    ))


def installation_token(settings: Settings, installation_id: int) -> str:
    """Exchange the app JWT for a one-hour installation token."""
    if installation_id <= 0:
        raise ValueError("Invalid GitHub installation id")
    url = f"{settings.github_api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens"
    response = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {app_jwt(settings)}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15.0,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub did not return an installation token")
    return token


def pull_request_diff(settings: Settings, token: str, repository: str, pr_number: int) -> str:
    """Download a bounded pull request diff without logging its contents."""
    if not repository or "/" not in repository or pr_number < 1:
        raise ValueError("Invalid pull request reference")
    url = f"{settings.github_api_url.rstrip('/')}/repos/{repository}/pulls/{pr_number}"
    response = httpx.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3.diff",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30.0,
    )
    response.raise_for_status()
    diff = response.text
    if len(diff.encode("utf-8")) > 200_000:
        raise ValueError("Pull request diff exceeds 200,000 bytes")
    return diff


def create_check_run(
    settings: Settings,
    token: str,
    repository: str,
    commit_sha: str,
    *,
    conclusion: str,
    summary: str,
    details_url: str | None = None,
) -> None:
    """Publish a completed AI Guardian check run for a commit."""
    url = f"{settings.github_api_url.rstrip('/')}/repos/{repository}/check-runs"
    body: dict[str, Any] = {
        "name": "AI Guardian",
        "head_sha": commit_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "AI Guardian security audit",
            "summary": summary[:65_000],
        },
    }
    if details_url:
        body["details_url"] = details_url
    response = httpx.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json=body,
        timeout=15.0,
    )
    response.raise_for_status()
