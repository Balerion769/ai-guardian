"""GitHub OAuth login and cookie session endpoints."""

from __future__ import annotations

import hmac
import logging
import secrets
from collections.abc import Mapping

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from dashboard.config import get_settings
from dashboard.db.models import OrgMember, Organization, User
from dashboard.db.session import get_db
from dashboard.security import encrypt_github_token, require_user


auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _primary_verified_email(payload: object) -> str | None:
    """Select only a GitHub-verified address for owner billing notices."""
    if not isinstance(payload, list):
        return None
    for entry in payload:
        if isinstance(entry, dict) and entry.get("primary") and entry.get("verified"):
            address = entry.get("email")
            if isinstance(address, str) and "@" in address and len(address) <= 320:
                return address
    return None


def _github_client():
    settings = get_settings()
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub login unavailable")
    oauth = OAuth()
    oauth.register(
        name="github",
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url=settings.github_api_url.rstrip("/") + "/",
        client_kwargs={"scope": "read:user user:email read:org repo"},
    )
    return oauth.github


@auth_router.get("/github")
async def github_login(request: Request):
    try:
        request.session.clear()
    except AssertionError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Session unavailable") from exc
    state = secrets.token_urlsafe(32)
    request.session["github_oauth_state"] = state
    callback = get_settings().github_callback_url or str(request.url_for("github_callback"))
    return await _github_client().authorize_redirect(request, callback, state=state)


async def _complete_login(request: Request, db: Session, code: str, state: str, *, post: bool):
    expected = request.session.get("github_oauth_state")
    if not expected or not state or not hmac.compare_digest(expected, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OAuth state")
    if not code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing OAuth code")
    client = _github_client()
    try:
        if post:
            # Authlib's Starlette helper reads query parameters. JSON/form callbacks
            # use its token exchange directly after checking the same session state.
            token = await client.fetch_access_token(
                code=code,
                redirect_uri=get_settings().github_callback_url,
            )
        else:
            token = await client.authorize_access_token(request)
        access_token = token.get("access_token")
        if not access_token:
            raise ValueError("missing access token")
        response = await client.get("user", token=token)
        response.raise_for_status()
        profile = response.json()
        github_id = int(profile["id"])
        login = str(profile["login"])
        if not profile.get("email"):
            try:
                email_response = await client.get("user/emails", token=token)
                email_response.raise_for_status()
                profile["email"] = _primary_verified_email(email_response.json())
            except Exception as exc:
                logger.warning("github_email_unavailable error_type=%s", type(exc).__name__)
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub login failed") from exc
    finally:
        request.session.pop("github_oauth_state", None)

    return _store_github_user(request, db, profile, access_token)


def _store_github_user(request: Request, db: Session, profile: Mapping, access_token: str) -> dict[str, str | None]:
    """Persist a GitHub-verified identity and issue the hosted session."""
    github_id = int(profile["id"])
    login = str(profile["login"])
    user = db.scalar(select(User).where(User.github_id == github_id))
    if user is None:
        user = User(github_id=github_id, login=login)
        db.add(user)
    user.login = login
    user.email = profile.get("email")
    user.name = profile.get("name")
    user.avatar_url = profile.get("avatar_url")
    user.github_token_ciphertext = encrypt_github_token(access_token)
    db.flush()
    personal_org = db.scalar(select(Organization).where(
        Organization.owner_id == user.id, Organization.github_slug.is_(None)
    ).order_by(Organization.created_at).limit(1))
    if personal_org is None:
        personal_org = Organization(name=f"{login}'s workspace", owner_id=user.id)
        db.add(personal_org)
        db.flush()
        db.add(OrgMember(org_id=personal_org.id, user_id=user.id, role="owner"))
    db.commit()
    db.refresh(user)
    request.session.clear()
    request.session["user_id"] = str(user.id)
    return {"id": str(user.id), "login": user.login, "email": user.email,
            "org_id": str(personal_org.id)}


async def _complete_token_exchange(request: Request, db: Session, access_token: str) -> dict[str, str | None]:
    """Verify NextAuth's GitHub token with GitHub before trusting identity."""
    if not access_token or len(access_token) > 4096:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid GitHub token")
    url = get_settings().github_api_url.rstrip("/") + "/user"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            })
            response.raise_for_status()
            profile = response.json()
            if isinstance(profile, dict) and not profile.get("email"):
                try:
                    email_response = await client.get(
                        get_settings().github_api_url.rstrip("/") + "/user/emails",
                        headers={"Authorization": f"Bearer {access_token}",
                                 "Accept": "application/vnd.github+json"},
                    )
                    email_response.raise_for_status()
                    profile["email"] = _primary_verified_email(email_response.json())
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    logger.warning("github_email_unavailable error_type=%s", type(exc).__name__)
        if not isinstance(profile, dict) or not isinstance(profile.get("id"), int) or not profile.get("login"):
            raise ValueError("Invalid GitHub profile")
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub token verification failed") from exc
    return _store_github_user(request, db, profile, access_token)


@auth_router.get("/github/callback")
async def github_callback(request: Request, db: Session = Depends(get_db)):
    return await _complete_login(
        request,
        db,
        request.query_params.get("code", ""),
        request.query_params.get("state", ""),
        post=False,
    )


@auth_router.post("/github")
async def github_callback_post(request: Request, db: Session = Depends(get_db)):
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        return await _complete_token_exchange(request, db, authorization[7:].strip())
    if request.headers.get("content-type", "").startswith("application/json"):
        payload = await request.json()
    else:
        payload = await request.form()
    if not isinstance(payload, Mapping):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OAuth response")
    return await _complete_login(
        request, db, str(payload.get("code", "")), str(payload.get("state", "")), post=True
    )


@auth_router.get("/me")
def current_user(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    return {"id": str(user.id), "login": user.login, "email": user.email}


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request):
    request.session.clear()
