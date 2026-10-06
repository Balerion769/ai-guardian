"""Session-authenticated organization administration."""

from __future__ import annotations

import re
import secrets
from uuid import UUID, uuid4
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from starlette.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dashboard.config import get_settings
from dashboard.db.models import ApiKey, Organization, OrgMember, Repository, User
from dashboard.db.session import get_db, tenant_scope
from dashboard.github_app import installation_details
from dashboard.security import decrypt_github_token, hash_api_key, require_org_member, require_user


orgs_router = APIRouter(prefix="/api/v1/orgs", tags=["organizations"])
_GITHUB_SLUG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    github_slug: str | None = Field(default=None, max_length=39)


class MemberCreate(BaseModel):
    user_id: UUID
    role: str = "member"


class RepositoryCreate(BaseModel):
    github_repo_full_name: str = Field(min_length=3, max_length=200)


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class InstallationConnect(BaseModel):
    """Untrusted setup callback identifier, verified against GitHub before use."""
    installation_id: int = Field(strict=True, gt=0)


def _org_json(org: Organization, role: str | None = None) -> dict:
    result = {
        "id": str(org.id),
        "name": org.name,
        "github_slug": org.github_slug,
        "plan": org.plan,
        "daily_limit": org.daily_limit,
        "billing_status": org.billing_status,
    }
    if role is not None:
        result["role"] = role
    return result


async def _github_get(user: User, path: str) -> dict | list:
    if not user.github_token_ciphertext:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub login required")
    token = decrypt_github_token(user.github_token_ciphertext)
    url = get_settings().github_api_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub access check unavailable") from exc
    if response.status_code in (401, 403, 404):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "GitHub access required")
    if response.status_code != 200:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub access check unavailable")
    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(503, "Invalid GitHub response") from exc
    if not isinstance(payload, (dict, list)):
        raise HTTPException(503, "Invalid GitHub response")
    return payload


@orgs_router.get("/{org_id}/github-repos")
async def discover_repos(org_id: UUID, request: Request,
                         page: int = Query(default=1, ge=1, le=10000),
                         db: Session = Depends(get_db)) -> dict:
    """List paginated repository metadata accessible to the signed-in user."""
    user = require_user(request, db)
    require_org_member(org_id, user, db, "admin")
    org = db.get(Organization, org_id)
    payload = await _github_get(user, f"user/repos?per_page=100&page={page}&sort=updated")
    if not isinstance(payload, list):
        raise HTTPException(503, "Invalid GitHub repository response")
    items = []
    for repo in payload:
        if not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str):
            continue
        permissions = repo.get("permissions", {})
        if not isinstance(permissions, dict) or not (permissions.get("push") or permissions.get("admin")):
            continue
        if org.github_slug and repo["full_name"].split("/")[0].casefold() != org.github_slug.casefold():
            continue
        items.append({"full_name": repo["full_name"], "private": bool(repo.get("private")),
                      "default_branch": str(repo.get("default_branch") or "main")})
    return {"items": items, "next_page": page + 1 if len(payload) == 100 else None}


@orgs_router.get("/{org_id}/github-installation")
def installation_status(org_id: UUID, request: Request, db: Session = Depends(get_db)) -> dict:
    """Return the verified workspace installation identifier without credentials."""
    user = require_user(request, db)
    require_org_member(org_id, user, db)
    org = db.get(Organization, org_id)
    return {"installation_id": org.github_installation_id}


@orgs_router.post("/{org_id}/github-installation")
async def connect_installation(org_id: UUID, payload: InstallationConnect, request: Request,
                               db: Session = Depends(get_db)) -> dict:
    """Bind only an installation of this App owned by the workspace account."""
    user = require_user(request, db)
    require_org_member(org_id, user, db, "admin")
    org = db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
    try:
        details = await installation_details(get_settings(), payload.installation_id)
    except (httpx.HTTPError, RuntimeError, ValueError) as exc:
        raise HTTPException(503, "GitHub installation verification unavailable") from exc
    account = details["account"]
    owner = db.get(User, org.owner_id)
    if org.github_slug:
        valid = account.get("type") == "Organization" and str(account.get("login", "")).casefold() == org.github_slug.casefold()
    else:
        valid = account.get("type") == "User" and account.get("id") == owner.github_id
    if not valid:
        raise HTTPException(403, "Installation account does not own this workspace")
    existing = db.scalar(select(Organization.id).where(
        Organization.github_installation_id == payload.installation_id, Organization.id != org_id))
    if existing:
        raise HTTPException(409, "Installation already connected to another workspace")
    org.github_installation_id = payload.installation_id
    org.github_app_installed_at = datetime.now(timezone.utc)
    db.commit()
    return {"installation_id": payload.installation_id}


@orgs_router.post("", status_code=status.HTTP_201_CREATED)
async def create_org(payload: OrganizationCreate, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    db.scalar(select(User.id).where(User.id == user.id).with_for_update())
    free_orgs = db.scalar(select(func.count(Organization.id)).where(
        Organization.owner_id == user.id, Organization.plan == "free")) or 0
    if free_orgs >= 1:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Free plan allows one organization")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Organization name required")
    github_slug = payload.github_slug.strip().lower() if payload.github_slug else None
    if github_slug:
        if not _GITHUB_SLUG.fullmatch(github_slug):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid GitHub organization")
        if db.scalar(select(Organization.id).where(Organization.github_slug == github_slug)):
            raise HTTPException(status.HTTP_409_CONFLICT, "GitHub organization already linked")
        membership = await _github_get(user, f"user/memberships/orgs/{github_slug}")
        if membership.get("state") != "active":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Active GitHub membership required")
    org = Organization(name=name, github_slug=github_slug, owner_id=user.id)
    db.add(org)
    db.flush()
    db.add(OrgMember(org_id=org.id, user_id=user.id, role="owner"))
    result = _org_json(org, "owner")
    db.commit()
    return result


@orgs_router.get("")
def list_orgs(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    rows = db.execute(
        select(Organization, OrgMember.role)
        .join(OrgMember, OrgMember.org_id == Organization.id)
        .where(OrgMember.user_id == user.id)
        .order_by(Organization.created_at)
    ).all()
    return [_org_json(org, role) for org, role in rows]


@orgs_router.get("/{org_id}")
def get_org(org_id: UUID, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    member = require_org_member(org_id, user, db)
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return _org_json(org, member.role)


@orgs_router.post("/{org_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(org_id: UUID, payload: MemberCreate, request: Request, db: Session = Depends(get_db)):
    actor = require_user(request, db)
    require_org_member(org_id, actor, db, "admin")
    if payload.role not in ("admin", "member"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid member role")
    target_user = db.get(User, payload.user_id)
    if target_user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    organization = db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if organization.plan in {"pro", "team"} and organization.stripe_subscription_id:
        member_count = db.scalar(select(func.count(OrgMember.id)).where(OrgMember.org_id == org_id)) or 0
        if member_count >= organization.seat_count:
            raise HTTPException(status.HTTP_409_CONFLICT, "Increase billed seats in the Stripe portal first")
    if organization.github_slug:
        membership = await _github_get(target_user, f"user/memberships/orgs/{organization.github_slug}")
        if membership.get("state") != "active":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Active GitHub membership required")
    existing = db.scalar(
        select(OrgMember).where(OrgMember.org_id == org_id, OrgMember.user_id == payload.user_id)
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Already a member")
    member = OrgMember(org_id=org_id, user_id=payload.user_id, role=payload.role)
    db.add(member)
    db.flush()
    result = {"user_id": str(member.user_id), "role": member.role}
    db.commit()
    return result


@orgs_router.get("/{org_id}/members")
def list_members(org_id: UUID, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_org_member(org_id, user, db)
    members = db.execute(select(OrgMember, User).join(User, User.id == OrgMember.user_id)
                         .where(OrgMember.org_id == org_id)).all()
    return [{"user_id": str(member.user_id), "role": member.role,
             "login": member_user.login, "email": member_user.email,
             "avatar_url": member_user.avatar_url} for member, member_user in members]


@orgs_router.post("/{org_id}/repos", status_code=status.HTTP_201_CREATED)
async def add_repo(org_id: UUID, payload: RepositoryCreate, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_org_member(org_id, user, db, "admin")
    full_name = payload.github_repo_full_name.strip()
    if not _REPO_NAME.fullmatch(full_name) or ".." in full_name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid GitHub repository")
    org = db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    tenant_scope(db, org_id)
    if org.plan == "free":
        repo_count = db.scalar(select(func.count(Repository.id)).where(Repository.org_id == org_id)) or 0
        if repo_count >= 3:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Free plan allows three repositories")
    if org.github_slug and full_name.split("/", 1)[0].casefold() != org.github_slug.casefold():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Repository owner differs from organization")
    github_repo = await _github_get(user, f"repos/{full_name}")
    if github_repo.get("full_name", "").casefold() != full_name.casefold():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "GitHub repository access required")
    permissions = github_repo.get("permissions")
    if not isinstance(permissions, dict) or not any(permissions.get(p) for p in ("push", "admin")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "GitHub repository access required")
    existing = db.scalar(
        select(Repository).where(
            Repository.org_id == org_id,
            Repository.github_repo_full_name == github_repo["full_name"],
        )
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Repository already linked")
    repo = Repository(org_id=org_id, github_repo_full_name=github_repo["full_name"],
                      default_branch=str(github_repo.get("default_branch") or "main")[:255])
    db.add(repo)
    db.flush()
    result = {"id": str(repo.id), "github_repo_full_name": repo.github_repo_full_name,
              "default_branch": repo.default_branch}
    db.commit()
    return result


@orgs_router.get("/{org_id}/repos")
def list_repos(org_id: UUID, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_org_member(org_id, user, db)
    tenant_scope(db, org_id)
    repos = db.scalars(select(Repository).where(Repository.org_id == org_id)).all()
    return [{"id": str(repo.id), "github_repo_full_name": repo.github_repo_full_name,
             "default_branch": repo.default_branch, "is_active": repo.is_active,
             "last_audit_at": repo.last_audit_at} for repo in repos]


@orgs_router.post("/{org_id}/api-keys", status_code=status.HTTP_201_CREATED)
@orgs_router.post("/{org_id}/keys", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_api_key(org_id: UUID, payload: ApiKeyCreate, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_org_member(org_id, user, db, "admin")
    key_id = uuid4()
    prefix = f"ag_live_{key_id}_"
    raw = prefix + secrets.token_urlsafe(36)
    salt = secrets.token_hex(16)
    key = ApiKey(
        id=key_id,
        org_id=org_id,
        name=payload.name.strip(),
        key_prefix=prefix,
        key_last4=raw[-4:],
        salt=salt,
        key_hash=hash_api_key(raw, salt),
        created_by=user.id,
    )
    if not key.name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Key name required")
    db.add(key)
    db.commit()
    return {"id": str(key_id), "name": key.name, "prefix": prefix, "last4": key.key_last4, "key": raw}


@orgs_router.get("/{org_id}/keys")
def list_api_keys(org_id: UUID, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_org_member(org_id, user, db, "admin")
    keys = db.scalars(select(ApiKey).where(ApiKey.org_id == org_id)).all()
    return [
        {
            "id": str(key.id), "name": key.name, "prefix": key.key_prefix,
            "last4": key.key_last4, "revoked": key.revoked_at is not None,
        }
        for key in keys
    ]


@orgs_router.delete("/{org_id}/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(org_id: UUID, key_id: UUID, request: Request,
                   db: Session = Depends(get_db)) -> Response:
    """Revoke a tenant key immediately; the raw value cannot be recovered."""
    from datetime import datetime, timezone

    user = require_user(request, db)
    require_org_member(org_id, user, db, "admin")
    key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == org_id))
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
