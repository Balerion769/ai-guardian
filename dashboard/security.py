"""Authentication and tenant authorization for the hosted API."""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from dashboard.config import get_settings
from dashboard.db.models import ApiKey, OrgMember, User


_KEY_PATTERN = re.compile(r"^ag_live_([0-9a-fA-F-]{36})_([A-Za-z0-9_-]{32,})$")
_ROLE_RANK = {"member": 0, "admin": 1, "owner": 2}


def _fernet() -> Fernet:
    key = get_settings().token_encryption_key
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_github_token(token: str) -> str:
    return _fernet().encrypt(token.encode()).decode()


def decrypt_github_token(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub credentials unavailable") from exc


def hash_api_key(raw_key: str, salt: str) -> str:
    """Hash a key with a unique random hex salt."""
    return hashlib.sha256(bytes.fromhex(salt) + raw_key.encode()).hexdigest()


def authenticate_api_key(raw_key: str, db: Session) -> ApiKey:
    match = _KEY_PATTERN.fullmatch(raw_key or "")
    if match is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    try:
        key_id = UUID(match.group(1))
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key") from exc
    key = db.get(ApiKey, key_id)
    if key is None or key.revoked_at is not None or (key.expires_at is not None and key.expires_at <= datetime.now(timezone.utc)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    try:
        expected = hash_api_key(raw_key, key.salt)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key") from None
    if not hmac.compare_digest(expected, key.key_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    key.last_used_at = datetime.now(timezone.utc)
    return key


def require_user(request: Request, db: Session) -> User:
    try:
        raw_id = request.session.get("user_id")
        user_id = UUID(str(raw_id)) if raw_id else None
    except (AssertionError, ValueError, TypeError):
        user_id = None
    user = db.get(User, user_id) if user_id else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Login required")
    return user


def require_org_member(
    org_id: UUID | str,
    user: User,
    db: Session,
    minimum_role: str = "member",
) -> OrgMember:
    if minimum_role not in _ROLE_RANK:
        raise ValueError("Unknown minimum role")
    try:
        normalized_id = UUID(str(org_id))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found") from exc
    membership = db.scalar(
        select(OrgMember).where(
            OrgMember.org_id == normalized_id,
            OrgMember.user_id == user.id,
        )
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if _ROLE_RANK.get(membership.role, -1) < _ROLE_RANK[minimum_role]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient organization role")
    return membership
