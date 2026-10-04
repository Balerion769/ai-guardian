"""Hosted persistence models. Source code and credentials never enter audit rows."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, DateTime, Float, ForeignKey, ForeignKeyConstraint,
    Index, Integer, String, Text, UniqueConstraint, Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Store timezone aware UTC instants, including with SQLite in tests."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone aware")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


def uuid_pk():
    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = uuid_pk()
    github_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    login: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    name: Mapped[str | None] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(String(2048))
    github_token_ciphertext: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    github_slug: Mapped[str | None] = mapped_column("github_org_name", String(255), unique=True)
    github_installation_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    github_app_installed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    owner_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False)
    plan: Mapped[str] = mapped_column(String(40), default="free", nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    billing_status: Mapped[str] = mapped_column(String(24), default="active", server_default="active", nullable=False)
    billing_event_created: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0", nullable=False)
    seat_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1", nullable=False)
    daily_limit: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)

    __table_args__ = (
        CheckConstraint("daily_limit > 0", name="ck_organizations_daily_limit"),
        CheckConstraint("plan IN ('free', 'pro', 'team')", name="ck_organizations_plan"),
        CheckConstraint("billing_status IN ('active', 'past_due')", name="ck_organizations_billing_status"),
        CheckConstraint("seat_count > 0", name="ck_organizations_seat_count"),
    )


class StripeEvent(Base):
    """Processed Stripe event IDs prevent duplicate subscription transitions."""

    __tablename__ = "stripe_events"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    org_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)


class OrgMember(Base):
    __tablename__ = "org_members"

    id: Mapped[UUID] = uuid_pk()
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "user_id", name="uq_org_members_org_user"),
        CheckConstraint("role IN ('owner', 'admin', 'member')", name="ck_org_members_role"),
        Index("ix_org_members_user_id", "user_id"),
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[UUID] = uuid_pk()
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    key_last4: Mapped[str] = mapped_column(String(4), nullable=False)
    salt: Mapped[str] = mapped_column(String(128), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    __table_args__ = (Index("ix_api_keys_org_id", "org_id"),)


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[UUID] = uuid_pk()
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    github_repo_full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), default="main", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_audit_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_repositories_org_id_id"),
        UniqueConstraint("org_id", "github_repo_full_name", name="uq_repositories_org_name"),
        Index("ix_repositories_org_id", "org_id"),
    )


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[UUID] = uuid_pk()
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    repo_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[str | None] = mapped_column(Text)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    diff_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    static_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ai_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    model_used: Mapped[str | None] = mapped_column(String(255))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(255))
    triggered_by: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "repo_id"], ["repositories.org_id", "repositories.id"], name="fk_audits_tenant_repository"),
        UniqueConstraint("org_id", "id", name="uq_audits_org_id_id"),
        CheckConstraint("status IN ('QUEUED', 'RUNNING', 'PASSED', 'FAILED', 'ERROR')", name="ck_audits_status"),
        CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="ck_audits_risk_score"),
        Index("ix_audits_org_id_created_at", "org_id", "created_at"),
        Index("ix_audits_repo_id", "repo_id"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = uuid_pk()
    org_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    category: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    line_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    tainted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_fixed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    fixed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    __table_args__ = (
        ForeignKeyConstraint(["org_id", "audit_id"], ["audits.org_id", "audits.id"], name="fk_findings_tenant_audit"),
        CheckConstraint("severity IN ('HIGH', 'MEDIUM', 'LOW')", name="ck_findings_severity"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_findings_confidence"),
        Index("ix_findings_org_id_created_at", "org_id", "created_at"),
        Index("ix_findings_audit_id", "audit_id"),
    )
