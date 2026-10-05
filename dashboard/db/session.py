"""Database sessions and transaction-local tenant context."""

from __future__ import annotations

import os
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker


_engine = None
_factory = None


def get_engine():
    """Create the application engine on first use, after deployment env is loaded."""
    global _engine
    if _engine is None:
        url = os.getenv("DATABASE_URL")
        if not url:
            raise RuntimeError("DATABASE_URL is required")
        if url.startswith(("postgres://", "postgresql://")):
            url = "postgresql+psycopg://" + url.split("://", 1)[1]
        _engine = create_engine(url, pool_pre_ping=True, hide_parameters=True)
    return _engine


def _get_factory():
    global _factory
    if _factory is None:
        _factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _factory


class _SessionLocal:
    """Lazy sessionmaker surface so importing hosted modules needs no DB URL."""

    def __call__(self) -> Session:
        return _get_factory()()

    def begin(self):
        return _get_factory().begin()


SessionLocal = _SessionLocal()


def get_db():
    """FastAPI dependency providing a request-owned SQLAlchemy session."""
    with SessionLocal() as session:
        yield session


def tenant_scope(session: Session, org_id: UUID | str) -> None:
    """Set the RLS organization for this transaction only.

    Call after starting a transaction and before touching tenant tables.
    """
    if not session.in_transaction():
        raise RuntimeError("tenant_scope requires an active transaction")
    org_id = str(UUID(str(org_id)))
    # SQLite is used by isolated route tests; PostgreSQL enforces production RLS.
    if hasattr(session, "get_bind") and session.get_bind().dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT set_config('app.current_org_id', :org_id, true)"),
        {"org_id": org_id},
    )
