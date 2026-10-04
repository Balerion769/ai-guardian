"""Idempotent hosted schema and PostgreSQL tenant policy initializer."""

from __future__ import annotations

import os
import re

from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from .models import Base
from .session import get_engine


TENANT_TABLES = ("repositories", "audits", "findings")
_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")


def install_rls(connection) -> None:
    """Install policies that deny access unless a local organization is set."""
    predicate = "org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid"
    for table in TENANT_TABLES:
        connection.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        connection.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        connection.execute(text(f"DROP POLICY IF EXISTS {table}_tenant ON {table}"))
        connection.execute(text(
            f"CREATE POLICY {table}_tenant ON {table} FOR ALL "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        ))


def provision_app_role(connection, role: str | None = None) -> bool:
    """Create/grant a non-owner role when initializer credentials allow it."""
    role = role or os.getenv("APP_DATABASE_ROLE", "aiguardian_app")
    if not _IDENTIFIER.fullmatch(role):
        raise ValueError("APP_DATABASE_ROLE must be a simple SQL identifier")
    password = os.getenv("AIGUARDIAN_DB_APP_PASSWORD")
    try:
        with connection.begin_nested():
            connection.execute(text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '"
                + role + "') THEN CREATE ROLE " + role
                + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; "
                "END IF; END $$"
            ))
            if password:
                command = connection.execute(
                    text("SELECT format('ALTER ROLE %I PASSWORD %L', CAST(:role AS text), CAST(:password AS text))"),
                    {"role": role, "password": password},
                ).scalar_one()
                connection.exec_driver_sql(command)
            connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
            connection.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}"))
            connection.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"))
    except DBAPIError as error:
        if getattr(error.orig, "sqlstate", None) in {"42501", "42704"}:
            return False
        raise
    return True


def init_db(engine=None) -> None:
    """Create missing tables and install tenant protection on PostgreSQL."""
    engine = engine or get_engine()
    Base.metadata.create_all(engine)
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            existing = {column["name"] for column in inspect(connection).get_columns("organizations")}
            additions = {
                "github_installation_id": "BIGINT UNIQUE",
                "github_app_installed_at": "TIMESTAMPTZ",
                "stripe_subscription_id": "VARCHAR(255)",
                "billing_status": "VARCHAR(24) NOT NULL DEFAULT 'active'",
                "billing_event_created": "BIGINT NOT NULL DEFAULT 0",
                "seat_count": "INTEGER NOT NULL DEFAULT 1",
            }
            for name, definition in additions.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE organizations ADD COLUMN {name} {definition}"))
            connection.execute(text("ALTER TABLE organizations DROP CONSTRAINT IF EXISTS ck_organizations_plan"))
            connection.execute(text("UPDATE organizations SET plan = 'team', daily_limit = 2147483647 WHERE plan = 'enterprise'"))
            connection.execute(text("ALTER TABLE organizations ADD CONSTRAINT ck_organizations_plan CHECK (plan IN ('free', 'pro', 'team'))"))
            connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_organizations_stripe_subscription_id ON organizations (stripe_subscription_id)"))
            connection.execute(text("ALTER TABLE organizations DROP CONSTRAINT IF EXISTS ck_organizations_billing_status"))
            connection.execute(text("ALTER TABLE organizations ADD CONSTRAINT ck_organizations_billing_status CHECK (billing_status IN ('active', 'past_due'))"))
            connection.execute(text("ALTER TABLE organizations DROP CONSTRAINT IF EXISTS ck_organizations_seat_count"))
            connection.execute(text("ALTER TABLE organizations ADD CONSTRAINT ck_organizations_seat_count CHECK (seat_count > 0)"))
            install_rls(connection)
            provision_app_role(connection)


if __name__ == "__main__":
    init_db()
